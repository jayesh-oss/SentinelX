# SentinelX - Architecture

This document covers the internal algorithms, scoring logic, and data flows that drive SentinelX's detection pipeline.

---

## Engine Registry

All engines are lazy-initialised singletons managed by `core/engine_registry.py`. The first caller initialises the instance; every subsequent caller gets the same object. A reentrant lock prevents race conditions during startup when multiple threads may reach an uninitialised engine simultaneously.

```
engine_registry
├── get_db()               → DatabaseManager (SQLite)
├── get_yara_engine()      → YaraEngine (1150+ compiled rules)
├── get_scanner()          → CoreScanner (unified scoring)
├── get_ml_engine()        → MLEngine (Random Forest / XGBoost)
├── get_visual_engine()    → VisualMLEngine (EfficientNet-B0)
├── get_vt_engine()        → VirusTotalEngine (API + cache)
├── get_quarantine_manager() → QuarantineManager
├── get_ransomware_engine()  → RansomwareEngine (static analysis)
└── get_ransomware_shield()  → RansomwareShield (real-time daemon)
```

The global `_ransomware_enabled` flag in the registry is the single source of truth for the dashboard toggle. The scan thread reads it before running ransomware analysis; the shield reads it to decide whether to start or stop its daemon threads.

---

## 1. Unified Threat Scoring - CoreScanner.evaluate_threat

Every file that enters the scanner - whether from a manual scan, the watchdog, or the process monitor - passes through the same scoring function.

```
Score = 0

Step 1 - Document bypass
  If extension in (.pdf, .docx, .txt, .xlsx, ...):
    Skip PE-dependent checks, return Clean immediately
    (prevents false positives on office documents)

Step 2 - YARA  (+100 on any match)
  Match file against 1,150+ compiled rules
  Any hit → score += 100, store matched rule name as threat_name

Step 3 - ML Heuristic  (variable weight)
  Extract 8 PE features:
    section_entropy, import_count, suspicious_api_count,
    section_count, resource_size, timestamp_anomaly,
    overlay_size, checksum_valid
  Feed to Random Forest / XGBoost model
  Model probability × configured weight → score delta

Step 4 - Visual CNN  (variable weight)
  Render raw bytes as 256×256 grayscale image
  EfficientNet-B0 forward pass → malware probability
  Probability × configured weight → score delta

Step 5 - VirusTotal  (conditional)
  Look up MD5 hash (SQLite cache first, then API)
  detections < 3  → no change (may suppress marginal result)
  detections >= 3 → score += 50

Step 6 - Verdict
  score >= 100  → "Malicious - [rule_name]"
  score >= 50   → "Suspicious"
  score < 50    → "Clean"
```

---

## 2. Ransomware Engine - RansomwareEngine.analyze

Runs after the main scoring pipeline as a separate, additive analysis pass. It does not modify the primary verdict - it produces its own verdict and score that are rendered in a distinct section of the scan output.

```
rw_score = 0

Layer 1 - Extension check
  If file extension in RANSOMWARE_EXTENSIONS (40+ known extensions):
    rw_score += 80
    (examples: .locked, .ryuk, .wncry, .conti, .hive, .lockbit,
               .cerber, .locky, .zepto, .crypt, .enc, .encrypt)

Layer 2 - Entropy analysis  (document types only)
  Read first 8 KB of file
  Calculate Shannon entropy: H = -Σ p(b) × log₂(p(b))
  entropy > 7.2 → rw_score += 40  (high - likely encrypted)
  entropy > 6.5 → rw_score += 15  (elevated - possibly compressed)

Layer 3 - Ransom string scan
  Read first 512 KB
  Search for 18 byte patterns:
    b'your files have been encrypted'
    b'vssadmin delete shadows'
    b'bitcoin'
    b'tor browser'
    b'.onion'
    b'decrypt'
    b'ransom'
    ... (11 more)
  Each unique match → rw_score += up to 60 total

Layer 4 - PE data reuse  (no re-parsing)
  Uses pe_analysis dict already computed by PE Analyser
  Crypto API imports found (CryptEncrypt, BCryptEncrypt, etc.) → rw_score += 30
  Anti-recovery imports found (DeleteShadowCopy, etc.)         → rw_score += 25
  Embedded ransom strings in PE string table                   → rw_score += 20

Verdict
  rw_score >= 80  → "Ransomware"
  rw_score >= 40  → "Suspicious (Possible Ransomware)"
  rw_score < 40   → "Clean"
```

---

## 3. Anti-Ransomware Shield - Three Tripwires

The shield runs in daemon threads started at application launch. It is entirely independent of the scan pipeline - it watches the live file system, not queued files.

### Tripwire A: Canary Files

```
On startup:
  For each protected directory (Desktop, Documents, Downloads, Pictures, Videos):
    Write  !SentinelX_Canary_do_not_delete.txt
    Record SHA-256 hash → _canary_hashes dict

Watchdog on_modified event:
  If modified path in _canary_hashes:
    → Immediate trigger (highest confidence - no threshold needed)
```

Canary files are named with `!` prefix so they sort alphabetically first. Ransomware typically encrypts files in directory order, guaranteeing it hits the canary before reaching real documents.

### Tripwire B: Mass Modification Counter

```
Watchdog on_modified event:
  If extension in PROTECTED_EXTENSIONS:
    Append timestamp to sliding deque
    Evict timestamps older than 60 seconds
    If len(deque) >= 20:
      Clear deque  (prevent re-firing on every subsequent event)
      → Trigger
```

### Tripwire C: VSS Deletion Watcher

```
Separate daemon thread:
  WMI Win32_Process.watch_for('creation')
  On each new process:
    Check CommandLine (lowercased) for:
      'vssadmin delete shadows'
      'shadowcopy delete'
      'bcdedit /set'
      'wbadmin delete catalog'
      'resize shadowstorage'
      'delete shadows /all'
    Any match → Trigger
```

### Trigger Response

When any tripwire fires:

```
1. Take two psutil I/O snapshots 150ms apart across all non-system processes
2. Find process with highest write_bytes delta
3. psutil.Process(pid).terminate() → wait up to 3s
4. Append alert string to _pending_alerts deque (maxlen=50, thread-safe)
5. Dashboard QTimer (2s interval) drains the deque and shows the alert banner
```

---

## 4. Real-Time Protection Flow

```
┌─────────────────────────────────────────────────────────┐
│                    Protection Layer                      │
│                                                         │
│   BehaviorMonitor          ProcessMonitor               │
│   (watchdog observer)      (WMI Win32_Process hook)     │
│         │                         │                     │
│   File created/modified    New process launched         │
│         │                         │                     │
│   Debounce 3s              Skip: system paths,          │
│   Wait for write lock      C:\Windows\, C:\Prog Files   │
│         │                         │                     │
│         └───────────┬─────────────┘                     │
│                     ▼                                    │
│            CoreScanner.evaluate_threat                   │
│                     │                                    │
│              Clean? │ Malicious?                         │
│                     │                                    │
│            Continue │ ┌──────────────────────┐          │
│            watching │ │  Kill process (WMI)  │          │
│                     │ │  QuarantineManager   │          │
│                     │ │  Update SQLite       │          │
│                     │ │  Refresh dashboard   │          │
│                     │ └──────────────────────┘          │
└─────────────────────────────────────────────────────────┘
```

---

## 5. Quarantine Algorithm

```
1. Compute MD5 of original file
2. Build isolated filename: {MD5}_{original_name}.isolated
3. shutil.move(original_path, quarantine/{isolated_name})
4. INSERT INTO quarantine_records:
     original_path, quarantine_path, md5_hash,
     threat_name, timestamp
5. UI Quarantine tab reads this table to show all entries
6. Restore: shutil.move back to original_path + DELETE record
7. Delete: os.remove(quarantine_path) + DELETE record
```

Files are never destroyed unless the user explicitly clicks Delete. The `.isolated` extension prevents accidental execution.

---

## 6. Scan Thread Data Flow

```
ScanThread (QThread)
  For each file:
    1. scanner.scan_file(path)          → hashes, file_type, pe_features
    2. yara_engine.scan_file(path)      → list[yara.Match]
    3. scanner.evaluate_threat(...)     → verdict, score, threat_level
    4. if ransomware_enabled:
         ransomware_engine.analyze(path, pe_analysis) → rw_result
    5. emit result signal → main thread
    6. display_results() renders HTML:
         - Primary verdict block (YARA / ML / VT outputs)
         - Anti-Ransomware Detection Report block (separate, purple border)
    7. if threat_level != Clean:
         quarantine_manager.quarantine_file(...)
         db.log_scan(...)
```

The signal/slot boundary between `ScanThread` and the main thread is the only point where background work touches the UI. All engine calls happen in the worker thread; all HTML rendering and widget updates happen in the main thread after the signal is received.
