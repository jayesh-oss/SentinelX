import os
import hashlib
import pefile
import math
import collections
from core import engine_registry
from core import pe_analyzer


class CoreScanner:
    def __init__(self):
        self.ml_engine = engine_registry.get_ml_engine()
        self.visual_engine = engine_registry.get_visual_engine()
        self.db = engine_registry.get_db()

    def calculate_hashes_from_bytes(self, data):
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        return {"md5": md5, "sha1": sha1, "sha256": sha256}

    def calculate_hashes(self, file_path):
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            return self.calculate_hashes_from_bytes(data)
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def calculate_entropy(data):
        if not data:
            return 0.0
        length = len(data)
        counts = collections.Counter(data)
        entropy = 0.0
        for count in counts.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
        return round(entropy, 4)

    @staticmethod
    def try_parse_pe(data):
        if len(data) < 2 or data[:2] != b'MZ':
            return None
        try:
            return pefile.PE(data=data)
        except pefile.PEFormatError:
            return None
        except Exception:
            return None

    def analyze_pe(self, file_path):
        """Legacy method — reads file and delegates to analyze_pe_from_parsed."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            pe = self.try_parse_pe(data)
            if not pe:
                return {"is_pe": False, "entropy": 0.0, "suspicious_imports": [],
                        "number_of_sections": 0, "error": None}
            entropy = self.calculate_entropy(data)
            result = self.analyze_pe_from_parsed(pe, entropy, data)
            pe.close()
            return result
        except Exception as e:
            return {"is_pe": False, "entropy": 0.0, "suspicious_imports": [],
                    "number_of_sections": 0, "error": str(e)}

    def analyze_pe_from_parsed(self, pe, entropy, file_data=None):
        return pe_analyzer.analyze(pe, file_data, entropy)

    def scan_file(self, file_path):
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
        except Exception as e:
            return {
                "file": file_path, "hashes": {"error": str(e)},
                "pe_analysis": {}, "ml_score": 0.0,
                "visual_cnn": {"available": False}, "threat_level": "Clean"
            }

        hashes = self.calculate_hashes_from_bytes(file_data)
        file_hash = hashes.get('md5')

        if file_hash:
            rep = self.db.get_hash_reputation(file_hash)
            if rep is False:
                return {
                    "file": file_path, "hashes": hashes,
                    "pe_analysis": {}, "yara_matches": [],
                    "ml_score": 0.0, "visual_cnn": {"available": False},
                    "threat_level": "Clean"
                }

        entropy = self.calculate_entropy(file_data)
        pe = self.try_parse_pe(file_data)

        if pe:
            pe_analysis = self.analyze_pe_from_parsed(pe, entropy, file_data)
            ml_score = self.ml_engine.predict_from_data(file_data, pe, entropy, pe_analysis)
            pe.close()
        else:
            pe_analysis = {"is_pe": False, "entropy": entropy,
                           "suspicious_imports": [], "number_of_sections": 0, "error": None}
            ml_score = 0.0

        visual_result = self.visual_engine.predict(file_data)

        return {
            "file": file_path, "hashes": hashes,
            "pe_analysis": pe_analysis, "ml_score": ml_score,
            "visual_cnn": visual_result,
            "threat_level": "Clean"
        }

    # --- YARA rule classification ---
    # Informational: file metadata, compiler IDs, generic indicators — zero score
    INFORMATIONAL_RULES = {
        "domain", "IP", "url", "contains_base64", "Big_Numbers1", "Big_Numbers2",
        "Big_Numbers3", "multiple_versions", "Misc_Suspicious_Strings",
        "IsPE32", "IsPE64", "IsConsole", "IsNET_EXE", "NETexecutableMicrosoft",
        "Prime_Constants_long", "invalid_trailer_structure",
        "HasOverlay", "HasDebugData", "HasRichSignature",
    }

    # Behavioral: technique/capability detection — matches common APIs that appear
    # in benign software too. Only scores when other engines already flag the file.
    BEHAVIORAL_PREFIXES = (
        "Debugger", "ThreadControl__", "SEH__", "SEH_",
        "Check_Dlls", "Check_Qemu", "Check_VBox", "Check_VMWare",
        "Check_VmTools", "Check_Wine", "Check_Debugger", "Check_DriveSize",
        "Check_FilePaths", "Check_UserNames", "Check_OutputDebugStringA",
        "Check_unhandledExceptionFiler", "check_RaiseException",
        "Check_FindWindowA",
        "anti_dbg", "antisb_", "antivm_",
        "disable_",
        "WMI_VM_",
        "inject_thread", "create_process", "create_service", "create_com_service",
        "hijack_network",
        "network_udp", "network_tcp", "network_dyndns", "network_toredo",
        "network_smtp", "network_p2p", "network_tor", "network_irc",
        "network_http", "network_dropper", "network_ftp", "network_dns",
        "network_ssl", "network_dga",
        "escalate_priv", "screenshot", "lookupip", "lookupgeo",
        "keylogger", "migrate_apc",
        "spreading_file", "spreading_share",
        "rat_vnc", "rat_rdp", "rat_telnet", "rat_webcam",
        "Str_Win32_",
        "Microsoft_Visual_Cpp", "_PseudoSigner_",
    )
    BEHAVIORAL_EXACT = {
        "vmdetect", "VMWare_Detection",
        "persistence", "bitcoin", "certificate", "dyndns",
        "cred_local", "cred_ff", "cred_vnc", "cred_ie7",
        "sniff_audio", "sniff_lan",
        "win_mutex", "win_registry", "win_token",
        "win_private_profile", "win_files_operation",
        "ldpreload", "mysql_database_presence",
    }

    @staticmethod
    def _classify_yara(rule_name):
        if rule_name in CoreScanner.INFORMATIONAL_RULES:
            return "informational"
        if rule_name in CoreScanner.BEHAVIORAL_EXACT:
            return "behavioral"
        if rule_name.startswith(CoreScanner.BEHAVIORAL_PREFIXES):
            return "behavioral"
        return "signature"

    def evaluate_threat(self, scan_result, yara_matches, vt_data=None):
        threat_score = 0
        reasons = []

        yara_matches = list(dict.fromkeys(yara_matches))

        # ── 1. Classify YARA rules into 3 tiers ──
        signature_hits = []
        behavioral_hits = []
        for rule in yara_matches:
            tier = self._classify_yara(rule)
            if tier == "signature":
                signature_hits.append(rule)
            elif tier == "behavioral":
                behavioral_hits.append(rule)

        # ── 2. Machine Learning Scoring ──
        ml_score = scan_result.get("ml_score", 0.0)
        if ml_score >= 0.85:
            threat_score += int(ml_score * 120)
            reasons.append(f"ML Heuristic ({ml_score})")
        elif ml_score >= 0.70:
            threat_score += int(ml_score * 100)
            reasons.append(f"ML Heuristic ({ml_score})")
        elif ml_score >= 0.50:
            threat_score += 30

        # ── 3. Static PE Analysis ──
        pe_data = scan_result.get("pe_analysis", {})
        if pe_data.get("entropy", 0.0) > 7.3:
            threat_score += 40
            reasons.append("High Entropy")
        elif pe_data.get("entropy", 0.0) > 6.5:
            threat_score += 20

        threat_cats = pe_data.get("threat_categories", {})

        injection_apis = threat_cats.get("Process Injection", [])
        if len(injection_apis) >= 2:
            threat_score += 50
            reasons.append("Process Injection APIs")

        crypto_apis = threat_cats.get("Crypto (Ransomware)", [])
        if len(crypto_apis) >= 2:
            threat_score += 40
            reasons.append("Crypto APIs (Ransomware)")

        cred_apis = threat_cats.get("Credential Access", [])
        if len(cred_apis) >= 2:
            threat_score += 40
            reasons.append("Credential Theft APIs")

        evasion_apis = threat_cats.get("Evasion / Anti-Debug", [])
        if len(evasion_apis) >= 2:
            threat_score += 30
            reasons.append("Anti-Debug / Evasion APIs")

        for section in pe_data.get("section_analysis", []):
            if section.get("entropy", 0) > 7.2:
                threat_score += 30
                reasons.append(f"Packed Section: {section['name']}")
                break

        anomalies = pe_data.get("anomalies", [])
        threat_score += min(len(anomalies) * 15, 45)
        if anomalies:
            reasons.append(f"PE Anomalies ({len(anomalies)})")

        # ── 4. Visual CNN Scoring ──
        visual = scan_result.get("visual_cnn", {})
        if visual.get("available"):
            v_score = visual.get("score", 0.0)
            v_family = visual.get("family", "Unknown")
            v_conf = visual.get("confidence", 0.0)
            if v_score >= 0.85 and v_conf >= 0.60:
                threat_score += 100
                reasons.append(f"Visual CNN: {v_family} ({v_conf:.0%})")
            elif v_score >= 0.70 and v_conf >= 0.50:
                threat_score += 60
                reasons.append(f"Visual CNN: {v_family} ({v_conf:.0%})")
            elif v_score >= 0.50 and v_conf >= 0.50:
                threat_score += 30

        # ── 5. VirusTotal Scoring ──
        if vt_data:
            malicious_count = vt_data.get("malicious", 0)
            if malicious_count >= 3:
                threat_score += 100
                reasons.append(f"Cloud-VT ({malicious_count}/{vt_data.get('total')})")
            elif malicious_count > 0:
                threat_score += (malicious_count * 25)

        # engine_score = everything scored so far (ML + PE + CNN + VT, no YARA yet)
        engine_score = threat_score

        # ── 6. Signature YARA Scoring (high confidence — specific malware families) ──
        sig_pending = None
        if len(signature_hits) >= 2:
            threat_score += len(signature_hits) * 100
            reasons.extend(signature_hits[:3])
        elif len(signature_hits) == 1:
            sig_pending = signature_hits[0]

        # Single signature hit needs corroboration from any other engine
        if sig_pending and engine_score > 0:
            threat_score += 60
            reasons.insert(0, sig_pending)

        # ── 7. Behavioral YARA Scoring (technique detection — needs strong corroboration) ──
        # Rules like "DebuggerCheck__QueryInfo" match on single API strings that appear
        # in every system binary. They only contribute when other engines are already
        # independently suspicious (engine_score >= 50).
        if behavioral_hits and engine_score >= 50:
            beh_score = min(len(behavioral_hits) * 15, 30)
            threat_score += beh_score
            reasons.append(f"Behavioral ({len(behavioral_hits)} technique rules)")

        # ── Final verdict ──
        file_path = scan_result.get("file", "").lower()
        executable_exts = ('.exe', '.dll', '.bat', '.ps1', '.vbs', '.cmd')
        if not file_path.endswith(executable_exts):
            scan_result["threat_level"] = "Clean"
            return scan_result

        if threat_score >= 100:
            if not reasons:
                reasons = list(set(yara_matches))[:3]
            scan_result["threat_level"] = f"Malicious ({', '.join(reasons)})"
        elif threat_score >= 50:
            scan_result["threat_level"] = f"Suspicious (Score: {int(threat_score)})"
        else:
            scan_result["threat_level"] = "Clean"

        return scan_result
