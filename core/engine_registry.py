import threading

_lock = threading.RLock()
_instances = {}
_ransomware_enabled = True   # global toggle — set by dashboard, read by ScanThread


def is_ransomware_enabled() -> bool:
    return _ransomware_enabled


def set_ransomware_enabled(value: bool):
    global _ransomware_enabled
    _ransomware_enabled = value


def get_db(db_path="database/sentinelx.db"):
    if "db" not in _instances:
        with _lock:
            if "db" not in _instances:
                from database.db_manager import DatabaseManager
                _instances["db"] = DatabaseManager(db_path=db_path)
    return _instances["db"]


def get_yara_engine(rules_dir="rules"):
    if "yara" not in _instances:
        with _lock:
            if "yara" not in _instances:
                from core.yara_engine import YaraEngine
                _instances["yara"] = YaraEngine(rules_dir=rules_dir)
    return _instances["yara"]


def get_scanner():
    if "scanner" not in _instances:
        with _lock:
            if "scanner" not in _instances:
                from core.scanner import CoreScanner
                _instances["scanner"] = CoreScanner()
    return _instances["scanner"]


def get_vt_engine():
    if "vt" not in _instances:
        with _lock:
            if "vt" not in _instances:
                from core.vt_engine import VirusTotalEngine
                _instances["vt"] = VirusTotalEngine()
    return _instances["vt"]


def get_quarantine_manager():
    if "quarantine" not in _instances:
        with _lock:
            if "quarantine" not in _instances:
                from core.quarantine import QuarantineManager
                _instances["quarantine"] = QuarantineManager()
    return _instances["quarantine"]


def get_ml_engine():
    if "ml" not in _instances:
        with _lock:
            if "ml" not in _instances:
                from core.ml_engine import MLEngine
                _instances["ml"] = MLEngine()
    return _instances["ml"]


def get_visual_engine():
    if "visual" not in _instances:
        with _lock:
            if "visual" not in _instances:
                from core.visual_engine import VisualMLEngine
                _instances["visual"] = VisualMLEngine()
    return _instances["visual"]


def get_ransomware_engine():
    if "ransomware_engine" not in _instances:
        with _lock:
            if "ransomware_engine" not in _instances:
                from core.ransomware_engine import RansomwareEngine
                _instances["ransomware_engine"] = RansomwareEngine()
    return _instances["ransomware_engine"]


def get_ransomware_shield():
    if "ransomware_shield" not in _instances:
        with _lock:
            if "ransomware_shield" not in _instances:
                from core.ransomware_shield import RansomwareShield
                _instances["ransomware_shield"] = RansomwareShield()
    return _instances["ransomware_shield"]
