import os
import hashlib
import pefile
import math
from core.ml_engine import MLEngine
from database.db_manager import DatabaseManager

class CoreScanner:
    def __init__(self):
        self.ml_engine = MLEngine()
        self.db = DatabaseManager()
    
    def calculate_hashes(self, file_path):
        """Calculates MD5, SHA1, and SHA256 hashes for a file."""
        hashes = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256()
        }
        
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(8192):
                    for h in hashes.values():
                        h.update(chunk)
            
            return {name: h.hexdigest() for name, h in hashes.items()}
        except Exception as e:
            return {"error": str(e)}

    def analyze_pe(self, file_path):
        """Analyzes a PE file for imports, entropy, and basic static anomalies."""
        results = {
            "is_pe": False,
            "entropy": 0.0,
            "suspicious_imports": [],
            "number_of_sections": 0,
            "error": None
        }

        try:
            # Check if it's a PE before proceeding
            with open(file_path, "rb") as f:
                header = f.read(2)
                if header != b'MZ':
                    return results
                
                # Read entire file into memory to avoid pefile mmap holding a Windows file lock
                f.seek(0)
                pe_data = f.read()
            
            # Since it's MZ, load with pefile from memory
            results["is_pe"] = True
            pe = pefile.PE(data=pe_data)
            
            results["number_of_sections"] = len(pe.sections)
            results["entropy"] = self._calculate_entropy(file_path)

            suspicious_apis = ["VirtualAlloc", "LoadLibraryA", "CreateRemoteThread", "WriteProcessMemory"]
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            name_str = imp.name.decode('utf-8', 'ignore')
                            if any(api in name_str for api in suspicious_apis):
                                results["suspicious_imports"].append(name_str)
                                
            pe.close()

        except pefile.PEFormatError:
             results["error"] = "Invalid PE format"
        except Exception as e:
             results["error"] = str(e)
             
        return results
        
    def _calculate_entropy(self, file_path):
        """Calculates the Shannon Entropy of a file."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()
                
            if not data:
                return 0.0
                
            entropy = 0
            for x in range(256):
                p_x = float(data.count(bytes([x]))) / len(data)
                if p_x > 0:
                    entropy += - p_x * math.log(p_x, 2)
            
            return entropy
        except Exception:
            return 0.0

    def scan_file(self, file_path):
        """Main routine to scan a file comprehensively."""
        hashes = self.calculate_hashes(file_path)
        file_hash = hashes.get('md5')
        
        if file_hash:
            rep = self.db.get_hash_reputation(file_hash)
            if rep is False: # Explicitly marked as safe/whitelisted
                return {
                    "file": file_path,
                    "hashes": hashes,
                    "pe_analysis": {},
                    "yara_matches": [],
                    "ml_score": 0.0,
                    "threat_level": "Clean"
                }

        ml_score = self.ml_engine.predict(file_path)
        
        result = {
            "file": file_path,
            "hashes": hashes,
            "pe_analysis": self.analyze_pe(file_path),
            "ml_score": ml_score,
            "threat_level": "Clean"
        }
        
        return result

    def evaluate_threat(self, scan_result, yara_matches, vt_data=None):
        """
        Unifies all engine data (Static, ML, YARA, VT) to calculate a final threshold score.
        Threshold >= 100 -> Malicious
        Threshold >= 50  -> Suspicious
        """
        threat_score = 0
        reasons = []

        # 1. YARA Rule Scoring
        informational_rules = {
            "domain", "IP", "url", "contains_base64", "Big_Numbers1", "Big_Numbers2", 
            "Big_Numbers3", "multiple_versions", "Misc_Suspicious_Strings", 
            "IsPE32", "IsConsole", "IsNET_EXE", "NETexecutableMicrosoft", 
            "Prime_Constants_long", "network_dns", "cred_local", "win_token",
            "vmdetect", "VMWare_Detection", "invalid_trailer_structure"
        }
        
        for rule in yara_matches:
            if rule in informational_rules:
                threat_score += 10 # Low weight for generic traits
            else:
                threat_score += 100 # High confidence malware signature
                if rule not in reasons:
                    reasons.append(rule)

        # 2. Machine Learning Scoring
        ml_score = scan_result.get("ml_score", 0.0)
        if ml_score >= 0.75:
            threat_score += (ml_score * 100)
            reasons.append(f"ML Heuristic ({ml_score})")
        elif ml_score >= 0.50:
            threat_score += 30

        # 3. Static PE Analysis
        pe_data = scan_result.get("pe_analysis", {})
        if pe_data.get("entropy", 0.0) > 7.3:
            threat_score += 40
            reasons.append("High Entropy")
            
        if len(pe_data.get("suspicious_imports", [])) > 2:
            threat_score += 30

        # 4. VirusTotal Scoring
        if vt_data:
            malicious_count = vt_data.get("malicious", 0)
            if malicious_count >= 3:
                threat_score += 100
                reasons.append(f"Cloud-VT ({malicious_count}/{vt_data.get('total')})")
            elif malicious_count > 0:
                threat_score += (malicious_count * 25)

        # Override: If the file is strictly meant to be a non-executable (like .pdf), always mark as Clean
        file_path = scan_result.get("file", "").lower()
        executable_exts = ('.exe', '.dll', '.bat', '.ps1', '.vbs', '.cmd')
        if not file_path.endswith(executable_exts):
            scan_result["threat_level"] = "Clean"
            return scan_result

        # Final Verdict for Executables
        if threat_score >= 100:
            if not reasons:
                # If it reached 100 just by stacking 10+ identical info hits
                reasons = list(set(yara_matches))[:3]
            scan_result["threat_level"] = f"Malicious ({', '.join(reasons)})"
        elif threat_score >= 50:
            scan_result["threat_level"] = f"Suspicious (Score: {int(threat_score)})"
        else:
            scan_result["threat_level"] = "Clean"
            
        return scan_result
