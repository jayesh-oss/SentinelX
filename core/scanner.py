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
            "yara_matches": [],
            "ml_score": ml_score,
            "threat_level": "Clean"
        }
        
        # High entropy generally means packed/encrypted
        if result["pe_analysis"].get("entropy", 0.0) > 7.2:
            result["threat_level"] = "Suspicious (High Entropy/Packed)"

        if len(result["pe_analysis"].get("suspicious_imports", [])) > 2:
            result["threat_level"] = "Suspicious (API Calls)"
            
        if ml_score >= 0.75:
            result["threat_level"] = f"Suspicious (ML Heuristic Score: {ml_score})"
            
        return result
