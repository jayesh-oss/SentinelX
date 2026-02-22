import os
import pefile
import math
import numpy as np
import logging
from sklearn.ensemble import RandomForestClassifier
import joblib

class MLEngine:
    def __init__(self, model_path="models/pe_heuristic_model.pkl"):
        self.model_path = model_path
        self.model = None
        self.suspicious_apis = [
            "VirtualAlloc", "VirtualProtect", "LoadLibraryA", "GetProcAddress",
            "CreateRemoteThread", "WriteProcessMemory", "SetWindowsHookEx",
            "CreateProcessA", "WinExec", "ShellExecute", "InternetOpenA"
        ]
        
        # Ensure models directory exists
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        self._load_or_train_model()

    def _load_or_train_model(self):
        """Loads the pre-trained model or trains a synthetic one if it doesn't exist."""
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                logging.info(f"ML Heuristic Model loaded from {self.model_path}")
            except Exception as e:
                logging.error(f"Failed to load ML model: {e}")
                self._train_synthetic_model()
        else:
            self._train_synthetic_model()

    def _train_synthetic_model(self):
        """Trains a basic RandomForest model using synthetic Data to serve as a demonstrative heuristic baseline."""
        logging.info("No ML Model found. Training synthetic base heuristic model...")
        
        # Synthetic Data: [Entropy, Num_Sections, Suspicious_Imports_Count, OptionalHeader_Size, SizeOfCode]
        
        # Malicious-like profiles (High entropy, weird sections, API injection)
        X_malicious = [
            [7.8, 3, 5, 224, 15000],
            [7.9, 2, 4, 224, 1000],
            [7.2, 4, 8, 224, 50000],
            [7.5, 8, 6, 224, 10000],
            [8.0, 1, 3, 224, 500]
        ]
        y_malicious = [1, 1, 1, 1, 1] # 1 = Malicious
        
        # Benign-like profiles (Normal entropy, standard sections, clean imports)
        X_benign = [
            [5.5, 5, 0, 224, 150000],
            [6.2, 4, 1, 224, 80000],
            [4.5, 6, 0, 224, 500000],
            [5.8, 4, 0, 224, 120000],
            [6.0, 5, 1, 224, 300000]
        ]
        y_benign = [0, 0, 0, 0, 0] # 0 = Clean
        
        X = np.array(X_malicious + X_benign)
        y = np.array(y_malicious + y_benign)
        
        # Train
        self.model = RandomForestClassifier(n_estimators=50, max_depth=5, random_state=42)
        self.model.fit(X, y)
        
        # Save
        joblib.dump(self.model, self.model_path)
        logging.info(f"Synthetic ML Model saved to {self.model_path}")

    def extract_features(self, file_path):
        """Extracts numerical features from a PE file to feed into the model."""
        features = [0.0, 0.0, 0.0, 0.0, 0.0] 
        # [Entropy, Num_Sections, Suspicious_Imports_Count, OptionalHeader_Size, SizeOfCode]
        
        try:
            # First calculate entropy without pefile
            with open(file_path, "rb") as f:
                data = f.read()
                if not data:
                    return features
                    
                entropy = 0.0
                for x in range(256):
                    p_x = float(data.count(bytes([x]))) / len(data)
                    if p_x > 0:
                        entropy += - p_x * math.log(p_x, 2)
                features[0] = entropy
                
            # Parse with pefile to extract structural features
            pe = pefile.PE(data=data)
            features[1] = len(pe.sections)
            
            suspicious_count = 0
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            name_str = imp.name.decode('utf-8', 'ignore')
                            if any(api in name_str for api in self.suspicious_apis):
                                suspicious_count += 1
            features[2] = float(suspicious_count)
            
            if hasattr(pe, 'OPTIONAL_HEADER'):
                features[3] = float(pe.OPTIONAL_HEADER.sizeof())
                features[4] = float(pe.OPTIONAL_HEADER.SizeOfCode)
                
            pe.close()
            return features
            
        except Exception as e:
            logging.error(f"ML Feature Extraction failed on {file_path}: {e}")
            return None

    def predict(self, file_path):
        """Extracts features and returns a heuristic threat score (0.0 to 1.0)."""
        if not self.model:
            return 0.0
            
        features = self.extract_features(file_path)
        if not features:
            return 0.0
            
        # Predict probability of class 1 (Malicious)
        try:
            X_test = np.array([features])
            proba = self.model.predict_proba(X_test)[0][1] # Probability of being malicious
            return round(proba, 2)
        except Exception as e:
            logging.error(f"ML Prediction failed: {e}")
            return 0.0
