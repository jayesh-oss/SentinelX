import os
import pefile
import math
import collections
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

        os.makedirs(os.path.dirname(self.model_path) or '.', exist_ok=True)
        self._load_or_train_model()

    EXPECTED_FEATURES = 8

    def _load_or_train_model(self):
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                if hasattr(self.model, 'n_features_in_') and self.model.n_features_in_ != self.EXPECTED_FEATURES:
                    logging.info("ML model feature count mismatch, retraining...")
                    self._train_synthetic_model()
                else:
                    logging.info(f"ML Heuristic Model loaded from {self.model_path}")
            except Exception as e:
                logging.error(f"Failed to load ML model: {e}")
                self._train_synthetic_model()
        else:
            self._train_synthetic_model()

    def _train_synthetic_model(self):
        logging.info("Training synthetic base heuristic model (8 features)...")

        # [Entropy, Num_Sections, Suspicious_Imports_Count, OptionalHeader_Size,
        #  SizeOfCode, Max_Section_Entropy, Anomaly_Count, Threat_Category_Count]
        X_malicious = [
            [7.8, 3, 5, 224, 15000, 7.9, 3, 4],
            [7.9, 2, 4, 224, 1000,  7.95, 2, 3],
            [7.2, 4, 8, 224, 50000, 7.5, 4, 5],
            [7.5, 8, 6, 224, 10000, 7.8, 3, 4],
            [8.0, 1, 3, 224, 500,   7.99, 5, 2],
        ]
        y_malicious = [1, 1, 1, 1, 1]

        X_benign = [
            [5.5, 5, 0, 224, 150000, 6.0, 0, 0],
            [6.2, 4, 1, 224, 80000,  6.5, 0, 1],
            [4.5, 6, 0, 224, 500000, 5.0, 0, 0],
            [5.8, 4, 0, 224, 120000, 6.1, 0, 0],
            [6.0, 5, 1, 224, 300000, 6.3, 1, 1],
        ]
        y_benign = [0, 0, 0, 0, 0]

        X = np.array(X_malicious + X_benign)
        y = np.array(y_malicious + y_benign)

        self.model = RandomForestClassifier(n_estimators=50, max_depth=5, random_state=42)
        self.model.fit(X, y)

        joblib.dump(self.model, self.model_path)
        logging.info(f"Synthetic ML Model saved to {self.model_path}")

    @staticmethod
    def _count_suspicious_apis(pe, suspicious_apis):
        count = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        name_str = imp.name.decode('utf-8', 'ignore')
                        if any(api in name_str for api in suspicious_apis):
                            count += 1
        return count

    def extract_features_from_parsed(self, pe, entropy, pe_analysis=None):
        features = [0.0] * self.EXPECTED_FEATURES
        try:
            features[0] = entropy
            features[1] = float(len(pe.sections))
            features[2] = float(self._count_suspicious_apis(pe, self.suspicious_apis))

            if hasattr(pe, 'OPTIONAL_HEADER'):
                features[3] = float(pe.OPTIONAL_HEADER.sizeof())
                features[4] = float(pe.OPTIONAL_HEADER.SizeOfCode)

            if pe_analysis:
                sections = pe_analysis.get("section_analysis", [])
                features[5] = max((s.get("entropy", 0) for s in sections), default=0.0)
                features[6] = float(len(pe_analysis.get("anomalies", [])))
                features[7] = float(len(pe_analysis.get("threat_categories", {})))
            else:
                features[5] = entropy
                features[6] = 0.0
                features[7] = 0.0

            return features
        except Exception as e:
            logging.error(f"ML Feature Extraction failed: {e}")
            return None

    def extract_features(self, file_path):
        """Legacy method — reads file and extracts features."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            if not data:
                return [0.0] * self.EXPECTED_FEATURES

            length = len(data)
            counts = collections.Counter(data)
            entropy = 0.0
            for count in counts.values():
                p_x = count / length
                entropy -= p_x * math.log2(p_x)

            if data[:2] != b'MZ':
                return [entropy] + [0.0] * (self.EXPECTED_FEATURES - 1)

            pe = pefile.PE(data=data)
            features = self.extract_features_from_parsed(pe, entropy)
            pe.close()
            return features
        except Exception as e:
            logging.error(f"ML Feature Extraction failed on {file_path}: {e}")
            return None

    def predict_from_data(self, file_data, pe, entropy, pe_analysis=None):
        if not self.model or not pe:
            return 0.0

        features = self.extract_features_from_parsed(pe, entropy, pe_analysis)
        if not features:
            return 0.0

        try:
            X_test = np.array([features])
            proba = self.model.predict_proba(X_test)[0][1]
            return round(proba, 2)
        except Exception as e:
            logging.error(f"ML Prediction failed: {e}")
            return 0.0

    def predict(self, file_path):
        """Legacy method — reads file and predicts."""
        if not self.model:
            return 0.0

        features = self.extract_features(file_path)
        if not features:
            return 0.0

        try:
            X_test = np.array([features])
            proba = self.model.predict_proba(X_test)[0][1]
            return round(proba, 2)
        except Exception as e:
            logging.error(f"ML Prediction failed: {e}")
            return 0.0
