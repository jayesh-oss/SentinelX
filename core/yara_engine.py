import os
import hashlib
import yara
import logging

class YaraEngine:
    def __init__(self, rules_dir="rules"):
        self.rules_dir = rules_dir
        self.compiled_rules = None
        self._load_rules()

    def _load_rules(self):
        """Loads and compiles all active .yar files from the rules_dir."""
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir)
            logging.warning(f"Rules directory {self.rules_dir} created. No rules loaded.")
            return

        rule_files = {}
        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith('.yar') or file.endswith('.yara'):
                    # Using file basename as key
                    rule_files[file] = os.path.join(root, file)

        if not rule_files:
            logging.warning("No YARA rules found in directory.")
            return

        try:
            logging.info(f"Attempting to compile {len(rule_files)} YARA rules...")
            self.compiled_rules = yara.compile(filepaths=rule_files)
            logging.info(f"Successfully compiled {len(rule_files)} YARA rule files.")
        except yara.SyntaxError as e:
            logging.error(f"YARA Syntax Error: {e}")
        except Exception as e:
            logging.error(f"Error compiling YARA rules: {e}")

    def scan_file(self, file_path):
        """Scans a file against compiled YARA rules."""
        if not self.compiled_rules:
            # Try reloading if missing
            self._load_rules()
            if not self.compiled_rules:
                return []

        try:
            matches = self.compiled_rules.match(file_path)
            return [match.rule for match in matches]
        except Exception as e:
            logging.error(f"Error scanning file {file_path}: {e}")
            return []

    def scan_memory(self, pid):
        """Scans the memory of a running process (requires elevated privileges)."""
        if not self.compiled_rules:
            return []
        
        try:
            matches = self.compiled_rules.match(pid=pid)
            return [match.rule for match in matches]
        except yara.Error as e:
            logging.error(f"YARA Error scanning PID {pid}: {e}")
            return []
        except Exception as e:
            # Handle other OS errors (like access denied)
            logging.error(f"System Error scanning PID {pid}: {e}")
            return []
