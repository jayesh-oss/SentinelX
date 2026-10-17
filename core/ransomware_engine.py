"""
Static per-file ransomware analysis engine for SentinelX.
Runs at the end of every scan when the shield is enabled.
"""

import os
import math
import collections
import logging

# ── Known ransomware file extensions ──────────────────────────────────────────
RANSOMWARE_EXTENSIONS = {
    '.locked', '.encrypted', '.crypt', '.enc', '.crypted', '.aes',
    '.ryk', '.ryuk', '.conti', '.hive', '.lockbit', '.maze',
    '.sodinokibi', '.revil', '.cerber', '.locky', '.wncry', '.wnry',
    '.petya', '.clop', '.dharma', '.stop', '.djvu', '.phobos',
    '.makop', '.avaddon', '.babuk', '.darkside', '.egregor',
    '.netwalker', '.ragnar', '.blackmatter', '.quantum', '.pysa',
    '.grief', '.yanluowang', '.saturn', '.karakurt', '.lockfile',
    '.lck', '.encode', '.encry', '.ezz', '.exx', '.zzz',
    '.xyz', '.aaa', '.abc', '.ccc', '.vvv', '.xtbl',
    '.rbr', '.rmd', '.r00t', '.r5a', '.ra1n',
    '.WNCRYPT', '.WCRY', '.WNcry',
}

# Extensions where we check entropy (documents that should be low-entropy)
DOCUMENT_EXTENSIONS = {
    '.doc', '.docx', '.xls', '.xlsx', '.pdf', '.txt',
    '.ppt', '.pptx', '.odt', '.csv', '.rtf', '.xml', '.html',
}

# Byte signatures of ransom note content embedded in executables
RANSOM_STRINGS = [
    b'your files have been encrypted',
    b'all your files are encrypted',
    b'your personal files are encrypted',
    b'all of your files are encrypted',
    b'files have been encrypted with',
    b'pay the ransom',
    b'buy decryption',
    b'buy our decryptor',
    b'to decrypt your files',
    b'decryption software',
    b'bitcoin address',
    b'send bitcoin',
    b'tor browser',
    b'.onion',
    b'vssadmin delete shadows',
    b'shadowcopy delete',
    b'bcdedit /set',
    b'wbadmin delete catalog',
]

# Anti-recovery API names
ANTI_RECOVERY_APIS = {
    'createvssbackupcomponents', 'deletesnapshot', 'isvssmountpoint',
    'exposesnapshot', 'reverttosnapshotset',
}


def _calc_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = collections.Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


class RansomwareEngine:
    """Static ransomware analysis: extension check, entropy, string scan, PE reuse."""

    def analyze(self, file_path: str, pe_analysis: dict = None) -> dict:
        result = {
            'file': file_path,
            'verdict': 'Clean',
            'score': 0,
            'indicators': [],
            'extension_verdict': 'Clean',
            'entropy': 0.0,
            'entropy_verdict': 'N/A',
            'ransom_strings_found': [],
            'crypto_apis': [],
            'anti_recovery': False,
        }

        try:
            ext = os.path.splitext(file_path)[1].lower()

            # ── 1. Known ransomware extension ────────────────────────────────
            if ext in RANSOMWARE_EXTENSIONS:
                result['extension_verdict'] = f'Known Ransomware Extension ({ext})'
                result['score'] += 80
                result['indicators'].append(f'Known ransomware file extension: {ext}')

            # ── 2. Read first 512 KB for content analysis ────────────────────
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(512 * 1024)
            except Exception as e:
                result['error'] = str(e)
                return result

            if not header:
                return result

            # ── 3. Entropy check (document extensions only) ──────────────────
            if ext in DOCUMENT_EXTENSIONS:
                entropy = _calc_entropy(header[:8192])
                result['entropy'] = entropy
                if entropy > 7.2:
                    result['entropy_verdict'] = f'High ({entropy:.2f}/8.0) — likely encrypted content'
                    result['score'] += 40
                    result['indicators'].append(f'High entropy for a document file ({entropy:.2f}/8.0)')
                elif entropy > 6.5:
                    result['entropy_verdict'] = f'Elevated ({entropy:.2f}/8.0)'
                    result['score'] += 15
                    result['indicators'].append(f'Elevated entropy ({entropy:.2f}/8.0)')
                else:
                    result['entropy_verdict'] = f'Normal ({entropy:.2f}/8.0)'

            # ── 4. Ransom note string scan (in binary content) ───────────────
            lower_data = header.lower()
            found_strings = []
            for sig in RANSOM_STRINGS:
                if sig in lower_data:
                    found_strings.append(sig.decode('utf-8', 'ignore'))
            if found_strings:
                result['ransom_strings_found'] = found_strings[:5]
                result['score'] += min(len(found_strings) * 20, 60)
                result['indicators'].append(
                    f'{len(found_strings)} ransom-related string(s) embedded in binary'
                )

            # ── 5. Reuse existing PE analysis (no extra I/O) ─────────────────
            if pe_analysis and pe_analysis.get('is_pe'):
                # Crypto APIs flagged by pe_analyzer
                crypto = pe_analysis.get('threat_categories', {}).get('Crypto (Ransomware)', [])
                if crypto:
                    result['crypto_apis'] = crypto
                    result['score'] += 30
                    result['indicators'].append(
                        f'Ransomware crypto APIs: {", ".join(crypto[:3])}'
                    )

                # Anti-recovery API imports
                for dll_funcs in pe_analysis.get('imports', {}).values():
                    for func in dll_funcs:
                        name = func.get('name', '').lower()
                        if name in ANTI_RECOVERY_APIS:
                            result['anti_recovery'] = True
                            result['score'] += 25
                            result['indicators'].append(
                                f'Shadow copy / VSS API: {func.get("name")}'
                            )
                            break
                    if result['anti_recovery']:
                        break

            # Anti-recovery commands embedded as strings
            if not result['anti_recovery'] and (
                b'vssadmin' in lower_data
                or b'shadowcopy delete' in lower_data
                or b'bcdedit' in lower_data
            ):
                result['anti_recovery'] = True
                result['score'] += 20
                result['indicators'].append('Anti-recovery commands embedded in binary')

            # ── Final verdict ─────────────────────────────────────────────────
            if result['score'] >= 80:
                result['verdict'] = 'Ransomware'
            elif result['score'] >= 40:
                result['verdict'] = 'Suspicious (Possible Ransomware)'
            else:
                result['verdict'] = 'Clean'

        except Exception as e:
            logging.error(f"[RansomwareEngine] Error analyzing {file_path}: {e}")
            result['error'] = str(e)

        return result
