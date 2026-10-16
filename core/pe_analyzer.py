import math
import collections
import pefile


THREAT_CATEGORIES = {
    "Process Injection": [
        "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
        "QueueUserAPC", "SetThreadContext", "NtMapViewOfSection",
        "NtWriteVirtualMemory", "RtlCreateUserThread", "NtQueueApcThread",
    ],
    "Code Loading": [
        "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
        "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress",
    ],
    "Memory Manipulation": [
        "VirtualAlloc", "VirtualProtect", "VirtualProtectEx",
        "HeapCreate", "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
    ],
    "Evasion / Anti-Debug": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "GetTickCount", "QueryPerformanceCounter",
        "OutputDebugStringA", "NtSetInformationThread",
    ],
    "Persistence": [
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
        "CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW",
    ],
    "Credential Access": [
        "CredEnumerateA", "CredEnumerateW",
        "CryptUnprotectData", "LsaRetrievePrivateData",
        "SamIConnect", "SamrQueryInformationUser",
    ],
    "Networking": [
        "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW",
        "HttpOpenRequestA", "HttpSendRequestA",
        "WSAStartup", "connect", "send", "recv",
        "URLDownloadToFileA", "URLDownloadToFileW",
    ],
    "Crypto (Ransomware)": [
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptDeriveKey",
        "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey",
    ],
    "Process / Thread Control": [
        "CreateProcessA", "CreateProcessW", "CreateProcessInternalW",
        "TerminateProcess", "OpenProcess", "OpenThread",
        "SuspendThread", "ResumeThread", "NtResumeThread",
        "WinExec", "ShellExecuteA", "ShellExecuteW",
    ],
}

_API_LOOKUP = {}
for _cat, _apis in THREAT_CATEGORIES.items():
    for _api in _apis:
        _API_LOOKUP[_api.lower()] = _cat

SUSPICIOUS_SECTION_NAMES = {
    "UPX0", "UPX1", "UPX2", "UPX!",
    ".themida", ".vmp0", ".vmp1", ".vmp2",
    ".aspack", ".adata", ".packed",
    ".nsp0", ".nsp1", ".nsp2",
}


def _section_entropy(section_data):
    if not section_data:
        return 0.0
    length = len(section_data)
    counts = collections.Counter(section_data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def analyze(pe, file_data, overall_entropy):
    """Full PE analysis: IAT enumeration, threat categorization, section entropy, anomalies."""
    result = {
        "is_pe": True,
        "entropy": overall_entropy,
        "number_of_sections": len(pe.sections),
        "imports": {},
        "suspicious_imports": [],
        "threat_categories": {},
        "section_analysis": [],
        "anomalies": [],
        "error": None,
    }

    _enumerate_imports(pe, result)
    _analyze_sections(pe, result)
    _detect_anomalies(pe, file_data, result)

    return result


def _enumerate_imports(pe, result):
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return

    all_suspicious = []
    cat_hits = {}

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode("utf-8", "ignore") if entry.dll else "unknown"
        funcs = []
        for imp in entry.imports:
            if imp.name:
                name_str = imp.name.decode("utf-8", "ignore")
                funcs.append({"name": name_str, "address": hex(imp.address) if imp.address else "0x0"})

                cat = _API_LOOKUP.get(name_str.lower())
                if cat:
                    all_suspicious.append(name_str)
                    cat_hits.setdefault(cat, []).append(name_str)
            else:
                funcs.append({"name": f"Ordinal {imp.ordinal}", "address": hex(imp.address) if imp.address else "0x0"})

        result["imports"][dll_name] = funcs

    result["suspicious_imports"] = all_suspicious
    result["threat_categories"] = cat_hits


def _analyze_sections(pe, result):
    for section in pe.sections:
        name = section.Name.decode("utf-8", "ignore").rstrip("\x00")
        raw_data = section.get_data()
        entropy = _section_entropy(raw_data)
        result["section_analysis"].append({
            "name": name,
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "entropy": entropy,
            "characteristics": hex(section.Characteristics),
        })


def _detect_anomalies(pe, file_data, result):
    anomalies = result["anomalies"]

    for sec_info in result["section_analysis"]:
        if sec_info["name"] in SUSPICIOUS_SECTION_NAMES:
            anomalies.append(f"Suspicious section name: {sec_info['name']}")

    for sec_info in result["section_analysis"]:
        if sec_info["raw_size"] > 0 and sec_info["virtual_size"] > 0:
            ratio = sec_info["virtual_size"] / sec_info["raw_size"]
            if ratio > 10:
                anomalies.append(f"Section '{sec_info['name']}' size mismatch (VirtualSize/RawSize = {ratio:.1f})")

    try:
        timestamp = pe.FILE_HEADER.TimeDateStamp
        if timestamp == 0:
            anomalies.append("Zero PE timestamp (likely tampered)")
    except Exception:
        pass

    try:
        checksum = pe.OPTIONAL_HEADER.CheckSum
        if checksum == 0:
            anomalies.append("Zero PE checksum")
    except Exception:
        pass

    num_sections = len(pe.sections)
    if num_sections > 20:
        anomalies.append(f"Abnormal section count: {num_sections}")
    elif num_sections == 0:
        anomalies.append("PE has zero sections")

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        dll_count = len(pe.DIRECTORY_ENTRY_IMPORT)
        if dll_count == 0:
            anomalies.append("No imports (possible packed/shellcode)")
        elif dll_count == 1:
            anomalies.append("Single DLL import (possibly packed)")

    try:
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_in_section = False
        for section in pe.sections:
            s_start = section.VirtualAddress
            s_end = s_start + section.Misc_VirtualSize
            if s_start <= ep < s_end:
                ep_in_section = True
                sec_name = section.Name.decode("utf-8", "ignore").rstrip("\x00")
                if sec_name not in (".text", ".code", "CODE", ".itext"):
                    anomalies.append(f"Entry point in non-standard section: {sec_name}")
                break
        if not ep_in_section:
            anomalies.append("Entry point outside any section")
    except Exception:
        pass
