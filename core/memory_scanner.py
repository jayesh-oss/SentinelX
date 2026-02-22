import ctypes
import psutil
import logging
from ctypes import wintypes
import time

# --- Consts & Structs for Windows API ---
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000

PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

# Load kernel32
k32 = ctypes.WinDLL('kernel32', use_last_error=True)

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

# Setup function signatures
k32.OpenProcess.restype = wintypes.HANDLE
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]

k32.ReadProcessMemory.restype = wintypes.BOOL
k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

k32.CloseHandle.restype = wintypes.BOOL
k32.CloseHandle.argtypes = [wintypes.HANDLE]

class MemoryScanner:
    def __init__(self):
        self.rwx_pages_found = 0
        self.suspicious_processes = []
    
    def scan_all_processes(self):
        """Scans all running processes for injected memory anomalies (RWX). Requires Admin."""
        self.rwx_pages_found = 0
        self.suspicious_processes = []
        logging.info("Starting System-Wide Memory Hunt...")
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                
                # Skip System Idle Process and System
                if pid <= 4:
                    continue
                    
                detection = self.scan_process_memory(pid, name)
                if detection:
                    self.suspicious_processes.append(detection)
                    
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
            except Exception as e:
                logging.error(f"Error scanning PID {pid}: {e}")
                
        logging.info(f"Memory Hunt Completed. RWX Pages Found: {self.rwx_pages_found} across {len(self.suspicious_processes)} Processes.")
        return self.suspicious_processes

    def scan_process_memory(self, pid, name):
        """Iterates through a specific process's Virtual Memory, hunting for RWX (PAGE_EXECUTE_READWRITE) segments."""
        h_process = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h_process:
            return None # Access Denied usually (needs elevation)
            
        mbi = MEMORY_BASIC_INFORMATION()
        address = 0
        max_address = 0x7FFFFFFFFFFF # Max userspace address on 64-bit Windows

        detection_details = {
            "pid": pid,
            "name": name,
            "rwx_regions": 0,
            "threat": False,
            "details": []
        }

        while address < max_address:
            result = k32.VirtualQueryEx(h_process, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
            if result == 0 or mbi.RegionSize == 0:
                break # Reached end of memory

            # Hunt for RWX (Read-Write-Execute) private memory. 
            # This is a massive indicator of unpacked malware or Reflective DLL injection (Cobalt Strike).
            if mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE:
                if mbi.Protect == PAGE_EXECUTE_READWRITE:
                    self.rwx_pages_found += 1
                    detection_details["rwx_regions"] += 1
                    detection_details["threat"] = True
                    
                    # Read the first few bytes to check for MZ header (Reflective DLL)
                    buffer = ctypes.create_string_buffer(2)
                    bytes_read = ctypes.c_size_t(0)
                    
                    if k32.ReadProcessMemory(h_process, ctypes.c_void_p(address), buffer, 2, ctypes.byref(bytes_read)):
                        if buffer.raw == b'MZ':
                            detection_details["details"].append(f"Reflective DLL injected at 0x{address:X}")
                        else:
                            detection_details["details"].append(f"Private RWX Anomaly at 0x{address:X} (Size: {mbi.RegionSize} bytes)")

            address += mbi.RegionSize

        k32.CloseHandle(h_process)
        
        if detection_details["threat"]:
            return detection_details
        return None
        class SYSTEM_INFO(ctypes.Structure):
            _fields_ = [
                ("wProcessorArchitecture", wintypes.WORD),
                ("wReserved", wintypes.WORD),
                ("dwPageSize", wintypes.DWORD),
                ("lpMinimumApplicationAddress", ctypes.c_void_p),
                ("lpMaximumApplicationAddress", ctypes.c_void_p),
                ("dwActiveProcessorMask", ctypes.c_void_p),
                ("dwNumberOfProcessors", wintypes.DWORD),
                ("dwProcessorType", wintypes.DWORD),
                ("dwAllocationGranularity", wintypes.DWORD),
                ("wProcessorLevel", wintypes.WORD),
                ("wProcessorRevision", wintypes.WORD),
            ]
        sysinfo = SYSTEM_INFO()
        k32.GetSystemInfo(ctypes.byref(sysinfo))
        return sysinfo
