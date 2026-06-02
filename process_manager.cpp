//============================================================================
//Rock Reading - Process Manager Implementation
//============================================================================
#include "process_manager.h"
#include <algorithm>

ProcessManager::ProcessManager() {}

ProcessManager::~ProcessManager() {
    Detach();
}

bool ProcessManager::EnableDebugPrivilege() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return false;
    }

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    DWORD err = GetLastError();
    CloseHandle(hToken);

    return ok && (err == ERROR_SUCCESS);
}

std::vector<ProcessInfo> ProcessManager::GetRunningProcesses() {
    std::vector<ProcessInfo> processes;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return processes;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnap, &pe)) {
        do {
            //Skip system idle process
            if (pe.th32ProcessID == 0) continue;

            ProcessInfo info;
            info.pid  = pe.th32ProcessID;
            info.name = pe.szExeFile;
            processes.push_back(info);
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);

    //Sort alphabetically by name (case-insensitive)
    std::sort(processes.begin(), processes.end(),
              [](const ProcessInfo& a, const ProcessInfo& b) {
                  return _wcsicmp(a.name.c_str(), b.name.c_str()) < 0;
              });

    return processes;
}

bool ProcessManager::Attach(DWORD pid) {
    Detach();

    //Try full access first
    m_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    //Fallback to minimal access
    if (!m_hProcess) {
        m_hProcess = OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
            PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE, pid);
    }

    if (!m_hProcess) return false;

    m_pid = pid;

    //Get the process name
    WCHAR name[MAX_PATH] = {};
    if (GetModuleBaseNameW(m_hProcess, nullptr, name, MAX_PATH)) {
        m_processName = name;
    } else {
        m_processName = L"Unknown";
    }

    return true;
}

void ProcessManager::Detach() {
    if (m_hProcess) {
        CloseHandle(m_hProcess);
        m_hProcess = nullptr;
    }
    m_pid = 0;
    m_processName.clear();
}

bool ProcessManager::IsProcessAlive() const {
    if (!m_hProcess) return false;
    DWORD exitCode = 0;
    if (!GetExitCodeProcess(m_hProcess, &exitCode)) return false;
    return exitCode == STILL_ACTIVE;
}

bool ProcessManager::ReadMemory(uintptr_t address, void* buffer, size_t size) const {
    if (!m_hProcess) return false;
    SIZE_T bytesRead = 0;
    return ReadProcessMemory(m_hProcess, reinterpret_cast<LPCVOID>(address),
                             buffer, size, &bytesRead) && bytesRead == size;
}

bool ProcessManager::WriteMemory(uintptr_t address, const void* data, size_t size) const {
    if (!m_hProcess) return false;
    SIZE_T bytesWritten = 0;
    return WriteProcessMemory(m_hProcess, reinterpret_cast<LPVOID>(address),
                              data, size, &bytesWritten) && bytesWritten == size;
}

std::vector<ProcessManager::MemoryRegion> ProcessManager::GetReadableRegions() const {
    std::vector<MemoryRegion> regions;
    if (!m_hProcess) return regions;

    MEMORY_BASIC_INFORMATION mbi = {};
    uintptr_t address = 0;

    while (VirtualQueryEx(m_hProcess, reinterpret_cast<LPCVOID>(address),
                          &mbi, sizeof(mbi))) {
        //Include committed, non-guarded, accessible regions
        if (mbi.State == MEM_COMMIT &&
            !(mbi.Protect & PAGE_GUARD) &&
            !(mbi.Protect & PAGE_NOACCESS)) {
            DWORD prot = mbi.Protect & 0xFF;
            if (prot == PAGE_READONLY       || prot == PAGE_READWRITE       ||
                prot == PAGE_WRITECOPY      || prot == PAGE_EXECUTE_READ    ||
                prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY) {
                MemoryRegion region;
                region.base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                region.size = mbi.RegionSize;
                regions.push_back(region);
            }
        }

        uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= address) break; // overflow guard
        address = next;
    }

    return regions;
}
