// ==========================================================================
// 0Rock Reading - Process Manager Header
// Handles process enumeration, attachment, and memory read/write operations.
// ==========================================================================
#pragma once
  
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <cstdint>

struct ProcessInfo {
    DWORD pid;
    std::wstring name;
};


class ProcessManager {
public:
    ProcessManager();
    ~ProcessManager();

    ProcessManager(const ProcessManager&) = delete;
    ProcessManager& operator=(const ProcessManager&) = delete;

    static std::vector<ProcessInfo> GetRunningProcesses();

    bool Attach(DWORD pid);

    void Detach();

    bool IsAttached() const { return m_hProcess != nullptr; }

    bool IsProcessAlive() const;

    DWORD GetPID() const { return m_pid; }

    const std::wstring& GetName() const { return m_processName; }

    HANDLE GetHandle() const { return m_hProcess; }

    bool ReadMemory(uintptr_t address, void* buffer, size_t size) const;

    bool WriteMemory(uintptr_t address, const void* data, size_t size) const;

    struct MemoryRegion {
        uintptr_t base;
        size_t    size;
    };

    // Get all readable/writable memory regions of the attached process
    std::vector<MemoryRegion> GetReadableRegions() const;

    static bool EnableDebugPrivilege();

private:
    HANDLE       m_hProcess    = nullptr;
    DWORD        m_pid         = 0;
    std::wstring m_processName;
};
