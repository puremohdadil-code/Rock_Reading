#pragma once

#include "process_manager.h"
#include <vector>
#include <string>
#include <cstdint>
#include <stack>
  
  
enum class ValueType {
    Byte   = 0,  //1 byte  (uint8_t)
    Int16  = 1,  //2 bytes (int16_t)
    Int32  = 2,  //4 bytes (int32_t)
    Int64  = 3,  //8 bytes (int64_t)
    Float  = 4,  //4 bytes (float)
    Double = 5,  //8 bytes (double)
    String = 6   //Variable length (ASCII)
};

enum class ScanType {
    ExactValue      = 0,
    GreaterThan     = 1,
    LessThan        = 2,
    Between         = 3,   //value1 <= x <= value2
    UnknownInitial  = 4,   //Store all values (first scan only)
    Changed         = 5,   //Value changed since last scan
    Unchanged       = 6,   //Value unchanged since last scan
    Increased       = 7,   //Value increased since last scan
    Decreased       = 8    //Value decreased since last scan
};

struct ScanResult {
    uintptr_t              address;
    std::vector<uint8_t>   value;          //Current value bytes
    std::vector<uint8_t>   previousValue;  //Value from previous scan
};

class MemoryScanner {
public:
    MemoryScanner();
    ~MemoryScanner();

    //Set the process manager to use for memory access
    void SetProcessManager(ProcessManager* pm) { m_pm = pm; }

    //---- Scanning ----

    //Perform the first scan with given parameters.
    //val1: Primary search value (ignored for UnknownInitial)
    //val2: Secondary value (only used for Between scan type)
    //Returns true on success.
    bool FirstScan(ValueType vtype, ScanType stype,
                   const std::wstring& val1, const std::wstring& val2 = L"");

    //Perform a subsequent scan to narrow down results.
    bool NextScan(ScanType stype,
                  const std::wstring& val1, const std::wstring& val2 = L"");

    //Reset scanner state (clear all results)
    void Reset();

    //Undo the last scan (revert to previous results)
    bool CanUndo() const { return !m_undoStack.empty(); }
    void UndoScan();

    //----Results----

    const std::vector<ScanResult>& GetResults() const { return m_results; }
    size_t GetResultCount() const { return m_results.size(); }
    ValueType GetValueType() const { return m_valueType; }
    bool HasScanned() const { return m_hasScanned; }

    // ----Utility (static)----

    //Get the byte size of a value type (0 for String, as it's variable)
    static size_t GetValueSize(ValueType type);

    //Format raw bytes as a human-readable string
    static std::wstring FormatValue(const uint8_t* data, ValueType type);

    //Parse a string into raw bytes for the given value type
    static bool ParseValue(const std::wstring& str, ValueType type,
                           std::vector<uint8_t>& out);

    //Compare a memory value against target(s) using the given scan type
    static bool CompareValues(const uint8_t* mem, const uint8_t* target,
                              ValueType type, ScanType scanType,
                              const uint8_t* target2 = nullptr,
                              const uint8_t* previous = nullptr);

private:
    ProcessManager*                          m_pm = nullptr;
    std::vector<ScanResult>                  m_results;
    std::stack<std::vector<ScanResult>>      m_undoStack;
    ValueType                                m_valueType  = ValueType::Int32;
    bool                                     m_hasScanned = false;

    //.Maximum results to store (to prevent excessive memory usage)
    static constexpr size_t MAX_RESULTS = 20000000; // 20 million
};
