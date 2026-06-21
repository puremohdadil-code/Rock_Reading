//============================================================================
//The Rock Reading - Memory Scanner Implementation
//============================================================================
#include "memory_scanner.h"
#include <algorithm>
#include <cstring>
#include <cwchar>
#include <stdexcept>

MemoryScanner::MemoryScanner() {}
MemoryScanner::~MemoryScanner() {}

size_t MemoryScanner::GetValueSize(ValueType type) {
    switch (type) {
        case ValueType::Byte:  return 1;
        case ValueType::Int16:  return 2;
        case ValueType::Int32:  return 4;
        case ValueType::Int64:  return 8;
        case ValueType::Float:  return 4;
        case ValueType::Double: return 8;
        case ValueType::String: return 0; // variable
    }
    return 0;
}

std::wstring MemoryScanner::FormatValue(const uint8_t* data, ValueType type) {
    if (!data) return L"?";
    wchar_t buf[128] = {};

    switch (type) {
        case ValueType::Byte:
            swprintf(buf, 128, L"%d", (int)(*data));
            break;
        case ValueType::Int16:
            swprintf(buf, 128, L"%d", (int)(*(const int16_t*)data));
            break;
        case ValueType::Int32:
            swprintf(buf, 128, L"%d", *(const int32_t*)data);
            break;
        case ValueType::Int64:
            swprintf(buf, 128, L"%lld", (long long)(*(const int64_t*)data));
            break;
        case ValueType::Float:
            swprintf(buf, 128, L"%.6g", (double)(*(const float*)data));
            break;
        case ValueType::Double:
            swprintf(buf, 128, L"%.10g", *(const double*)data);
            break;
        case ValueType::String: {
            std::wstring result;
            for (int i = 0; data[i] && i < 256; i++)
                result += static_cast<wchar_t>(data[i]);
            return result;
        }
    }
    return buf;
}

bool MemoryScanner::ParseValue(const std::wstring& str, ValueType type,
                               std::vector<uint8_t>& out) {
    out.clear();
    if (str.empty() && type != ValueType::String) return false;

    try {
        switch (type) {
            case ValueType::Byte: {
                int val = std::stoi(str);
                if (val < -128 || val > 255) return false;
                out.resize(1);
                out[0] = static_cast<uint8_t>(val);
                break;
            }
            case ValueType::Int16: {
                int val = std::stoi(str);
                out.resize(2);
                *reinterpret_cast<int16_t*>(out.data()) = static_cast<int16_t>(val);
                break;
            }
            case ValueType::Int32: {
                long val = std::stol(str);
                out.resize(4);
                *reinterpret_cast<int32_t*>(out.data()) = static_cast<int32_t>(val);
                break;
            }
            case ValueType::Int64: {
                long long val = std::stoll(str);
                out.resize(8);
                *reinterpret_cast<int64_t*>(out.data()) = static_cast<int64_t>(val);
                break;
            }
            case ValueType::Float: {
                float val = std::stof(str);
                out.resize(4);
                *reinterpret_cast<float*>(out.data()) = val;
                break;
            }
            case ValueType::Double: {
                double val = std::stod(str);
                out.resize(8);
                *reinterpret_cast<double*>(out.data()) = val;
                break;
            }
            case ValueType::String: {
                for (wchar_t c : str)
                    out.push_back(static_cast<uint8_t>(c & 0xFF));
                out.push_back(0); // null terminator
                break;
            }
        }
    } catch (...) {
        return false;
    }
    return !out.empty();
}

template <typename T>
static bool CompareTyped(const uint8_t* mem, const uint8_t* target,
                         ScanType scanType, const uint8_t* target2,
                         const uint8_t* previous) {
    T memVal = *reinterpret_cast<const T*>(mem);

    switch (scanType) {
        case ScanType::ExactValue:
            return target && memVal == *reinterpret_cast<const T*>(target);
        case ScanType::GreaterThan:
            return target && memVal > *reinterpret_cast<const T*>(target);
        case ScanType::LessThan:
            return target && memVal < *reinterpret_cast<const T*>(target);
        case ScanType::Between:
            return target && target2 &&
                   memVal >= *reinterpret_cast<const T*>(target) &&
                   memVal <= *reinterpret_cast<const T*>(target2);
      case ScanType::UnknownInitial:
         return true;
   case ScanType::Changed:
           return previous && memVal != *reinterpret_cast<const T*>(previous);
    case ScanType::Unchanged:
          return previous && memVal == *reinterpret_cast<const T*>(previous);
     case ScanType::Increased:
           return previous && memVal > *reinterpret_cast<const T*>(previous);
      case ScanType::Decreased:
        return previous && memVal < *reinterpret_cast<const T*>(previous);
    }
    return false;
}

bool MemoryScanner::CompareValues(const uint8_t* mem, const uint8_t* target,
                                  ValueType type, ScanType scanType,
                                  const uint8_t* target2,
                                  const uint8_t* previous) {
    switch (type) {
        case ValueType::Byte:
            return CompareTyped<uint8_t>(mem, target, scanType, target2, previous);
        case ValueType::Int16:
            return CompareTyped<int16_t>(mem, target, scanType, target2, previous);
        case ValueType::Int32:
            return CompareTyped<int32_t>(mem, target, scanType, target2, previous);
        case ValueType::Int64:
            return CompareTyped<int64_t>(mem, target, scanType, target2, previous);
        case ValueType::Float:
            return CompareTyped<float>(mem, target, scanType, target2, previous);
        case ValueType::Double:
            return CompareTyped<double>(mem, target, scanType, target2, previous);
        case ValueType::String: {
            if (scanType == ScanType::UnknownInitial) return true;
            if (scanType == ScanType::ExactValue && target) {
                return strcmp(reinterpret_cast<const char*>(mem),
                              reinterpret_cast<const char*>(target)) == 0;
            }
            if (scanType == ScanType::Changed && previous) {
                return strcmp(reinterpret_cast<const char*>(mem),
                              reinterpret_cast<const char*>(previous)) != 0;
            }
            if (scanType == ScanType::Unchanged && previous) {
                return strcmp(reinterpret_cast<const char*>(mem),
                              reinterpret_cast<const char*>(previous)) == 0;
            }
            return false;
        }
    }
    return false; 
}

bool MemoryScanner::FirstScan(ValueType vtype, ScanType stype,
                              const std::wstring& val1, const std::wstring& val2) {
    if (!m_pm || !m_pm->IsAttached()) return false;

    m_valueType = vtype;
    m_results.clear();
    // Clear undo stack
    while (!m_undoStack.empty()) m_undoStack.pop();

    size_t valueSize = GetValueSize(vtype);

    // Parse target values
    std::vector<uint8_t> targetValue, targetValue2;

    bool needsValue = (stype != ScanType::UnknownInitial &&
                       stype != ScanType::Changed &&
                       stype != ScanType::Unchanged &&
                       stype != ScanType::Increased &&
                       stype != ScanType::Decreased);

    if (needsValue) {
        if (!ParseValue(val1, vtype, targetValue)) return false;
        if (stype == ScanType::Between) {
            if (!ParseValue(val2, vtype, targetValue2)) return false;
        }
    }

    // For String type, get the size from the parsed value
    if (vtype == ValueType::String) {
        valueSize = targetValue.empty() ? 1 : targetValue.size();
    }

    // Get readable memory regions
    auto regions = m_pm->GetReadableRegions();

    const size_t CHUNK_SIZE = 65536; // 64 KB chunks
    std::vector<uint8_t> buffer;
    buffer.resize(CHUNK_SIZE + valueSize);

    bool limitReached = false;

    for (const auto& region : regions) {
        if (limitReached) break;

        for (size_t offset = 0; offset < region.size; offset += CHUNK_SIZE) {
            if (limitReached) break;

            size_t remaining = region.size - offset;
            size_t readSize = (remaining < CHUNK_SIZE + valueSize - 1)
                                  ? remaining
                                  : CHUNK_SIZE + valueSize - 1;
            if (readSize < valueSize) continue;

            if (!m_pm->ReadMemory(region.base + offset, buffer.data(), readSize))
                continue;

            // Alignment: scan at value-size boundaries (1 for strings/bytes)
            size_t alignment = (vtype == ValueType::String || vtype == ValueType::Byte)
                                   ? 1 : valueSize;

            for (size_t i = 0; i + valueSize <= readSize; i += alignment) {
                bool matches = CompareValues(
                    buffer.data() + i,
                    targetValue.empty() ? nullptr : targetValue.data(),
                    vtype, stype,
                    targetValue2.empty() ? nullptr : targetValue2.data(),
                    nullptr);

                if (matches) {
                    ScanResult result;
                    result.address = region.base + offset + i;
                    result.value.assign(buffer.data() + i,
                                        buffer.data() + i + valueSize);
                    result.previousValue = result.value;
                    m_results.push_back(result);

                    if (m_results.size() >= MAX_RESULTS) {
                        limitReached = true;
                        break;
                    }
                }
            }
        }
    }

    m_hasScanned = true;
    return true;
}

bool MemoryScanner::NextScan(ScanType stype,
                             const std::wstring& val1, const std::wstring& val2) {
    if (!m_pm || !m_pm->IsAttached() || !m_hasScanned) return false;

    // Save current state for undo
    m_undoStack.push(m_results);

    size_t valueSize = GetValueSize(m_valueType);
    if (m_valueType == ValueType::String && !m_results.empty()) {
        valueSize = m_results[0].value.size();
    }

    // Parse target values
    std::vector<uint8_t> targetValue, targetValue2;

    bool needsValue = (stype == ScanType::ExactValue ||
                       stype == ScanType::GreaterThan ||
                       stype == ScanType::LessThan ||
                       stype == ScanType::Between);

    if (needsValue) {
        if (!ParseValue(val1, m_valueType, targetValue)) return false;
        if (stype == ScanType::Between) {
            if (!ParseValue(val2, m_valueType, targetValue2)) return false;
        }
    }

    std::vector<ScanResult> newResults;
    newResults.reserve(m_results.size() / 2); // rough estimate

    for (auto& result : m_results) {
        std::vector<uint8_t> currentValue(valueSize);
        if (!m_pm->ReadMemory(result.address, currentValue.data(), valueSize))
            continue;

        bool matches = CompareValues(
            currentValue.data(),
            targetValue.empty() ? nullptr : targetValue.data(),
            m_valueType, stype,
            targetValue2.empty() ? nullptr : targetValue2.data(),
            result.value.data());

        if (matches) {
            result.previousValue = result.value;
            result.value = currentValue;
            newResults.push_back(result);
        }
    }

    m_results = std::move(newResults);
    return true;
}

void MemoryScanner::Reset() {
    m_results.clear();
    while (!m_undoStack.empty()) m_undoStack.pop();
    m_hasScanned = false;
}

void MemoryScanner::UndoScan() {
    if (m_undoStack.empty()) return;
    m_results = std::move(m_undoStack.top());
    m_undoStack.pop();
}
