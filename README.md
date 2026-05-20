# RS - Memory Scanner & Editor

A powerful, easy-to-use memory scanner and editor for Windows games and applications, built with C++ and Win32 API.

---

## Features

| Feature | Description |
|---------|-------------|
| **Process Selection** | Browse and attach to any running process with search/filter |
| **Memory Scanner** | Scan process memory for values with multiple data types |
| **Value Types** | Byte, 2 Bytes, 4 Bytes, 8 Bytes, Float, Double, String |
| **Scan Types** | Exact Value, Greater/Less Than, Between, Unknown Initial, Changed, Unchanged, Increased, Decreased |
| **Next Scan** | Progressively narrow down results with subsequent scans |
| **Undo Scan** | Revert to previous scan results if needed |
| **Address Table** | Save important addresses with descriptions |
| **Freeze Values** | Lock values so the game can't change them (checkbox) |
| **Edit Values** | Write new values directly to memory |
| **Live Updates** | Address table values refresh automatically every 250ms |


### Using CMake

```bash
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

### Manual Compilation (MSVC)

```bash
cl /EHsc /std:c++17 /DUNICODE /D_UNICODE /DNOMINMAX /O2 /Fe:CheatEnginePro.exe src\main.cpp src\process_manager.cpp src\memory_scanner.cpp /link user32.lib gdi32.lib comctl32.lib psapi.lib advapi32.lib shell32.lib
```

### Manual Compilation (MinGW g++)

```bash
g++ -std=c++17 -DUNICODE -D_UNICODE -DNOMINMAX -O2 -mwindows -o CheatEnginePro.exe src/main.cpp src/process_manager.cpp src/memory_scanner.cpp -luser32 -lgdi32 -lcomctl32 -lpsapi -ladvapi32 -lshell32
```

### Requirements
- Windows 7 or later
- C++17 compatible compiler (MSVC 2017+ or MinGW-w64)
- No external libraries needed (pure Win32 API)


### Value Types Guide:
| Type | Size | Common Use |
|------|------|------------|
| Byte | 1 byte | Small values (0-255) |
| 2 Bytes | 2 bytes | Medium values (0-65535) |
| **4 Bytes** | 4 bytes | **Most common** - health, ammo, money |
| 8 Bytes | 8 bytes | Large values, some 64-bit games |
| Float | 4 bytes | Decimal values (health bars, coordinates) |
| Double | 8 bytes | High-precision decimals |
| String | variable | Text values (player name, etc.) |

---

## Project Structure

```
├── CMakeLists.txt              # CMake build configuration
├── build.bat                   # Simple build script
├── README.md                   # This file
└── src/
    ├── main.cpp                # GUI application (Win32)
    ├── process_manager.h       # Process attachment & memory I/O
    ├── process_manager.cpp     # Process manager implementation
    ├── memory_scanner.h        # Memory scanning engine
    └── memory_scanner.cpp      # Scanner implementation
```

---

## Architecture

```
┌─────────────────────────────────────────────┐
│              main.cpp (GUI)                 │
│  ┌───────────────┐  ┌────────────────────┐  │
│  │ Process Select│  │  Memory Scanner    │  │
│  │    Dialog     │  │    Controls        │  │
│  └───────────────┘  └────────────────────┘  │
│  ┌───────────────────────────────────────┐  │
│  │         Found Addresses List          │  │
│  │        (Virtual ListView)             │  │
│  └───────────────────────────────────────┘  │
│  ┌───────────────────────────────────────┐  │
│  │     Address Table (with Freeze)       │  │
│  └───────────────────────────────────────┘  │
├─────────────────────────────────────────────┤
│  ProcessManager    │  MemoryScanner         │
│  - Attach/Detach   │  - FirstScan           │
│  - ReadMemory      │  - NextScan            │
│  - WriteMemory     │  - Undo/Reset          │
│  - EnumRegions     │  - CompareValues       │
└─────────────────────────────────────────────┘
```
