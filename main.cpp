#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <uxtheme.h>
#include <string>
#include <vector>
#include <algorithm>
#include <sstream>
#include <cstdio>
#include <ctime>
#include <cmath>

#include "process_manager.h"
#include "memory_scanner.h"
#include "game_analyzer.h"
#include "arabic_guide.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "uxtheme.lib")

#pragma comment(linker, "/manifestdependency:\"type='win32' " \
    "name='Microsoft.Windows.Common-Controls' version='6.0.0.0' " \
    "processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")


static const COLORREF CLR_BG_DARK    = RGB(15, 17, 26);
static const COLORREF CLR_BG_PANEL   = RGB(22, 27, 34);
static const COLORREF CLR_BG_CARD    = RGB(30, 35, 44);
static const COLORREF CLR_BG_INPUT   = RGB(13, 17, 23);
static const COLORREF CLR_ACCENT     = RGB(0, 200, 255);
static const COLORREF CLR_ACCENT_DIM = RGB(0, 80, 110);
static const COLORREF CLR_TEXT       = RGB(230, 237, 243);
static const COLORREF CLR_TEXT_DIM   = RGB(125, 133, 144);
static const COLORREF CLR_BORDER     = RGB(48, 54, 61);
static const COLORREF CLR_SUCCESS    = RGB(63, 185, 80);
static const COLORREF CLR_ERROR      = RGB(248, 81, 73);
static const COLORREF CLR_HEADER     = RGB(10, 12, 18);
static const COLORREF CLR_BTN_BG     = RGB(33, 38, 45);
static const COLORREF CLR_BTN_HOVER  = RGB(48, 54, 61);
static const int HEADER_HEIGHT = 52;

static HBRUSH g_hDarkBgBrush   = nullptr;
static HBRUSH g_hPanelBgBrush  = nullptr;
static HBRUSH g_hCardBgBrush   = nullptr;
static HBRUSH g_hInputBgBrush  = nullptr;
static HBRUSH g_hHeaderBrush   = nullptr;

enum CtrlID {
    IDC_PROCESS_BTN = 1001, IDC_PROCESS_LABEL,
    IDC_VALUE_TYPE_COMBO, IDC_SCAN_TYPE_COMBO,
    IDC_VALUE_EDIT, IDC_VALUE2_EDIT, IDC_VALUE2_LABEL,
    IDC_FIRST_SCAN_BTN, IDC_NEXT_SCAN_BTN, IDC_UNDO_SCAN_BTN, IDC_RESET_BTN,
    IDC_FOUND_LIST, IDC_FOUND_COUNT,
    IDC_ADD_TO_TABLE_BTN, IDC_ADDRESS_TABLE,
    IDC_ADD_ADDR_BTN, IDC_REMOVE_ADDR_BTN, IDC_EDIT_VALUE_BTN,
    IDC_STATUSBAR, IDC_SCANNER_GROUP, IDC_TABLE_GROUP,
    IDC_WRITE_VALUE_BTN,
    IDC_TAB_CTRL = 1100,
    IDC_ANALYSIS_SEARCH_EDIT = 1200, IDC_ANALYSIS_SEARCH_BTN,
    IDC_ANALYSIS_COMBO, IDC_ANALYSIS_LIST,
    IDC_ANALYSIS_DETAIL, IDC_ANALYSIS_DETAIL_LABEL,
    IDC_ANALYSIS_NEARBY_BTN,
    IDC_GUIDE_LIST = 1300, IDC_GUIDE_TEXT,
    IDC_LOG_LIST = 1400,
    IDC_LOG_GROUP,
    IDC_TIMER_UPDATE = 2001
};

static HINSTANCE g_hInst;
static HWND g_hMainWnd;
static HWND g_hProcessBtn, g_hProcessLabel;
static HWND g_hValueTypeCombo, g_hScanTypeCombo;
static HWND g_hValueEdit, g_hValue2Edit, g_hValue2Label;
static HWND g_hFirstScanBtn, g_hNextScanBtn, g_hUndoScanBtn, g_hResetBtn;
static HWND g_hFoundList, g_hFoundCount;
static HWND g_hAddToTableBtn, g_hWriteValueBtn;
static HWND g_hAddressTable;
static HWND g_hAddAddrBtn, g_hRemoveAddrBtn, g_hEditValueBtn;
static HWND g_hStatusBar;
static HWND g_hScannerGroup, g_hTableGroup;
static HWND g_hLogGroup, g_hLogList;

static HWND g_hTabCtrl;
static HWND g_hAnalysisSearchEdit, g_hAnalysisSearchBtn;
static HWND g_hAnalysisCombo, g_hAnalysisList;
static HWND g_hAnalysisDetail, g_hAnalysisDetailLabel;
static HWND g_hAnalysisNearbyBtn;
static HWND g_hGuideList, g_hGuideText;

static HFONT g_hFont        = nullptr;
static HFONT g_hBoldFont    = nullptr;
static HFONT g_hMonoFont    = nullptr;
static HFONT g_hTitleFont   = nullptr;

static ProcessManager g_ProcessManager;
static MemoryScanner  g_Scanner;
static GameAnalyzer   g_Analyzer;

static int g_currentTab = 0;

static std::vector<StringSearchResult> g_searchResults;
static std::vector<ModuleInfo>         g_moduleResults;
static std::vector<MemoryRegionDetail> g_regionResults;
static std::vector<ThreadInfo>         g_threadResults;
static int g_analysisMode = 0;

static std::vector<GuideSection> g_guideSections;

struct AddressEntry {
    uintptr_t            address;
    std::wstring         description;
    ValueType            type;
    bool                 frozen;
    std::vector<uint8_t> frozenValue;
};
static std::vector<AddressEntry> g_AddressTable;

static const wchar_t* VALUE_TYPE_NAMES[] = {
    L"Byte (1)", L"2 Bytes", L"4 Bytes", L"8 Bytes",
    L"Float", L"Double", L"String (ASCII)"
};
static const int VALUE_TYPE_COUNT = 7;

static const wchar_t* SCAN_TYPE_NAMES[] = {
    L"Exact Value", L"Greater Than", L"Less Than", L"Between",
    L"Unknown Initial Value",
    L"Changed", L"Unchanged", L"Increased", L"Decreased"
};
static const int SCAN_TYPE_COUNT = 9;

static LRESULT CALLBACK MainWndProc(HWND, UINT, WPARAM, LPARAM);
static void CreateMainControls(HWND hWnd);
static void OnResize(HWND hWnd);
static void UpdateScanUI();
static void UpdateStatusBar(const wchar_t* text);
static void OnSelectProcess();
static void OnFirstScan();
static void OnNextScan();
static void OnUndoScan();
static void OnResetScan();
static void OnAddToTable();
static void OnAddAddressManual();
static void OnRemoveAddress();
static void OnEditValue();
static void OnWriteFoundValue();
static void OnTimer();
static void RefreshFoundList();
static void RefreshAddressTable();
static void SwitchTab(int tabIndex);
static void OnAnalysisSearch();
static void OnAnalysisSelChange();
static void OnAnalysisNearby();
static void OnGuideSelChange();
static void AddLog(const wchar_t* msg);
static void AddLogf(const wchar_t* fmt, ...);
static void DrawEyeLogo(HDC hdc, int x, int y, int w, int h);
static void DrawDarkButton(LPDRAWITEMSTRUCT lpDIS, bool isAccent);

static void DrawEyeLogo(HDC hdc, int x, int y, int w, int h) {
    int cx = x + w / 2, cy = y + h / 2;

    // Outer glow (thicker, dimmer)
    HPEN hGlow = CreatePen(PS_SOLID, 3, CLR_ACCENT_DIM);
    HPEN oldPen = (HPEN)SelectObject(hdc, hGlow);
    HBRUSH oldBr = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));

    POINT ug[] = {{x-2, cy}, {x + w/4, y-3}, {x + 3*w/4, y-3}, {x+w+2, cy}};
    PolyBezier(hdc, ug, 4);
    POINT lg[] = {{x-2, cy}, {x + w/4, y+h+3}, {x + 3*w/4, y+h+3}, {x+w+2, cy}};
    PolyBezier(hdc, lg, 4);

    // Eye outline
    HPEN hPenEye = CreatePen(PS_SOLID, 2, CLR_ACCENT);
    SelectObject(hdc, hPenEye);

    POINT upper[] = {{x, cy}, {x + w/4, y}, {x + 3*w/4, y}, {x + w, cy}};
    PolyBezier(hdc, upper, 4);
    POINT lower[] = {{x, cy}, {x + w/4, y + h}, {x + 3*w/4, y + h}, {x + w, cy}};
    PolyBezier(hdc, lower, 4);

    // Iris
    HBRUSH hIris = CreateSolidBrush(CLR_ACCENT);
    SelectObject(hdc, hIris);
    HPEN hIrisPen = CreatePen(PS_SOLID, 1, CLR_ACCENT);
    SelectObject(hdc, hIrisPen);
    int ir = h / 3 + 1;
    Ellipse(hdc, cx - ir, cy - ir, cx + ir, cy + ir);

    // Pupil
    HBRUSH hPupil = CreateSolidBrush(RGB(5, 8, 15));
    SelectObject(hdc, hPupil);
    HPEN hPupilPen = CreatePen(PS_SOLID, 1, RGB(5, 8, 15));
    SelectObject(hdc, hPupilPen);
    int pr = ir * 2 / 3;
    Ellipse(hdc, cx - pr, cy - pr, cx + pr, cy + pr);

    // CPU crosshair inside pupil
    HPEN hCross = CreatePen(PS_SOLID, 1, CLR_ACCENT);
    SelectObject(hdc, hCross);
    MoveToEx(hdc, cx - pr + 2, cy, nullptr);
    LineTo(hdc, cx + pr - 2, cy);
    MoveToEx(hdc, cx, cy - pr + 2, nullptr);
    LineTo(hdc, cx, cy + pr - 2);

    // Corner dots
    int d = pr / 2;
    HBRUSH hDot = CreateSolidBrush(CLR_ACCENT);
    SelectObject(hdc, hDot);
    Ellipse(hdc, cx+d-1, cy+d-1, cx+d+2, cy+d+2);
    Ellipse(hdc, cx-d-1, cy+d-1, cx-d+2, cy+d+2);
    Ellipse(hdc, cx+d-1, cy-d-1, cx+d+2, cy-d+2);
    Ellipse(hdc, cx-d-1, cy-d-1, cx-d+2, cy-d+2);

    SelectObject(hdc, oldPen);
    SelectObject(hdc, oldBr);
    DeleteObject(hGlow);
    DeleteObject(hPenEye);
    DeleteObject(hIris);
    DeleteObject(hIrisPen);
    DeleteObject(hPupil);
    DeleteObject(hPupilPen);
    DeleteObject(hCross);
    DeleteObject(hDot);
}

static void DrawDarkButton(LPDRAWITEMSTRUCT lpDIS, bool isAccent) {
    HDC hdc = lpDIS->hDC;
    RECT rc = lpDIS->rcItem;
    bool pressed = (lpDIS->itemState & ODS_SELECTED) != 0;
    bool disabled = (lpDIS->itemState & ODS_DISABLED) != 0;
    bool focused = (lpDIS->itemState & ODS_FOCUS) != 0;

    COLORREF bg;
    if (disabled) bg = RGB(20, 22, 30);
    else if (pressed) bg = isAccent ? RGB(0, 50, 70) : RGB(18, 20, 28);
    else if (isAccent) bg = CLR_ACCENT_DIM;
    else bg = CLR_BTN_BG;

    HBRUSH hBg = CreateSolidBrush(bg);
    FillRect(hdc, &rc, hBg);
    DeleteObject(hBg);

    COLORREF borderClr = focused ? CLR_ACCENT : (isAccent ? CLR_ACCENT : CLR_BORDER);
    HPEN hPen = CreatePen(PS_SOLID, 1, borderClr);
    HPEN oldPen = (HPEN)SelectObject(hdc, hPen);
    HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
    RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, 6, 6);
    SelectObject(hdc, oldPen);
    SelectObject(hdc, oldBrush);
    DeleteObject(hPen);

    SetBkMode(hdc, TRANSPARENT);
    COLORREF textClr = disabled ? CLR_TEXT_DIM : (isAccent ? CLR_ACCENT : CLR_TEXT);
    SetTextColor(hdc, textClr);

    wchar_t text[256];
    GetWindowTextW(lpDIS->hwndItem, text, 256);
    if (g_hFont) SelectObject(hdc, g_hFont);
    DrawTextW(hdc, text, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

static void SetCtrlText(HWND h, const wchar_t* t) {
    SetWindowTextW(h, t);
}

static std::wstring FormatNumber(size_t n) {
    std::wstring s = std::to_wstring(n);
    int insertPos = (int)s.length() - 3;
    while (insertPos > 0) {
        s.insert(insertPos, L",");
        insertPos -= 3;
    }
    return s;
}

static std::wstring FormatSize(size_t bytes) {
    if (bytes >= 1073741824)
        return std::to_wstring(bytes / 1073741824) + L" GB";
    if (bytes >= 1048576)
        return std::to_wstring(bytes / 1048576) + L" MB";
    if (bytes >= 1024)
        return std::to_wstring(bytes / 1024) + L" KB";
    return std::to_wstring(bytes) + L" B";
}

static void MakeOwnerDraw(HWND hBtn) {
    if (!hBtn) return;
    LONG style = GetWindowLongW(hBtn, GWL_STYLE);
    style = (style & ~0x0FL) | BS_OWNERDRAW;
    SetWindowLongW(hBtn, GWL_STYLE, style);
    InvalidateRect(hBtn, nullptr, TRUE);
}

static void ApplyDarkToControl(HWND h) {
    if (!h) return;
    SetWindowTheme(h, L"", L"");
}

static void AddLog(const wchar_t* msg) {
    if (!g_hLogList) return;

    time_t now = time(nullptr);
    struct tm lt = {};
    localtime_s(&lt, &now);
    wchar_t timeBuf[32];
    swprintf(timeBuf, 32, L"[%02d:%02d:%02d] ", lt.tm_hour, lt.tm_min, lt.tm_sec);

    std::wstring fullMsg = timeBuf;
    fullMsg += msg;

    int idx = (int)SendMessageW(g_hLogList, LB_ADDSTRING, 0,
                                (LPARAM)fullMsg.c_str());
    SendMessage(g_hLogList, LB_SETTOPINDEX, idx, 0);

    while (SendMessage(g_hLogList, LB_GETCOUNT, 0, 0) > 500)
        SendMessage(g_hLogList, LB_DELETESTRING, 0, 0);
}

static void AddLogf(const wchar_t* fmt, ...) {
    wchar_t buf[1024];
    va_list args;
    va_start(args, fmt);
    vswprintf(buf, 1024, fmt, args);
    va_end(args);
    AddLog(buf);
}

struct ProcessDialogData {
    DWORD selectedPID = 0;
    bool  confirmed   = false;
    HWND  hList       = nullptr;
    HWND  hSearchEdit = nullptr;
    std::vector<ProcessInfo> allProcesses;
    std::vector<ProcessInfo> filteredProcesses;
};
static ProcessDialogData g_procDlgData;

static void PopulateProcessList(HWND hList,
                                const std::vector<ProcessInfo>& procs) {
    ListView_DeleteAllItems(hList);
    LVITEMW item = {};
    item.mask = LVIF_TEXT;

    for (int i = 0; i < (int)procs.size(); i++) {
        wchar_t pidStr[16];
        swprintf(pidStr, 16, L"%u", procs[i].pid);
        item.iItem    = i;
        item.iSubItem = 0;
        item.pszText  = pidStr;
        ListView_InsertItem(hList, &item);
        ListView_SetItemText(hList, i, 1,
                             const_cast<LPWSTR>(procs[i].name.c_str()));
    }
}

static void FilterProcessList() {
    wchar_t searchText[256] = {};
    GetWindowTextW(g_procDlgData.hSearchEdit, searchText, 256);
    std::wstring filter(searchText);

    g_procDlgData.filteredProcesses.clear();
    for (const auto& p : g_procDlgData.allProcesses) {
        if (filter.empty()) {
            g_procDlgData.filteredProcesses.push_back(p);
        } else {
            std::wstring nameLower = p.name;
            std::wstring filterLower = filter;
            std::transform(nameLower.begin(), nameLower.end(),
                           nameLower.begin(), ::towlower);
            std::transform(filterLower.begin(), filterLower.end(),
                           filterLower.begin(), ::towlower);
            if (nameLower.find(filterLower) != std::wstring::npos) {
                g_procDlgData.filteredProcesses.push_back(p);
            }
        }
    }
    PopulateProcessList(g_procDlgData.hList, g_procDlgData.filteredProcesses);
}

static LRESULT CALLBACK ProcessDlgWndProc(HWND hWnd, UINT msg,
                                           WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        HFONT hFont = g_hFont ? g_hFont : (HFONT)GetStockObject(DEFAULT_GUI_FONT);

        HWND hTitle = CreateWindowW(L"STATIC",
            L"  \x0627\x062E\x062A\x0631 \x0639\x0645\x0644\x064A\x0629 \x0644\x0644\x0627\x062A\x0635\x0627\x0644 \x0628\x0647\x0627:",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            0, 0, 500, 28, hWnd, nullptr, g_hInst, nullptr);
        SendMessage(hTitle, WM_SETFONT, (WPARAM)(g_hBoldFont ? g_hBoldFont : hFont), TRUE);

        HWND hSL = CreateWindowW(L"STATIC",
            L"  \x0628\x062D\x062B:",
            WS_CHILD | WS_VISIBLE, 0, 32, 55, 22, hWnd, nullptr,
            g_hInst, nullptr);
        SendMessage(hSL, WM_SETFONT, (WPARAM)hFont, TRUE);

        g_procDlgData.hSearchEdit = CreateWindowExW(WS_EX_CLIENTEDGE,
            L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            58, 30, 420, 24, hWnd, (HMENU)3001, g_hInst, nullptr);
        SendMessage(g_procDlgData.hSearchEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

        g_procDlgData.hList = CreateWindowExW(WS_EX_CLIENTEDGE,
            WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL |
            LVS_SHOWSELALWAYS,
            8, 60, 468, 290, hWnd, (HMENU)3002, g_hInst, nullptr);
        ListView_SetExtendedListViewStyle(g_procDlgData.hList,
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
        SendMessage(g_procDlgData.hList, WM_SETFONT, (WPARAM)hFont, TRUE);

        // Dark theme for dialog ListView
        ApplyDarkToControl(g_procDlgData.hList);
        ListView_SetBkColor(g_procDlgData.hList, CLR_BG_DARK);
        ListView_SetTextBkColor(g_procDlgData.hList, CLR_BG_DARK);
        ListView_SetTextColor(g_procDlgData.hList, CLR_TEXT);

        LVCOLUMNW col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.pszText = const_cast<LPWSTR>(L"PID");
        col.cx = 70;
        ListView_InsertColumn(g_procDlgData.hList, 0, &col);
        col.pszText = const_cast<LPWSTR>(L"\x0627\x0644\x0627\x0633\x0645");
        col.cx = 380;
        ListView_InsertColumn(g_procDlgData.hList, 1, &col);

        HWND hRefresh = CreateWindowW(L"BUTTON",
            L"\x062A\x062D\x062F\x064A\x062B",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 8, 358, 90, 30,
            hWnd, (HMENU)3003, g_hInst, nullptr);
        SendMessage(hRefresh, WM_SETFONT, (WPARAM)hFont, TRUE);

        HWND hSelect = CreateWindowW(L"BUTTON",
            L"\x0627\x062E\x062A\x064A\x0627\x0631",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 280, 358, 92, 30,
            hWnd, (HMENU)IDOK, g_hInst, nullptr);
        SendMessage(hSelect, WM_SETFONT, (WPARAM)hFont, TRUE);

        HWND hCancel = CreateWindowW(L"BUTTON",
            L"\x0625\x0644\x063A\x0627\x0621",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 380, 358, 92, 30,
            hWnd, (HMENU)IDCANCEL, g_hInst, nullptr);
        SendMessage(hCancel, WM_SETFONT, (WPARAM)hFont, TRUE);

        g_procDlgData.allProcesses = ProcessManager::GetRunningProcesses();
        g_procDlgData.filteredProcesses = g_procDlgData.allProcesses;
        PopulateProcessList(g_procDlgData.hList, g_procDlgData.filteredProcesses);

        RECT rc, rcP;
        GetWindowRect(hWnd, &rc);
        GetWindowRect(g_hMainWnd, &rcP);
        int cx = rcP.left + ((rcP.right - rcP.left) - (rc.right - rc.left)) / 2;
        int cy = rcP.top + ((rcP.bottom - rcP.top) - (rc.bottom - rc.top)) / 2;
        SetWindowPos(hWnd, nullptr, cx, cy, 0, 0, SWP_NOSIZE | SWP_NOZORDER);

        SetFocus(g_procDlgData.hSearchEdit);
        break;
    }
    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT lpDIS = (LPDRAWITEMSTRUCT)lParam;
        if (lpDIS->CtlType == ODT_BUTTON) {
            DrawDarkButton(lpDIS, LOWORD(wParam) == IDOK);
            return TRUE;
        }
        break;
    }
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT: {
        HDC hdcCtrl = (HDC)wParam;
        SetTextColor(hdcCtrl, CLR_TEXT);
        SetBkColor(hdcCtrl, msg == WM_CTLCOLOREDIT ? CLR_BG_INPUT : CLR_BG_PANEL);
        return (LRESULT)(msg == WM_CTLCOLOREDIT ? g_hInputBgBrush : g_hPanelBgBrush);
    }
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case 3001:
            if (HIWORD(wParam) == EN_CHANGE) FilterProcessList();
            break;
        case IDOK: {
            int sel = ListView_GetNextItem(g_procDlgData.hList, -1, LVNI_SELECTED);
            if (sel >= 0 && sel < (int)g_procDlgData.filteredProcesses.size()) {
                g_procDlgData.selectedPID = g_procDlgData.filteredProcesses[sel].pid;
                g_procDlgData.confirmed = true;
                DestroyWindow(hWnd);
            } else {
                MessageBoxW(hWnd,
                    L"\x0627\x062E\x062A\x0631 \x0639\x0645\x0644\x064A\x0629 \x0623\x0648\x0644\x0627\x064B",
                    L"Cheat Engine Pro", MB_ICONINFORMATION);
            }
            break;
        }
        case IDCANCEL:
            g_procDlgData.confirmed = false;
            DestroyWindow(hWnd);
            break;
        case 3003:
            g_procDlgData.allProcesses = ProcessManager::GetRunningProcesses();
            FilterProcessList();
            break;
        }
        break;
    case WM_NOTIFY: {
        LPNMHDR nm = reinterpret_cast<LPNMHDR>(lParam);
        if (nm->hwndFrom == g_procDlgData.hList && nm->code == NM_DBLCLK)
            SendMessage(hWnd, WM_COMMAND, IDOK, 0);
        break;
    }
    case WM_CLOSE:
        g_procDlgData.confirmed = false;
        DestroyWindow(hWnd);
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

static bool ShowProcessDialog() {
    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc); wc.lpfnWndProc = ProcessDlgWndProc;
        wc.hInstance = g_hInst; wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = CreateSolidBrush(CLR_BG_PANEL);
        wc.lpszClassName = L"CE_ProcessDlg";
        RegisterClassExW(&wc);
        registered = true;
    }
    g_procDlgData.selectedPID = 0;
    g_procDlgData.confirmed = false;

    HWND hDlg = CreateWindowExW(WS_EX_DLGMODALFRAME,
        L"CE_ProcessDlg",
        L"\x0627\x062E\x062A\x064A\x0627\x0631 \x0627\x0644\x0639\x0645\x0644\x064A\x0629",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, 500, 430,
        g_hMainWnd, nullptr, g_hInst, nullptr);

    ShowWindow(hDlg, SW_SHOW); UpdateWindow(hDlg);
    EnableWindow(g_hMainWnd, FALSE);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        if (!IsWindow(hDlg)) break;
        TranslateMessage(&msg); DispatchMessageW(&msg);
    }
    EnableWindow(g_hMainWnd, TRUE);
    SetForegroundWindow(g_hMainWnd);
    return g_procDlgData.confirmed;
}

struct InputDialogData {
    std::wstring title, prompt, value;
    bool confirmed = false;
    HWND hEdit = nullptr;
};
static InputDialogData g_inputDlgData;

static LRESULT CALLBACK InputDlgWndProc(HWND hWnd, UINT msg,
                                         WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        HFONT hFont = g_hFont ? g_hFont : (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        HWND hLbl = CreateWindowW(L"STATIC", g_inputDlgData.prompt.c_str(),
            WS_CHILD | WS_VISIBLE, 12, 12, 300, 20, hWnd, nullptr, g_hInst, nullptr);
        SendMessage(hLbl, WM_SETFONT, (WPARAM)hFont, TRUE);

        g_inputDlgData.hEdit = CreateWindowExW(WS_EX_CLIENTEDGE,
            L"EDIT", g_inputDlgData.value.c_str(),
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            12, 36, 296, 24, hWnd, nullptr, g_hInst, nullptr);
        SendMessage(g_inputDlgData.hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessage(g_inputDlgData.hEdit, EM_SETSEL, 0, -1);

        HWND hOK = CreateWindowW(L"BUTTON", L"OK",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            140, 72, 80, 28, hWnd, (HMENU)IDOK, g_hInst, nullptr);
        SendMessage(hOK, WM_SETFONT, (WPARAM)hFont, TRUE);

        HWND hCan = CreateWindowW(L"BUTTON",
            L"\x0625\x0644\x063A\x0627\x0621",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            228, 72, 80, 28, hWnd, (HMENU)IDCANCEL, g_hInst, nullptr);
        SendMessage(hCan, WM_SETFONT, (WPARAM)hFont, TRUE);

        RECT rc, rcP;
        GetWindowRect(hWnd, &rc); GetWindowRect(g_hMainWnd, &rcP);
        SetWindowPos(hWnd, nullptr,
            rcP.left + ((rcP.right - rcP.left) - (rc.right - rc.left)) / 2,
            rcP.top + ((rcP.bottom - rcP.top) - (rc.bottom - rc.top)) / 2,
            0, 0, SWP_NOSIZE | SWP_NOZORDER);
        SetFocus(g_inputDlgData.hEdit);
        break;
    }
    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT lpDIS = (LPDRAWITEMSTRUCT)lParam;
        if (lpDIS->CtlType == ODT_BUTTON) {
            DrawDarkButton(lpDIS, LOWORD(wParam) == IDOK);
            return TRUE;
        }
        break;
    }
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT: {
        HDC hdcCtrl = (HDC)wParam;
        SetTextColor(hdcCtrl, CLR_TEXT);
        SetBkColor(hdcCtrl, msg == WM_CTLCOLOREDIT ? CLR_BG_INPUT : CLR_BG_PANEL);
        return (LRESULT)(msg == WM_CTLCOLOREDIT ? g_hInputBgBrush : g_hPanelBgBrush);
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK) {
            wchar_t buf[1024];
            GetWindowTextW(g_inputDlgData.hEdit, buf, 1024);
            g_inputDlgData.value = buf;
            g_inputDlgData.confirmed = true;
            DestroyWindow(hWnd);
        } else if (LOWORD(wParam) == IDCANCEL) {
            g_inputDlgData.confirmed = false;
            DestroyWindow(hWnd);
        }
        break;
    case WM_CLOSE:
        g_inputDlgData.confirmed = false; DestroyWindow(hWnd); break;
    case WM_DESTROY:
        PostQuitMessage(0); break;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

static bool ShowInputDialog(const wchar_t* title, const wchar_t* prompt,
                            std::wstring& value) {
    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc); wc.lpfnWndProc = InputDlgWndProc;
        wc.hInstance = g_hInst; wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = CreateSolidBrush(CLR_BG_PANEL);
        wc.lpszClassName = L"CE_InputDlg";
        RegisterClassExW(&wc);
        registered = true;
    }
    g_inputDlgData.title = title; g_inputDlgData.prompt = prompt;
    g_inputDlgData.value = value; g_inputDlgData.confirmed = false;

    HWND hDlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"CE_InputDlg", title,
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, 336, 145,
        g_hMainWnd, nullptr, g_hInst, nullptr);
    ShowWindow(hDlg, SW_SHOW); UpdateWindow(hDlg);
    EnableWindow(g_hMainWnd, FALSE);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        if (!IsWindow(hDlg)) break;
        TranslateMessage(&msg); DispatchMessageW(&msg);
    }
    EnableWindow(g_hMainWnd, TRUE);
    SetForegroundWindow(g_hMainWnd);
    if (g_inputDlgData.confirmed) value = g_inputDlgData.value;
    return g_inputDlgData.confirmed;
}

struct AddAddrDlgData {
    std::wstring address, description;
    ValueType type = ValueType::Int32;
    bool confirmed = false;
    HWND hAddr = nullptr, hDesc = nullptr, hType = nullptr;
};
static AddAddrDlgData g_addAddrData;

static LRESULT CALLBACK AddAddrDlgWndProc(HWND hWnd, UINT msg,
                                           WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        HFONT hFont = g_hFont ? g_hFont : (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        int y = 12;
        auto MkLabel = [&](const wchar_t* text, int yy) {
            HWND h = CreateWindowW(L"STATIC", text, WS_CHILD | WS_VISIBLE,
                12, yy, 110, 20, hWnd, nullptr, g_hInst, nullptr);
            SendMessage(h, WM_SETFONT, (WPARAM)hFont, TRUE);
        };

        MkLabel(L"\x0627\x0644\x0639\x0646\x0648\x0627\x0646 (hex):", y);
        g_addAddrData.hAddr = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT",
            g_addAddrData.address.c_str(),
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            130, y, 185, 24, hWnd, nullptr, g_hInst, nullptr);
        SendMessage(g_addAddrData.hAddr, WM_SETFONT, (WPARAM)hFont, TRUE);
        y += 32;

        MkLabel(L"\x0627\x0644\x0648\x0635\x0641:", y);
        g_addAddrData.hDesc = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT",
            g_addAddrData.description.c_str(),
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            130, y, 185, 24, hWnd, nullptr, g_hInst, nullptr);
        SendMessage(g_addAddrData.hDesc, WM_SETFONT, (WPARAM)hFont, TRUE);
        y += 32;

        MkLabel(L"\x0646\x0648\x0639 \x0627\x0644\x0642\x064A\x0645\x0629:", y);
        g_addAddrData.hType = CreateWindowW(L"COMBOBOX", L"",
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
            130, y, 185, 250, hWnd, nullptr, g_hInst, nullptr);
        SendMessage(g_addAddrData.hType, WM_SETFONT, (WPARAM)hFont, TRUE);
        for (int i = 0; i < VALUE_TYPE_COUNT; i++)
            SendMessageW(g_addAddrData.hType, CB_ADDSTRING, 0, (LPARAM)VALUE_TYPE_NAMES[i]);
        SendMessage(g_addAddrData.hType, CB_SETCURSEL, (int)g_addAddrData.type, 0);
        y += 38;

        HWND hOK = CreateWindowW(L"BUTTON", L"OK",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            148, y, 80, 28, hWnd, (HMENU)IDOK, g_hInst, nullptr);
        SendMessage(hOK, WM_SETFONT, (WPARAM)hFont, TRUE);
        HWND hCan = CreateWindowW(L"BUTTON",
            L"\x0625\x0644\x063A\x0627\x0621",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            236, y, 80, 28, hWnd, (HMENU)IDCANCEL, g_hInst, nullptr);
        SendMessage(hCan, WM_SETFONT, (WPARAM)hFont, TRUE);

        RECT rc, rcP;
        GetWindowRect(hWnd, &rc); GetWindowRect(g_hMainWnd, &rcP);
        SetWindowPos(hWnd, nullptr,
            rcP.left + ((rcP.right - rcP.left) - (rc.right - rc.left)) / 2,
            rcP.top + ((rcP.bottom - rcP.top) - (rc.bottom - rc.top)) / 2,
            0, 0, SWP_NOSIZE | SWP_NOZORDER);
        SetFocus(g_addAddrData.hAddr);
        break;
    }
    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT lpDIS = (LPDRAWITEMSTRUCT)lParam;
        if (lpDIS->CtlType == ODT_BUTTON) {
            DrawDarkButton(lpDIS, LOWORD(wParam) == IDOK);
            return TRUE;
        }
        break;
    }
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT: {
        HDC hdcCtrl = (HDC)wParam;
        SetTextColor(hdcCtrl, CLR_TEXT);
        SetBkColor(hdcCtrl, msg == WM_CTLCOLOREDIT ? CLR_BG_INPUT : CLR_BG_PANEL);
        return (LRESULT)(msg == WM_CTLCOLOREDIT ? g_hInputBgBrush : g_hPanelBgBrush);
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK) {
            wchar_t buf[512];
            GetWindowTextW(g_addAddrData.hAddr, buf, 512); g_addAddrData.address = buf;
            GetWindowTextW(g_addAddrData.hDesc, buf, 512); g_addAddrData.description = buf;
            int sel = (int)SendMessage(g_addAddrData.hType, CB_GETCURSEL, 0, 0);
            g_addAddrData.type = (sel >= 0) ? (ValueType)sel : ValueType::Int32;
            g_addAddrData.confirmed = true;
            DestroyWindow(hWnd);
        } else if (LOWORD(wParam) == IDCANCEL) {
            g_addAddrData.confirmed = false; DestroyWindow(hWnd);
        }
        break;
    case WM_CLOSE: g_addAddrData.confirmed = false; DestroyWindow(hWnd); break;
    case WM_DESTROY: PostQuitMessage(0); break;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

static bool ShowAddAddressDialog(uintptr_t& address, std::wstring& description,
                                 ValueType& type) {
    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc); wc.lpfnWndProc = AddAddrDlgWndProc;
        wc.hInstance = g_hInst; wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = CreateSolidBrush(CLR_BG_PANEL);
        wc.lpszClassName = L"CE_AddAddrDlg";
        RegisterClassExW(&wc);
        registered = true;
    }
    wchar_t addrBuf[32];
    swprintf(addrBuf, 32, L"%llX", (unsigned long long)address);
    g_addAddrData.address = addrBuf;
    g_addAddrData.description = description;
    g_addAddrData.type = type;
    g_addAddrData.confirmed = false;

    HWND hDlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"CE_AddAddrDlg",
        L"\x0625\x0636\x0627\x0641\x0629 \x0639\x0646\x0648\x0627\x0646",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, 345, 210,
        g_hMainWnd, nullptr, g_hInst, nullptr);
    ShowWindow(hDlg, SW_SHOW); UpdateWindow(hDlg);
    EnableWindow(g_hMainWnd, FALSE);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        if (!IsWindow(hDlg)) break;
        TranslateMessage(&msg); DispatchMessageW(&msg);
    }
    EnableWindow(g_hMainWnd, TRUE);
    SetForegroundWindow(g_hMainWnd);

    if (g_addAddrData.confirmed) {
        address = wcstoull(g_addAddrData.address.c_str(), nullptr, 16);
        description = g_addAddrData.description;
        type = g_addAddrData.type;
    }
    return g_addAddrData.confirmed;
}

static void CreateMainControls(HWND hWnd) {
    // Create dark brushes
    g_hDarkBgBrush  = CreateSolidBrush(CLR_BG_DARK);
    g_hPanelBgBrush = CreateSolidBrush(CLR_BG_PANEL);
    g_hCardBgBrush  = CreateSolidBrush(CLR_BG_CARD);
    g_hInputBgBrush = CreateSolidBrush(CLR_BG_INPUT);
    g_hHeaderBrush  = CreateSolidBrush(CLR_HEADER);

    // Fonts
    LOGFONTW lf = {};
    lf.lfHeight  = -13;
    lf.lfWeight  = FW_NORMAL;
    lf.lfCharSet = DEFAULT_CHARSET;
    wcscpy_s(lf.lfFaceName, L"Segoe UI");
    g_hFont = CreateFontIndirectW(&lf);

    lf.lfWeight = FW_BOLD;
    g_hBoldFont = CreateFontIndirectW(&lf);

    lf.lfWeight = FW_NORMAL;
    wcscpy_s(lf.lfFaceName, L"Consolas");
    lf.lfHeight = -12;
    g_hMonoFont = CreateFontIndirectW(&lf);

    lf.lfHeight = -18;
    lf.lfWeight = FW_BOLD;
    wcscpy_s(lf.lfFaceName, L"Segoe UI");
    g_hTitleFont = CreateFontIndirectW(&lf);

    auto F = [](HWND h) { SendMessage(h, WM_SETFONT, (WPARAM)g_hFont, TRUE); };
    auto B = [](HWND h) { SendMessage(h, WM_SETFONT, (WPARAM)g_hBoldFont, TRUE); };

  
    int topY = HEADER_HEIGHT + 4;
    g_hProcessBtn = CreateWindowW(L"BUTTON",
        L"  \x0627\x062E\x062A\x064A\x0627\x0631 \x0627\x0644\x0639\x0645\x0644\x064A\x0629  ",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 10, topY, 160, 30,
        hWnd, (HMENU)IDC_PROCESS_BTN, g_hInst, nullptr);
    B(g_hProcessBtn);

    g_hProcessLabel = CreateWindowW(L"STATIC",
        L"  \x0644\x0645 \x064A\x062A\x0645 \x0627\x062E\x062A\x064A\x0627\x0631 \x0639\x0645\x0644\x064A\x0629",
        WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE,
        178, topY, 800, 30, hWnd, (HMENU)IDC_PROCESS_LABEL, g_hInst, nullptr);
    F(g_hProcessLabel);

    int sy = topY + 36;
    g_hScannerGroup = CreateWindowW(L"BUTTON",
        L" \x0645\x0627\x0633\x062D \x0627\x0644\x0630\x0627\x0643\x0631\x0629 ",
        WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
        8, sy, 400, 160, hWnd, (HMENU)IDC_SCANNER_GROUP, g_hInst, nullptr);
    B(g_hScannerGroup);

    auto MkStatic = [&](const wchar_t* t, int x, int y, int w, int h) -> HWND {
        HWND h_ = CreateWindowW(L"STATIC", t, WS_CHILD | WS_VISIBLE,
            x, y, w, h, hWnd, nullptr, g_hInst, nullptr);
        F(h_); return h_;
    };

    MkStatic(L"\x0646\x0648\x0639 \x0627\x0644\x0642\x064A\x0645\x0629:", 20, sy+22, 80, 20);

    g_hValueTypeCombo = CreateWindowW(L"COMBOBOX", L"",
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        105, sy+19, 130, 250, hWnd, (HMENU)IDC_VALUE_TYPE_COMBO, g_hInst, nullptr);
    F(g_hValueTypeCombo);
    for (int i = 0; i < VALUE_TYPE_COUNT; i++)
        SendMessageW(g_hValueTypeCombo, CB_ADDSTRING, 0, (LPARAM)VALUE_TYPE_NAMES[i]);
    SendMessage(g_hValueTypeCombo, CB_SETCURSEL, 2, 0);

    MkStatic(L"\x0646\x0648\x0639 \x0627\x0644\x0641\x062D\x0635:", 244, sy+22, 75, 20);

    g_hScanTypeCombo = CreateWindowW(L"COMBOBOX", L"",
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        322, sy+19, 80, 300, hWnd, (HMENU)IDC_SCAN_TYPE_COMBO, g_hInst, nullptr);
    F(g_hScanTypeCombo);
    for (int i = 0; i < SCAN_TYPE_COUNT; i++)
        SendMessageW(g_hScanTypeCombo, CB_ADDSTRING, 0, (LPARAM)SCAN_TYPE_NAMES[i]);
    SendMessage(g_hScanTypeCombo, CB_SETCURSEL, 0, 0);

    MkStatic(L"\x0627\x0644\x0642\x064A\x0645\x0629:", 20, sy+52, 50, 20);

    g_hValueEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        75, sy+49, 160, 24, hWnd, (HMENU)IDC_VALUE_EDIT, g_hInst, nullptr);
    F(g_hValueEdit);

    g_hValue2Label = CreateWindowW(L"STATIC", L"\x0625\x0644\x0649:",
        WS_CHILD, 244, sy+52, 30, 20, hWnd, (HMENU)IDC_VALUE2_LABEL, g_hInst, nullptr);
    F(g_hValue2Label);

    g_hValue2Edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | ES_AUTOHSCROLL,
        278, sy+49, 130, 24, hWnd, (HMENU)IDC_VALUE2_EDIT, g_hInst, nullptr);
    F(g_hValue2Edit);

    // Scan buttons
    int by = sy + 84;
    g_hFirstScanBtn = CreateWindowW(L"BUTTON",
        L"\x0641\x062D\x0635 \x0623\x0648\x0644",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 20, by, 90, 28,
        hWnd, (HMENU)IDC_FIRST_SCAN_BTN, g_hInst, nullptr); F(g_hFirstScanBtn);

    g_hNextScanBtn = CreateWindowW(L"BUTTON",
        L"\x0641\x062D\x0635 \x062A\x0627\x0644\x064A",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 115, by, 90, 28,
        hWnd, (HMENU)IDC_NEXT_SCAN_BTN, g_hInst, nullptr); F(g_hNextScanBtn);
    EnableWindow(g_hNextScanBtn, FALSE);

    g_hUndoScanBtn = CreateWindowW(L"BUTTON",
        L"\x062A\x0631\x0627\x062C\x0639",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 210, by, 70, 28,
        hWnd, (HMENU)IDC_UNDO_SCAN_BTN, g_hInst, nullptr); F(g_hUndoScanBtn);
    EnableWindow(g_hUndoScanBtn, FALSE);

    g_hResetBtn = CreateWindowW(L"BUTTON",
        L"\x0625\x0639\x0627\x062F\x0629",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 285, by, 70, 28,
        hWnd, (HMENU)IDC_RESET_BTN, g_hInst, nullptr); F(g_hResetBtn);

    g_hFoundCount = CreateWindowW(L"STATIC",
        L"\x0627\x0644\x0646\x062A\x0627\x0626\x062C: 0",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        20, by+34, 370, 20, hWnd, (HMENU)IDC_FOUND_COUNT, g_hInst, nullptr);
    F(g_hFoundCount);

    // ---- Activity Log below scanner ----
    int logY = sy + 165;
    g_hLogGroup = CreateWindowW(L"BUTTON",
        L" \x0633\x062C\x0644 \x0627\x0644\x0646\x0634\x0627\x0637 ",
        WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
        8, logY, 400, 100, hWnd, (HMENU)IDC_LOG_GROUP, g_hInst, nullptr);
    B(g_hLogGroup);

    g_hLogList = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOINTEGRALHEIGHT | LBS_NOSEL,
        12, logY + 18, 392, 76, hWnd, (HMENU)IDC_LOG_LIST, g_hInst, nullptr);
    SendMessage(g_hLogList, WM_SETFONT, (WPARAM)g_hMonoFont, TRUE);

    // ---- TAB CONTROL (right side) ----
    int tabX = 420;
    g_hTabCtrl = CreateWindowW(WC_TABCONTROLW, L"",
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | TCS_OWNERDRAWFIXED,
        tabX, sy, 500, 220, hWnd, (HMENU)IDC_TAB_CTRL, g_hInst, nullptr);
    F(g_hTabCtrl);

    TCITEMW tie = {};
    tie.mask = TCIF_TEXT;
    tie.pszText = const_cast<LPWSTR>(L"\x0627\x0644\x0646\x062A\x0627\x0626\x062C");
    TabCtrl_InsertItem(g_hTabCtrl, 0, &tie);
    tie.pszText = const_cast<LPWSTR>(L"\x062A\x062D\x0644\x064A\x0644 \x0627\x0644\x0639\x0645\x0644\x064A\x0629");
    TabCtrl_InsertItem(g_hTabCtrl, 1, &tie);
    tie.pszText = const_cast<LPWSTR>(L"\x0627\x0644\x062F\x0644\x064A\x0644 \x0627\x0644\x0639\x0631\x0628\x064A");
    TabCtrl_InsertItem(g_hTabCtrl, 2, &tie);

    // == Tab 0: Found Addresses ==
    int tx = tabX + 4, ty = sy + 28;
    g_hFoundList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_OWNERDATA |
        LVS_SINGLESEL | LVS_SHOWSELALWAYS,
        tx, ty, 490, 155, hWnd, (HMENU)IDC_FOUND_LIST, g_hInst, nullptr);
    ListView_SetExtendedListViewStyle(g_hFoundList,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
    F(g_hFoundList);

    LVCOLUMNW col = {};
    col.mask = LVCF_TEXT | LVCF_WIDTH;
    col.pszText = const_cast<LPWSTR>(L"\x0627\x0644\x0639\x0646\x0648\x0627\x0646");
    col.cx = 140;
    ListView_InsertColumn(g_hFoundList, 0, &col);
    col.pszText = const_cast<LPWSTR>(L"\x0627\x0644\x0642\x064A\x0645\x0629"); col.cx = 100;
    ListView_InsertColumn(g_hFoundList, 1, &col);
    col.pszText = const_cast<LPWSTR>(L"\x0627\x0644\x0633\x0627\x0628\x0642\x0629"); col.cx = 100;
    ListView_InsertColumn(g_hFoundList, 2, &col);

    g_hWriteValueBtn = CreateWindowW(L"BUTTON",
        L"\x0643\x062A\x0627\x0628\x0629 \x0642\x064A\x0645\x0629",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, tx, ty+160, 120, 26,
        hWnd, (HMENU)IDC_WRITE_VALUE_BTN, g_hInst, nullptr); F(g_hWriteValueBtn);

    g_hAddToTableBtn = CreateWindowW(L"BUTTON",
        L"\x0625\x0636\x0627\x0641\x0629 \x0644\x0644\x062C\x062F\x0648\x0644",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, tx+130, ty+160, 120, 26,
        hWnd, (HMENU)IDC_ADD_TO_TABLE_BTN, g_hInst, nullptr); F(g_hAddToTableBtn);

    // == Tab 1: Process Analysis ==
    g_hAnalysisCombo = CreateWindowW(L"COMBOBOX", L"",
        WS_CHILD | CBS_DROPDOWNLIST,
        tx, ty, 150, 200, hWnd, (HMENU)IDC_ANALYSIS_COMBO, g_hInst, nullptr);
    F(g_hAnalysisCombo);
    SendMessageW(g_hAnalysisCombo, CB_ADDSTRING, 0,
        (LPARAM)L"\x0628\x062D\x062B \x0646\x0635\x064A (String)");
    SendMessageW(g_hAnalysisCombo, CB_ADDSTRING, 0,
        (LPARAM)L"\x0627\x0644\x0645\x0648\x062F\x064A\x0648\x0644\x0627\x062A (DLLs)");
    SendMessageW(g_hAnalysisCombo, CB_ADDSTRING, 0,
        (LPARAM)L"\x0645\x0646\x0627\x0637\x0642 \x0627\x0644\x0630\x0627\x0643\x0631\x0629");
    SendMessageW(g_hAnalysisCombo, CB_ADDSTRING, 0,
        (LPARAM)L"\x0627\x0644\x062E\x064A\x0648\x0637 (Threads)");
    SendMessage(g_hAnalysisCombo, CB_SETCURSEL, 0, 0);

    g_hAnalysisSearchEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | ES_AUTOHSCROLL,
        tx+155, ty, 240, 24, hWnd, (HMENU)IDC_ANALYSIS_SEARCH_EDIT, g_hInst, nullptr);
    F(g_hAnalysisSearchEdit);

    g_hAnalysisSearchBtn = CreateWindowW(L"BUTTON",
        L"\x0628\x062D\x062B",
        WS_CHILD | BS_OWNERDRAW, tx+400, ty, 60, 24,
        hWnd, (HMENU)IDC_ANALYSIS_SEARCH_BTN, g_hInst, nullptr); F(g_hAnalysisSearchBtn);

    g_hAnalysisList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        WS_CHILD | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
        tx, ty+30, 462, 80, hWnd, (HMENU)IDC_ANALYSIS_LIST, g_hInst, nullptr);
    ListView_SetExtendedListViewStyle(g_hAnalysisList,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
    F(g_hAnalysisList);

    g_hAnalysisDetailLabel = CreateWindowW(L"STATIC",
        L"\x0627\x0644\x062A\x0641\x0627\x0635\x064A\x0644:",
        WS_CHILD, tx, ty+114, 80, 18,
        hWnd, nullptr, g_hInst, nullptr); B(g_hAnalysisDetailLabel);

    g_hAnalysisNearbyBtn = CreateWindowW(L"BUTTON",
        L"\x0627\x0644\x0642\x064A\x0645 \x0627\x0644\x0645\x062C\x0627\x0648\x0631\x0629",
        WS_CHILD | BS_OWNERDRAW, tx+350, ty+112, 110, 22,
        hWnd, (HMENU)IDC_ANALYSIS_NEARBY_BTN, g_hInst, nullptr); F(g_hAnalysisNearbyBtn);

    g_hAnalysisDetail = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        tx, ty+135, 462, 50, hWnd, (HMENU)IDC_ANALYSIS_DETAIL, g_hInst, nullptr);
    SendMessage(g_hAnalysisDetail, WM_SETFONT, (WPARAM)g_hMonoFont, TRUE);

    // == Tab 2: Arabic Guide ==
    g_hGuideList = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
        WS_CHILD | WS_VSCROLL | LBS_NOTIFY,
        tx, ty, 462, 80, hWnd, (HMENU)IDC_GUIDE_LIST, g_hInst, nullptr);
    F(g_hGuideList);

    g_hGuideText = CreateWindowExW(WS_EX_CLIENTEDGE | WS_EX_LAYOUTRTL, L"EDIT", L"",
        WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        tx, ty+84, 462, 102, hWnd, (HMENU)IDC_GUIDE_TEXT, g_hInst, nullptr);
    F(g_hGuideText);

    // Populate guide
    g_guideSections = GetArabicGuide();
    for (const auto& sec : g_guideSections)
        SendMessageW(g_hGuideList, LB_ADDSTRING, 0, (LPARAM)sec.title.c_str());

    // ---- Address Table ----
    int tableY = 320;
    g_hTableGroup = CreateWindowW(L"BUTTON",
        L" \x062C\x062F\x0648\x0644 \x0627\x0644\x0639\x0646\x0627\x0648\x064A\x0646 (\x0641\x0639\x0644 \x0644\x0644\x062A\x062C\x0645\x064A\x062F) ",
        WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
        8, tableY, 900, 30, hWnd, (HMENU)IDC_TABLE_GROUP, g_hInst, nullptr);
    B(g_hTableGroup);

    g_hAddressTable = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
        10, tableY+20, 890, 150, hWnd, (HMENU)IDC_ADDRESS_TABLE, g_hInst, nullptr);
    ListView_SetExtendedListViewStyle(g_hAddressTable,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_CHECKBOXES | LVS_EX_DOUBLEBUFFER);
    F(g_hAddressTable);

    col.pszText = const_cast<LPWSTR>(L"\x062A\x062C\x0645\x064A\x062F"); col.cx = 55;
    ListView_InsertColumn(g_hAddressTable, 0, &col);
    col.pszText = const_cast<LPWSTR>(L"\x0627\x0644\x0648\x0635\x0641"); col.cx = 200;
    ListView_InsertColumn(g_hAddressTable, 1, &col);
    col.pszText = const_cast<LPWSTR>(L"\x0627\x0644\x0639\x0646\x0648\x0627\x0646"); col.cx = 150;
    ListView_InsertColumn(g_hAddressTable, 2, &col);
    col.pszText = const_cast<LPWSTR>(L"\x0627\x0644\x0646\x0648\x0639"); col.cx = 100;
    ListView_InsertColumn(g_hAddressTable, 3, &col);
    col.pszText = const_cast<LPWSTR>(L"\x0627\x0644\x0642\x064A\x0645\x0629"); col.cx = 130;
    ListView_InsertColumn(g_hAddressTable, 4, &col);

    int tby = tableY + 176;
    g_hAddAddrBtn = CreateWindowW(L"BUTTON",
        L"\x0625\x0636\x0627\x0641\x0629 \x0639\x0646\x0648\x0627\x0646",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 10, tby, 110, 28,
        hWnd, (HMENU)IDC_ADD_ADDR_BTN, g_hInst, nullptr); F(g_hAddAddrBtn);

    g_hRemoveAddrBtn = CreateWindowW(L"BUTTON",
        L"\x062D\x0630\x0641",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 126, tby, 80, 28,
        hWnd, (HMENU)IDC_REMOVE_ADDR_BTN, g_hInst, nullptr); F(g_hRemoveAddrBtn);

    g_hEditValueBtn = CreateWindowW(L"BUTTON",
        L"\x062A\x0639\x062F\x064A\x0644 \x0627\x0644\x0642\x064A\x0645\x0629",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 212, tby, 110, 28,
        hWnd, (HMENU)IDC_EDIT_VALUE_BTN, g_hInst, nullptr); F(g_hEditValueBtn);

    // ---- Status bar ----
    g_hStatusBar = CreateWindowW(STATUSCLASSNAMEW, L"",
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0, hWnd, (HMENU)IDC_STATUSBAR, g_hInst, nullptr);
    F(g_hStatusBar);

    auto DarkLV = [](HWND h) {
        ApplyDarkToControl(h);
        ListView_SetBkColor(h, CLR_BG_DARK);
        ListView_SetTextBkColor(h, CLR_BG_DARK);
        ListView_SetTextColor(h, CLR_TEXT);
    };
    DarkLV(g_hFoundList);
    DarkLV(g_hAnalysisList);
    DarkLV(g_hAddressTable);

    // Tab control
    ApplyDarkToControl(g_hTabCtrl);

    // Status bar
    ApplyDarkToControl(g_hStatusBar);
    SendMessage(g_hStatusBar, SB_SETBKCOLOR, 0, (LPARAM)CLR_BG_PANEL);

    // Show Tab 0, hide others
    SwitchTab(0);
    UpdateScanUI();
    UpdateStatusBar(L" \x062C\x0627\x0647\x0632 - \x0627\x062E\x062A\x0631 \x0639\x0645\x0644\x064A\x0629 \x0644\x0644\x0628\x062F\x0621");
    AddLog(L"\x062A\x0645 \x062A\x0634\x063A\x064A\x0644 Cheat Engine Pro v3.0 - Dark Edition");

    SetTimer(hWnd, IDC_TIMER_UPDATE, 250, nullptr);
}

static void SwitchTab(int tabIndex) {
    g_currentTab = tabIndex;

    BOOL t0 = (tabIndex == 0);
    ShowWindow(g_hFoundList, t0 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hWriteValueBtn, t0 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hAddToTableBtn, t0 ? SW_SHOW : SW_HIDE);

    BOOL t1 = (tabIndex == 1);
    ShowWindow(g_hAnalysisCombo, t1 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hAnalysisSearchEdit, t1 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hAnalysisSearchBtn, t1 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hAnalysisList, t1 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hAnalysisDetail, t1 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hAnalysisDetailLabel, t1 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hAnalysisNearbyBtn, t1 ? SW_SHOW : SW_HIDE);

    BOOL t2 = (tabIndex == 2);
    ShowWindow(g_hGuideList, t2 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hGuideText, t2 ? SW_SHOW : SW_HIDE);
}

static void OnResize(HWND hWnd) {
    RECT rc;
    GetClientRect(hWnd, &rc);
    int W = rc.right;
    int H = rc.bottom;

    SendMessage(g_hStatusBar, WM_SIZE, 0, 0);
    RECT sbRc;
    GetWindowRect(g_hStatusBar, &sbRc);
    int sbH = sbRc.bottom - sbRc.top;
    int usableH = H - sbH;

    int topY = HEADER_HEIGHT + 4;
    MoveWindow(g_hProcessLabel, 178, topY, W - 190, 30, TRUE);

    int scanW = (std::min)(420, W / 2 - 20);
    int sy = topY + 36;
    MoveWindow(g_hScannerGroup, 8, sy, scanW, 160, TRUE);

    int logY = sy + 165;
    int logH = 100;
    MoveWindow(g_hLogGroup, 8, logY, scanW, logH, TRUE);
    MoveWindow(g_hLogList, 12, logY+18, scanW-8, logH-24, TRUE);

    int tabX = scanW + 20;
    int tabW = W - tabX - 8;
    if (tabW < 300) tabW = 300;
    int tabH = logY + logH - sy;
    MoveWindow(g_hTabCtrl, tabX, sy, tabW, tabH, TRUE);

    int tx = tabX + 4;
    int ty = sy + 28;
    int tw = tabW - 10;
    int tch = tabH - 60;

    int listH = tch - 32;
    if (listH < 60) listH = 60;
    MoveWindow(g_hFoundList, tx, ty, tw, listH, TRUE);
    MoveWindow(g_hWriteValueBtn, tx, ty + listH + 4, 120, 26, TRUE);
    MoveWindow(g_hAddToTableBtn, tx + 130, ty + listH + 4, 120, 26, TRUE);

    MoveWindow(g_hAnalysisCombo, tx, ty, 150, 200, TRUE);
    MoveWindow(g_hAnalysisSearchEdit, tx+155, ty, tw-225, 24, TRUE);
    MoveWindow(g_hAnalysisSearchBtn, tx + tw - 65, ty, 60, 24, TRUE);

    int anaListH = (tch - 60) / 2;
    if (anaListH < 40) anaListH = 40;
    MoveWindow(g_hAnalysisList, tx, ty+30, tw, anaListH, TRUE);

    int detailY = ty + 30 + anaListH + 4;
    int detailH = tch - anaListH - 60;
    if (detailH < 30) detailH = 30;
    MoveWindow(g_hAnalysisDetailLabel, tx, detailY, 80, 18, TRUE);
    MoveWindow(g_hAnalysisNearbyBtn, tx + tw - 120, detailY, 120, 22, TRUE);
    MoveWindow(g_hAnalysisDetail, tx, detailY + 22, tw, detailH, TRUE);

    int guideListH = tch / 3;
    if (guideListH < 50) guideListH = 50;
    MoveWindow(g_hGuideList, tx, ty, tw, guideListH, TRUE);
    MoveWindow(g_hGuideText, tx, ty + guideListH + 4, tw, tch - guideListH - 8, TRUE);

    int tableY = logY + logH + 8;
    int tableH = usableH - tableY - 40;
    if (tableH < 80) tableH = 80;

    MoveWindow(g_hTableGroup, 8, tableY, W - 16, tableH + 20, TRUE);
    MoveWindow(g_hAddressTable, 10, tableY + 20, W - 20, tableH - 8, TRUE);

    int tby = tableY + tableH + 14;
    MoveWindow(g_hAddAddrBtn, 10, tby, 110, 28, TRUE);
    MoveWindow(g_hRemoveAddrBtn, 126, tby, 80, 28, TRUE);
    MoveWindow(g_hEditValueBtn, 212, tby, 110, 28, TRUE);

    InvalidateRect(hWnd, nullptr, TRUE);
}

static void UpdateScanUI() {
    bool attached = g_ProcessManager.IsAttached();
    bool scanned  = g_Scanner.HasScanned();
    int  scanType = (int)SendMessage(g_hScanTypeCombo, CB_GETCURSEL, 0, 0);

    EnableWindow(g_hFirstScanBtn, attached);
    EnableWindow(g_hNextScanBtn, attached && scanned);
    EnableWindow(g_hUndoScanBtn, attached && g_Scanner.CanUndo());
    EnableWindow(g_hResetBtn, scanned);

    bool isBetween = (scanType == (int)ScanType::Between);
    ShowWindow(g_hValue2Label, isBetween ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hValue2Edit, isBetween ? SW_SHOW : SW_HIDE);

    bool needsValue = (scanType == (int)ScanType::ExactValue ||
                       scanType == (int)ScanType::GreaterThan ||
                       scanType == (int)ScanType::LessThan ||
                       scanType == (int)ScanType::Between);
    EnableWindow(g_hValueEdit, needsValue);
    EnableWindow(g_hValue2Edit, needsValue && isBetween);

    wchar_t countBuf[128];
    swprintf(countBuf, 128,
        L"\x0627\x0644\x0646\x062A\x0627\x0626\x062C: %s \x0639\x0646\x0648\x0627\x0646",
        FormatNumber(g_Scanner.GetResultCount()).c_str());
    SetCtrlText(g_hFoundCount, countBuf);
}

static void UpdateStatusBar(const wchar_t* text) {
    SendMessageW(g_hStatusBar, SB_SETTEXTW, 0, (LPARAM)text);
}

static void OnSelectProcess() {
    if (ShowProcessDialog()) {
        g_ProcessManager.Detach();
        g_Scanner.Reset();
        g_AddressTable.clear();
        RefreshAddressTable();
        RefreshFoundList();

        AddLogf(L"\x062C\x0627\x0631\x064A \x0627\x0644\x0627\x062A\x0635\x0627\x0644 \x0628\x0627\x0644\x0639\x0645\x0644\x064A\x0629 PID=%u ...",
                g_procDlgData.selectedPID);

        if (g_ProcessManager.Attach(g_procDlgData.selectedPID)) {
            g_Analyzer.SetProcessManager(&g_ProcessManager);
            g_Scanner.SetProcessManager(&g_ProcessManager);

            wchar_t buf[256];
            swprintf(buf, 256,
                L"  \x0645\x062A\x0635\x0644: %s  (PID: %u)",
                g_ProcessManager.GetName().c_str(), g_ProcessManager.GetPID());
            SetCtrlText(g_hProcessLabel, buf);
            UpdateStatusBar(L" \x062A\x0645 \x0627\x0644\x0627\x062A\x0635\x0627\x0644 \x0628\x0646\x062C\x0627\x062D. \x062C\x0627\x0647\x0632 \x0644\x0644\x0641\x062D\x0635.");

            auto detail = g_Analyzer.GetProcessDetails();
            AddLogf(L"\x062A\x0645 \x0627\x0644\x0627\x062A\x0635\x0627\x0644 \x0628\x0640 %s (PID: %u)",
                    detail.name.c_str(), detail.pid);
            AddLogf(L"  \x0627\x0644\x0628\x0646\x064A\x0629: %s | RAM: %s",
                    detail.architecture.c_str(),
                    FormatSize(detail.workingSetSize).c_str());
            AddLogf(L"  \x0627\x0644\x0645\x0648\x062F\x064A\x0648\x0644\x0627\x062A: %zu | \x0627\x0644\x062E\x064A\x0648\x0637: %zu | \x0627\x0644\x0645\x0646\x0627\x0637\x0642: %zu",
                    detail.moduleCount, detail.threadCount, detail.regionCount);
        } else {
            SetCtrlText(g_hProcessLabel,
                L"  \x0641\x0634\x0644 \x0627\x0644\x0627\x062A\x0635\x0627\x0644!");
            UpdateStatusBar(
                L" \x062E\x0637\x0623: \x0644\x0645 \x064A\x062A\x0645 \x0627\x0644\x0627\x062A\x0635\x0627\x0644. \x062C\x0631\x0628 \x0643\x0645\x0633\x0624\x0648\x0644.");
            AddLog(L"\x0641\x0634\x0644 \x0627\x0644\x0627\x062A\x0635\x0627\x0644 - \x062C\x0631\x0628 \x062A\x0634\x063A\x064A\x0644 \x0643\x0645\x0633\x0624\x0648\x0644");
        }
        UpdateScanUI();
    }
}

static void OnFirstScan() {
    if (!g_ProcessManager.IsAttached()) return;
    int vtIdx = (int)SendMessage(g_hValueTypeCombo, CB_GETCURSEL, 0, 0);
    int stIdx = (int)SendMessage(g_hScanTypeCombo, CB_GETCURSEL, 0, 0);
    if (vtIdx < 0 || stIdx < 0) return;

    ValueType vtype = (ValueType)vtIdx;
    ScanType  stype = (ScanType)stIdx;

    wchar_t val1Buf[512] = {}, val2Buf[512] = {};
    GetWindowTextW(g_hValueEdit, val1Buf, 512);
    GetWindowTextW(g_hValue2Edit, val2Buf, 512);

    AddLogf(L"\x0628\x062F\x0621 \x0627\x0644\x0641\x062D\x0635 \x0627\x0644\x0623\x0648\x0644 - \x0627\x0644\x0646\x0648\x0639: %s | \x0627\x0644\x0642\x064A\x0645\x0629: %s",
            VALUE_TYPE_NAMES[vtIdx], val1Buf[0] ? val1Buf : L"(\x063A\x064A\x0631 \x0645\x062D\x062F\x062F)");
    UpdateStatusBar(L" \x062C\x0627\x0631\x064A \x0627\x0644\x0641\x062D\x0635... \x0627\x0646\x062A\x0638\x0631");
    SetCursor(LoadCursor(nullptr, IDC_WAIT));

    g_Scanner.SetProcessManager(&g_ProcessManager);
    DWORD t0 = GetTickCount();
    bool ok = g_Scanner.FirstScan(vtype, stype, val1Buf, val2Buf);
    DWORD elapsed = GetTickCount() - t0;

    SetCursor(LoadCursor(nullptr, IDC_ARROW));

    if (ok) {
        AddLogf(L"\x0627\x0643\x062A\x0645\x0644 \x0627\x0644\x0641\x062D\x0635 \x0641\x064A %u ms - \x0648\x062C\x062F %s \x0639\x0646\x0648\x0627\x0646",
                elapsed, FormatNumber(g_Scanner.GetResultCount()).c_str());
        wchar_t sb[256];
        swprintf(sb, 256,
            L" \x0627\x0643\x062A\x0645\x0644 \x0627\x0644\x0641\x062D\x0635. \x0648\x062C\x062F %s \x0639\x0646\x0648\x0627\x0646 (%u ms)",
            FormatNumber(g_Scanner.GetResultCount()).c_str(), elapsed);
        UpdateStatusBar(sb);
    } else {
        UpdateStatusBar(L" \x0641\x0634\x0644 \x0627\x0644\x0641\x062D\x0635");
        AddLog(L"\x0641\x0634\x0644 \x0641\x064A \x0627\x0644\x0641\x062D\x0635 - \x062A\x062D\x0642\x0642 \x0645\x0646 \x0627\x0644\x0642\x064A\x0645\x0629");
        MessageBoxW(g_hMainWnd,
            L"\x0641\x0634\x0644 \x0627\x0644\x0641\x062D\x0635. \x062A\x0623\x0643\x062F \x0645\x0646 \x0635\x062D\x0629 \x0627\x0644\x0642\x064A\x0645\x0629.",
            L"\x062E\x0637\x0623", MB_ICONWARNING);
    }
    RefreshFoundList();
    UpdateScanUI();
}

static void OnNextScan() {
    if (!g_ProcessManager.IsAttached() || !g_Scanner.HasScanned()) return;
    int stIdx = (int)SendMessage(g_hScanTypeCombo, CB_GETCURSEL, 0, 0);
    if (stIdx < 0) return;

    wchar_t val1Buf[512] = {}, val2Buf[512] = {};
    GetWindowTextW(g_hValueEdit, val1Buf, 512);
    GetWindowTextW(g_hValue2Edit, val2Buf, 512);

    AddLogf(L"\x0641\x062D\x0635 \x062A\x0627\x0644\x064A - %s | %s",
            SCAN_TYPE_NAMES[stIdx], val1Buf[0] ? val1Buf : L"(\x063A\x064A\x0631 \x0645\x062D\x062F\x062F)");
    SetCursor(LoadCursor(nullptr, IDC_WAIT));

    DWORD t0 = GetTickCount();
    bool ok = g_Scanner.NextScan((ScanType)stIdx, val1Buf, val2Buf);
    DWORD elapsed = GetTickCount() - t0;

    SetCursor(LoadCursor(nullptr, IDC_ARROW));

    if (ok) {
        AddLogf(L"\x0627\x0643\x062A\x0645\x0644 \x0641\x064A %u ms - \x0628\x0642\x064A %s \x0639\x0646\x0648\x0627\x0646",
                elapsed, FormatNumber(g_Scanner.GetResultCount()).c_str());
        wchar_t sb[256];
        swprintf(sb, 256,
            L" \x0628\x0642\x064A %s \x0639\x0646\x0648\x0627\x0646 (%u ms)",
            FormatNumber(g_Scanner.GetResultCount()).c_str(), elapsed);
        UpdateStatusBar(sb);
    } else {
        AddLog(L"\x0641\x0634\x0644 \x0627\x0644\x0641\x062D\x0635 \x0627\x0644\x062A\x0627\x0644\x064A");
    }
    RefreshFoundList();
    UpdateScanUI();
}

static void OnUndoScan() {
    g_Scanner.UndoScan();
    RefreshFoundList(); UpdateScanUI();
    AddLog(L"\x062A\x0645 \x0627\x0644\x062A\x0631\x0627\x062C\x0639");
    UpdateStatusBar(L" \x062A\x0645 \x0627\x0644\x062A\x0631\x0627\x062C\x0639");
}

static void OnResetScan() {
    g_Scanner.Reset();
    RefreshFoundList(); UpdateScanUI();
    AddLog(L"\x062A\x0645 \x0625\x0639\x0627\x062F\x0629 \x062A\x0639\x064A\x064A\x0646 \x0627\x0644\x0645\x0627\x0633\x062D");
    UpdateStatusBar(L" \x062A\x0645 \x0625\x0639\x0627\x062F\x0629 \x062A\x0639\x064A\x064A\x0646 \x0627\x0644\x0645\x0627\x0633\x062D");
}

static void RefreshFoundList() {
    ListView_SetItemCountEx(g_hFoundList, (int)g_Scanner.GetResultCount(),
                            LVSICF_NOINVALIDATEALL);
    InvalidateRect(g_hFoundList, nullptr, TRUE);
}

static void RefreshAddressTable() {
    ListView_DeleteAllItems(g_hAddressTable);
    LVITEMW item = {};
    item.mask = LVIF_TEXT;

    for (int i = 0; i < (int)g_AddressTable.size(); i++) {
        auto& entry = g_AddressTable[i];
        item.iItem = i; item.iSubItem = 0;
        item.pszText = const_cast<LPWSTR>(L"");
        ListView_InsertItem(g_hAddressTable, &item);
        ListView_SetCheckState(g_hAddressTable, i, entry.frozen);
        ListView_SetItemText(g_hAddressTable, i, 1, const_cast<LPWSTR>(entry.description.c_str()));

        wchar_t addrBuf[32];
        swprintf(addrBuf, 32, L"0x%llX", (unsigned long long)entry.address);
        ListView_SetItemText(g_hAddressTable, i, 2, addrBuf);

        int typeIdx = (int)entry.type;
        if (typeIdx >= 0 && typeIdx < VALUE_TYPE_COUNT)
            ListView_SetItemText(g_hAddressTable, i, 3, const_cast<LPWSTR>(VALUE_TYPE_NAMES[typeIdx]));

        size_t valSize = MemoryScanner::GetValueSize(entry.type);
        if (valSize == 0) valSize = 64;
        std::vector<uint8_t> valBuf(valSize, 0);
        if (g_ProcessManager.IsAttached() &&
            g_ProcessManager.ReadMemory(entry.address, valBuf.data(), valSize)) {
            auto valStr = MemoryScanner::FormatValue(valBuf.data(), entry.type);
            ListView_SetItemText(g_hAddressTable, i, 4, const_cast<LPWSTR>(valStr.c_str()));
        } else {
            ListView_SetItemText(g_hAddressTable, i, 4, const_cast<LPWSTR>(L"???"));
        }
    }
}

static void OnAddToTable() {
    int sel = ListView_GetNextItem(g_hFoundList, -1, LVNI_SELECTED);
    if (sel < 0 || sel >= (int)g_Scanner.GetResultCount()) {
        MessageBoxW(g_hMainWnd,
            L"\x0627\x062E\x062A\x0631 \x0639\x0646\x0648\x0627\x0646 \x0645\x0646 \x0627\x0644\x0642\x0627\x0626\x0645\x0629 \x0623\x0648\x0644\x0627\x064B",
            L"\x0645\x0639\x0644\x0648\x0645\x0629", MB_ICONINFORMATION);
        return;
    }
    const auto& result = g_Scanner.GetResults()[sel];
    AddressEntry entry;
    entry.address = result.address; entry.type = g_Scanner.GetValueType();
    entry.frozen = false; entry.frozenValue = result.value;

    std::wstring desc = L"\x0628\x062F\x0648\x0646 \x0648\x0635\x0641";
    ShowInputDialog(L"\x0627\x0644\x0648\x0635\x0641",
        L"\x0623\x062F\x062E\x0644 \x0648\x0635\x0641\x0627\x064B \x0644\x0647\x0630\x0627 \x0627\x0644\x0639\x0646\x0648\x0627\x0646:", desc);
    entry.description = desc;

    g_AddressTable.push_back(entry);
    RefreshAddressTable();

    wchar_t addrStr[32];
    swprintf(addrStr, 32, L"0x%llX", (unsigned long long)entry.address);
    AddLogf(L"\x0623\x0636\x064A\x0641 \x0644\x0644\x062C\x062F\x0648\x0644: %s (%s)", addrStr, desc.c_str());
}

static void OnWriteFoundValue() {
    int sel = ListView_GetNextItem(g_hFoundList, -1, LVNI_SELECTED);
    if (sel < 0 || sel >= (int)g_Scanner.GetResultCount()) {
        MessageBoxW(g_hMainWnd,
            L"\x0627\x062E\x062A\x0631 \x0639\x0646\x0648\x0627\x0646 \x0623\x0648\x0644\x0627\x064B",
            L"\x0645\x0639\x0644\x0648\x0645\x0629", MB_ICONINFORMATION);
        return;
    }
    const auto& result = g_Scanner.GetResults()[sel];
    auto current = MemoryScanner::FormatValue(result.value.data(), g_Scanner.GetValueType());
    std::wstring newVal = current;
    if (ShowInputDialog(L"\x0643\x062A\x0627\x0628\x0629 \x0642\x064A\x0645\x0629",
                        L"\x0623\x062F\x062E\x0644 \x0627\x0644\x0642\x064A\x0645\x0629 \x0627\x0644\x062C\x062F\x064A\x062F\x0629:", newVal)) {
        std::vector<uint8_t> bytes;
        if (MemoryScanner::ParseValue(newVal, g_Scanner.GetValueType(), bytes)) {
            if (g_ProcessManager.WriteMemory(result.address, bytes.data(), bytes.size())) {
                AddLogf(L"\x0643\x062A\x0628 %s \x0641\x064A 0x%llX", newVal.c_str(), (unsigned long long)result.address);
                UpdateStatusBar(L" \x062A\x0645 \x0643\x062A\x0627\x0628\x0629 \x0627\x0644\x0642\x064A\x0645\x0629");
            } else {
                AddLog(L"\x0641\x0634\x0644 \x0643\x062A\x0627\x0628\x0629 \x0627\x0644\x0642\x064A\x0645\x0629");
                MessageBoxW(g_hMainWnd,
                    L"\x0641\x0634\x0644 \x0641\x064A \x0627\x0644\x0643\x062A\x0627\x0628\x0629",
                    L"\x062E\x0637\x0623", MB_ICONWARNING);
            }
        }
    }
}

static void OnAddAddressManual() {
    uintptr_t addr = 0; std::wstring desc = L""; ValueType type = ValueType::Int32;
    if (ShowAddAddressDialog(addr, desc, type)) {
        AddressEntry entry;
        entry.address = addr; entry.description = desc; entry.type = type;
        entry.frozen = false;
        size_t valSize = MemoryScanner::GetValueSize(type);
        if (valSize == 0) valSize = 64;
        entry.frozenValue.resize(valSize, 0);
        if (g_ProcessManager.IsAttached())
            g_ProcessManager.ReadMemory(addr, entry.frozenValue.data(), valSize);
        g_AddressTable.push_back(entry);
        RefreshAddressTable();
        AddLogf(L"\x0623\x0636\x064A\x0641 \x0639\x0646\x0648\x0627\x0646 \x064A\x062F\x0648\x064A: 0x%llX", (unsigned long long)addr);
    }
}

static void OnRemoveAddress() {
    int sel = ListView_GetNextItem(g_hAddressTable, -1, LVNI_SELECTED);
    if (sel < 0 || sel >= (int)g_AddressTable.size()) return;
    AddLogf(L"\x062D\x0630\x0641: %s", g_AddressTable[sel].description.c_str());
    g_AddressTable.erase(g_AddressTable.begin() + sel);
    RefreshAddressTable();
}

static void OnEditValue() {
    int sel = ListView_GetNextItem(g_hAddressTable, -1, LVNI_SELECTED);
    if (sel < 0 || sel >= (int)g_AddressTable.size()) return;
    auto& entry = g_AddressTable[sel];
    size_t valSize = MemoryScanner::GetValueSize(entry.type);
    if (valSize == 0) valSize = 64;

    std::vector<uint8_t> valBuf(valSize, 0);
    g_ProcessManager.ReadMemory(entry.address, valBuf.data(), valSize);
    auto current = MemoryScanner::FormatValue(valBuf.data(), entry.type);
    std::wstring newVal = current;

    if (ShowInputDialog(L"\x062A\x0639\x062F\x064A\x0644 \x0627\x0644\x0642\x064A\x0645\x0629",
                        L"\x0623\x062F\x062E\x0644 \x0627\x0644\x0642\x064A\x0645\x0629 \x0627\x0644\x062C\x062F\x064A\x062F\x0629:", newVal)) {
        std::vector<uint8_t> bytes;
        if (MemoryScanner::ParseValue(newVal, entry.type, bytes)) {
            if (g_ProcessManager.WriteMemory(entry.address, bytes.data(), bytes.size())) {
                entry.frozenValue = bytes;
                RefreshAddressTable();
                AddLogf(L"\x0639\x062F\x0644 %s -> %s", entry.description.c_str(), newVal.c_str());
            }
        }
    }
}

static void SetupAnalysisColumns(int mode) {
    while (ListView_DeleteColumn(g_hAnalysisList, 0)) {}

    LVCOLUMNW col = {};
    col.mask = LVCF_TEXT | LVCF_WIDTH;

    if (mode == 0) {
        col.pszText = const_cast<LPWSTR>(L"\x0627\x0644\x0639\x0646\x0648\x0627\x0646"); col.cx = 120;
        ListView_InsertColumn(g_hAnalysisList, 0, &col);
        col.pszText = const_cast<LPWSTR>(L"\x0627\x0644\x0646\x0635 \x0627\x0644\x0645\x0648\x062C\x0648\x062F"); col.cx = 180;
        ListView_InsertColumn(g_hAnalysisList, 1, &col);
        col.pszText = const_cast<LPWSTR>(L"\x0627\x0644\x0645\x0648\x062F\x064A\x0648\x0644"); col.cx = 100;
        ListView_InsertColumn(g_hAnalysisList, 2, &col);
        col.pszText = const_cast<LPWSTR>(L"\x0627\x0644\x0645\x0646\x0637\x0642\x0629"); col.cx = 140;
        ListView_InsertColumn(g_hAnalysisList, 3, &col);
    } else if (mode == 1) {
        col.pszText = const_cast<LPWSTR>(L"\x0627\x0644\x0627\x0633\x0645"); col.cx = 150;
        ListView_InsertColumn(g_hAnalysisList, 0, &col);
        col.pszText = const_cast<LPWSTR>(L"\x0627\x0644\x0639\x0646\x0648\x0627\x0646"); col.cx = 130;
        ListView_InsertColumn(g_hAnalysisList, 1, &col);
        col.pszText = const_cast<LPWSTR>(L"\x0627\x0644\x062D\x062C\x0645"); col.cx = 80;
        ListView_InsertColumn(g_hAnalysisList, 2, &col);
        col.pszText = const_cast<LPWSTR>(L"\x0627\x0644\x0645\x0633\x0627\x0631"); col.cx = 200;
        ListView_InsertColumn(g_hAnalysisList, 3, &col);
    } else if (mode == 2) {
        col.pszText = const_cast<LPWSTR>(L"\x0627\x0644\x0639\x0646\x0648\x0627\x0646"); col.cx = 130;
        ListView_InsertColumn(g_hAnalysisList, 0, &col);
        col.pszText = const_cast<LPWSTR>(L"\x0627\x0644\x062D\x062C\x0645"); col.cx = 80;
        ListView_InsertColumn(g_hAnalysisList, 1, &col);
        col.pszText = const_cast<LPWSTR>(L"\x0627\x0644\x062D\x0645\x0627\x064A\x0629"); col.cx = 150;
        ListView_InsertColumn(g_hAnalysisList, 2, &col);
        col.pszText = const_cast<LPWSTR>(L"\x0627\x0644\x0646\x0648\x0639"); col.cx = 100;
        ListView_InsertColumn(g_hAnalysisList, 3, &col);
    } else if (mode == 3) {
        col.pszText = const_cast<LPWSTR>(L"Thread ID"); col.cx = 100;
        ListView_InsertColumn(g_hAnalysisList, 0, &col);
        col.pszText = const_cast<LPWSTR>(L"\x0627\x0644\x0623\x0648\x0644\x0648\x064A\x0629"); col.cx = 80;
        ListView_InsertColumn(g_hAnalysisList, 1, &col);
        col.pszText = const_cast<LPWSTR>(L"\x0627\x0644\x0648\x0635\x0641"); col.cx = 200;
        ListView_InsertColumn(g_hAnalysisList, 2, &col);
    }
}

static void OnAnalysisSearch() {
    if (!g_ProcessManager.IsAttached()) {
        MessageBoxW(g_hMainWnd,
            L"\x0627\x062A\x0635\x0644 \x0628\x0639\x0645\x0644\x064A\x0629 \x0623\x0648\x0644\x0627\x064B",
            L"\x062A\x0646\x0628\x064A\x0647", MB_ICONINFORMATION);
        return;
    }

    int mode = (int)SendMessage(g_hAnalysisCombo, CB_GETCURSEL, 0, 0);
    g_analysisMode = mode;
    ListView_DeleteAllItems(g_hAnalysisList);
    SetupAnalysisColumns(mode);
    SetCtrlText(g_hAnalysisDetail, L"");

    SetCursor(LoadCursor(nullptr, IDC_WAIT));
    DWORD t0 = GetTickCount();

    LVITEMW item = {};
    item.mask = LVIF_TEXT;

    if (mode == 0) {
        wchar_t searchBuf[256] = {};
        GetWindowTextW(g_hAnalysisSearchEdit, searchBuf, 256);
        if (searchBuf[0] == 0) {
            SetCursor(LoadCursor(nullptr, IDC_ARROW));
            MessageBoxW(g_hMainWnd,
                L"\x0623\x062F\x062E\x0644 \x0646\x0635 \x0644\x0644\x0628\x062D\x062B",
                L"\x062A\x0646\x0628\x064A\x0647", MB_ICONINFORMATION);
            return;
        }
        AddLogf(L"\x0628\x062D\x062B \x0646\x0635\x064A \x0639\x0646: '%s'", searchBuf);

        g_searchResults = g_Analyzer.SearchStrings(searchBuf, 1000);
        DWORD elapsed = GetTickCount() - t0;

        for (int i = 0; i < (int)g_searchResults.size(); i++) {
            auto& r = g_searchResults[i];
            wchar_t addrBuf[32];
            swprintf(addrBuf, 32, L"0x%llX", (unsigned long long)r.address);

            item.iItem = i; item.iSubItem = 0; item.pszText = addrBuf;
            ListView_InsertItem(g_hAnalysisList, &item);
            ListView_SetItemText(g_hAnalysisList, i, 1, const_cast<LPWSTR>(r.foundString.c_str()));
            ListView_SetItemText(g_hAnalysisList, i, 2,
                const_cast<LPWSTR>(r.moduleName.empty() ? L"(\x062E\x0627\x0635)" : r.moduleName.c_str()));
            ListView_SetItemText(g_hAnalysisList, i, 3, const_cast<LPWSTR>(r.regionInfo.c_str()));
        }

        AddLogf(L"\x0648\x062C\x062F %zu \x0646\x062A\x064A\x062C\x0629 \x0641\x064A %u ms", g_searchResults.size(), elapsed);

    } else if (mode == 1) {
        AddLog(L"\x062C\x0627\x0631\x064A \x062A\x062D\x0644\x064A\x0644 \x0627\x0644\x0645\x0648\x062F\x064A\x0648\x0644\x0627\x062A...");
        g_moduleResults = g_Analyzer.GetModules();
        DWORD elapsed = GetTickCount() - t0;

        for (int i = 0; i < (int)g_moduleResults.size(); i++) {
            auto& m = g_moduleResults[i];
            wchar_t addrBuf[32];
            swprintf(addrBuf, 32, L"0x%llX", (unsigned long long)m.baseAddress);
            auto sizeStr = FormatSize(m.size);

            item.iItem = i; item.iSubItem = 0;
            item.pszText = const_cast<LPWSTR>(m.name.c_str());
            ListView_InsertItem(g_hAnalysisList, &item);
            ListView_SetItemText(g_hAnalysisList, i, 1, addrBuf);
            ListView_SetItemText(g_hAnalysisList, i, 2, const_cast<LPWSTR>(sizeStr.c_str()));
            ListView_SetItemText(g_hAnalysisList, i, 3, const_cast<LPWSTR>(m.path.c_str()));
        }

        AddLogf(L"\x0648\x062C\x062F %zu \x0645\x0648\x062F\x064A\x0648\x0644 (%u ms)",
                g_moduleResults.size(), elapsed);

    } else if (mode == 2) {
        AddLog(L"\x062C\x0627\x0631\x064A \x062A\x062D\x0644\x064A\x0644 \x0645\x0646\x0627\x0637\x0642 \x0627\x0644\x0630\x0627\x0643\x0631\x0629...");
        g_regionResults = g_Analyzer.GetMemoryRegions();
        DWORD elapsed = GetTickCount() - t0;

        int row = 0;
        for (int i = 0; i < (int)g_regionResults.size() && row < 5000; i++) {
            auto& r = g_regionResults[i];
            if (r.state != MEM_COMMIT) continue;

            wchar_t addrBuf[32];
            swprintf(addrBuf, 32, L"0x%llX", (unsigned long long)r.base);
            auto sizeStr = FormatSize(r.size);

            item.iItem = row; item.iSubItem = 0; item.pszText = addrBuf;
            ListView_InsertItem(g_hAnalysisList, &item);
            ListView_SetItemText(g_hAnalysisList, row, 1, const_cast<LPWSTR>(sizeStr.c_str()));
            ListView_SetItemText(g_hAnalysisList, row, 2, const_cast<LPWSTR>(r.protectionStr.c_str()));
            ListView_SetItemText(g_hAnalysisList, row, 3,
                const_cast<LPWSTR>(r.moduleName.empty() ? r.typeStr.c_str() : r.moduleName.c_str()));
            row++;
        }

        AddLogf(L"\x0648\x062C\x062F %d \x0645\x0646\x0637\x0642\x0629 \x0645\x062D\x062C\x0648\x0632\x0629 (%u ms)", row, elapsed);

    } else if (mode == 3) {
        AddLog(L"\x062C\x0627\x0631\x064A \x062A\x062D\x0644\x064A\x0644 \x0627\x0644\x062E\x064A\x0648\x0637...");
        g_threadResults = g_Analyzer.GetThreads();
        DWORD elapsed = GetTickCount() - t0;

        for (int i = 0; i < (int)g_threadResults.size(); i++) {
            auto& t = g_threadResults[i];
            wchar_t tidBuf[32], priBuf[16];
            swprintf(tidBuf, 32, L"%u", t.threadId);
            swprintf(priBuf, 16, L"%d", t.basePriority);

            const wchar_t* desc = L"\x062E\x064A\x0637 \x0639\x0645\x0644";
            if (i == 0) desc = L"\x0627\x0644\x062E\x064A\x0637 \x0627\x0644\x0631\x0626\x064A\x0633\x064A (\x063A\x0627\x0644\x0628\x0627\x064B)";

            item.iItem = i; item.iSubItem = 0; item.pszText = tidBuf;
            ListView_InsertItem(g_hAnalysisList, &item);
            ListView_SetItemText(g_hAnalysisList, i, 1, priBuf);
            ListView_SetItemText(g_hAnalysisList, i, 2, const_cast<LPWSTR>(desc));
        }

        AddLogf(L"\x0648\x062C\x062F %zu \x062E\x064A\x0637 (%u ms)", g_threadResults.size(), elapsed);
    }

    SetCursor(LoadCursor(nullptr, IDC_ARROW));
}

static void OnAnalysisSelChange() {
    int sel = ListView_GetNextItem(g_hAnalysisList, -1, LVNI_SELECTED);
    if (sel < 0) return;

    std::wstringstream ss;

    if (g_analysisMode == 0 && sel < (int)g_searchResults.size()) {
        auto& r = g_searchResults[sel];
        ss << L"\x0627\x0644\x0639\x0646\x0648\x0627\x0646: 0x" << std::hex << r.address << L"\r\n";
        ss << L"\x0627\x0644\x0646\x0635: " << r.foundString << L"\r\n";
        ss << L"\x0627\x0644\x0645\x0648\x062F\x064A\x0648\x0644: " << (r.moduleName.empty() ? L"\x062E\x0627\x0635" : r.moduleName) << L"\r\n";
        ss << L"\x0627\x0644\x0645\x0646\x0637\x0642\x0629: " << r.regionInfo << L"\r\n";
        ss << L"\r\n--- \x0634\x0631\x062D ---\r\n";
        ss << L"\x0647\x0630\x0627 \x0627\x0644\x0639\x0646\x0648\x0627\x0646 \x064A\x062D\x062A\x0648\x064A \x0639\x0644\x0649 \x0627\x0644\x0646\x0635 '" << r.foundString << L"'\r\n";
        ss << L"\x0641\x064A \x0630\x0627\x0643\x0631\x0629 \x0627\x0644\x0644\x0639\x0628\x0629. \x0627\x0644\x0642\x064A\x0645 \x0627\x0644\x0645\x062C\x0627\x0648\x0631\x0629 \x0631\x0628\x0645\x0627 \x062A\x062D\x062A\x0648\x064A \x0639\x0644\x0649\r\n";
        ss << L"\x0628\x064A\x0627\x0646\x0627\x062A \x0645\x062B\x0644 \x0627\x0644\x0630\x062E\x064A\x0631\x0629\x060C \x0627\x0644\x0636\x0631\x0631\x060C \x0627\x0644\x0633\x0631\x0639\x0629 \x0648\x063A\x064A\x0631\x0647\x0627.\r\n";
        ss << L"\x0627\x0636\x063A\x0637 '\x0627\x0644\x0642\x064A\x0645 \x0627\x0644\x0645\x062C\x0627\x0648\x0631\x0629' \x0644\x0644\x062A\x0641\x0627\x0635\x064A\x0644.\r\n";

    } else if (g_analysisMode == 1 && sel < (int)g_moduleResults.size()) {
        auto& m = g_moduleResults[sel];
        ss << L"\x0627\x0644\x0627\x0633\x0645: " << m.name << L"\r\n";
        ss << L"\x0627\x0644\x0639\x0646\x0648\x0627\x0646: 0x" << std::hex << m.baseAddress << L"\r\n";
        ss << std::dec;
        ss << L"\x0627\x0644\x062D\x062C\x0645: " << FormatSize(m.size) << L"\r\n";
        ss << L"\x0627\x0644\x0645\x0633\x0627\x0631: " << m.path << L"\r\n";
        ss << L"\r\n--- \x0634\x0631\x062D ---\r\n";
        ss << L"\x0647\x0630\x0627 \x0645\x0648\x062F\x064A\x0648\x0644 (\x0645\x0643\x062A\x0628\x0629 DLL \x0623\x0648 EXE) \x0645\x062D\x0645\x0644 \x0641\x064A \x0627\x0644\x0630\x0627\x0643\x0631\x0629.\r\n";
        ss << L"\x0627\x0644 CPU \x064A\x0646\x0641\x0630 \x0623\x0648\x0627\x0645\x0631\x0647 \x0645\x0628\x0627\x0634\x0631\x0629 \x0645\x0646 \x0647\x0630\x0627 \x0627\x0644\x0639\x0646\x0648\x0627\x0646.\r\n";

        std::wstring nameLower = m.name;
        for (auto& c : nameLower) c = towlower(c);
        if (nameLower.find(L"kernel32") != std::wstring::npos)
            ss << L"\x0647\x0630\x0627 kernel32 - \x0645\x0643\x062A\x0628\x0629 \x0627\x0644\x0646\x0638\x0627\x0645 \x0627\x0644\x0623\x0633\x0627\x0633\x064A\x0629 (\x0625\x062F\x0627\x0631\x0629 \x0627\x0644\x0645\x0644\x0641\x0627\x062A/\x0627\x0644\x0630\x0627\x0643\x0631\x0629/\x0627\x0644\x062E\x064A\x0648\x0637)\r\n";
        else if (nameLower.find(L"user32") != std::wstring::npos)
            ss << L"\x0647\x0630\x0627 user32 - \x0645\x0643\x062A\x0628\x0629 \x0627\x0644\x0646\x0648\x0627\x0641\x0630 \x0648\x0627\x0644\x0625\x062F\x062E\x0627\x0644\r\n";
        else if (nameLower.find(L"d3d") != std::wstring::npos)
            ss << L"\x0647\x0630\x0627 DirectX - \x0645\x0643\x062A\x0628\x0629 \x0627\x0644\x0631\x0633\x0648\x0645\x064A\x0627\x062A 3D\r\n";
        else if (nameLower.find(L"opengl") != std::wstring::npos)
            ss << L"\x0647\x0630\x0627 OpenGL - \x0645\x0643\x062A\x0628\x0629 \x0631\x0633\x0648\x0645\x064A\x0627\x062A\r\n";
        else if (nameLower.find(L"xinput") != std::wstring::npos)
            ss << L"\x0647\x0630\x0627 XInput - \x0645\x0643\x062A\x0628\x0629 \x0623\x0630\x0631\x0639 \x0627\x0644\x062A\x062D\x0643\x0645\r\n";
        else if (nameLower.find(L"wsock") != std::wstring::npos || nameLower.find(L"ws2") != std::wstring::npos)
            ss << L"\x0647\x0630\x0627 WinSock - \x0645\x0643\x062A\x0628\x0629 \x0627\x0644\x0634\x0628\x0643\x0629/\x0627\x0644\x0625\x0646\x062A\x0631\x0646\x062A\r\n";
        else if (nameLower.find(L"ntdll") != std::wstring::npos)
            ss << L"\x0647\x0630\x0627 ntdll - \x0627\x0644\x0637\x0628\x0642\x0629 \x0627\x0644\x0623\x0633\x0627\x0633\x064A\x0629 \x0644\x0644\x0646\x0638\x0627\x0645\r\n";
    }

    SetCtrlText(g_hAnalysisDetail, ss.str().c_str());
}

static void OnAnalysisNearby() {
    if (g_analysisMode != 0) return;
    int sel = ListView_GetNextItem(g_hAnalysisList, -1, LVNI_SELECTED);
    if (sel < 0 || sel >= (int)g_searchResults.size()) return;

    uintptr_t addr = g_searchResults[sel].address;

    auto nearby = g_Analyzer.GetNearbyValues(addr, 128);
    auto hexDump = g_Analyzer.HexDump(addr > 32 ? addr - 32 : 0, 128);
    auto fullAnalysis = g_Analyzer.AnalyzeAddress(addr);

    std::wstringstream ss;
    ss << fullAnalysis << L"\r\n";

    ss << L"--- \x0627\x0644\x0642\x064A\x0645 \x0627\x0644\x0645\x062C\x0627\x0648\x0631\x0629 ---\r\n";
    ss << L"\x0627\x0644\x0639\x0646\x0648\x0627\x0646          | Offset | Int32      | Float    | \x0627\x0644\x0648\x0635\x0641\r\n";
    for (const auto& nv : nearby) {
        if (nv.offset >= -64 && nv.offset <= 64) {
            wchar_t line[256];
            swprintf(line, 256, L"0x%llX | %+4d   | %-10d | %-8.2f | %s\r\n",
                (unsigned long long)nv.address, nv.offset,
                nv.intValue, nv.floatValue, nv.description.c_str());
            ss << line;
        }
    }

    ss << L"\r\n--- Hex Dump ---\r\n" << hexDump;

    SetCtrlText(g_hAnalysisDetail, ss.str().c_str());
    AddLogf(L"\x062A\x062D\x0644\x064A\x0644 \x0627\x0644\x0642\x064A\x0645 \x0627\x0644\x0645\x062C\x0627\x0648\x0631\x0629 \x0644\x0640 0x%llX", (unsigned long long)addr);
}

static void OnGuideSelChange() {
    int sel = (int)SendMessage(g_hGuideList, LB_GETCURSEL, 0, 0);
    if (sel < 0 || sel >= (int)g_guideSections.size()) return;
    SetCtrlText(g_hGuideText, g_guideSections[sel].content.c_str());
}

static void OnTimer() {
    if (!g_ProcessManager.IsAttached()) return;

    if (!g_ProcessManager.IsProcessAlive()) {
        g_ProcessManager.Detach();
        g_Scanner.Reset();
        SetCtrlText(g_hProcessLabel,
            L"  \x0627\x0644\x0639\x0645\x0644\x064A\x0629 \x0627\x0646\x062A\x0647\x062A");
        RefreshFoundList(); UpdateScanUI();
        UpdateStatusBar(L" \x0627\x0644\x0639\x0645\x0644\x064A\x0629 \x0627\x0646\x062A\x0647\x062A");
        AddLog(L"\x0627\x0644\x0639\x0645\x0644\x064A\x0629 \x0627\x0646\x062A\x0647\x062A");
        return;
    }

    for (int i = 0; i < (int)g_AddressTable.size(); i++) {
        auto& entry = g_AddressTable[i];
        size_t valSize = MemoryScanner::GetValueSize(entry.type);
        if (valSize == 0) valSize = 64;

        if (entry.frozen) {
            g_ProcessManager.WriteMemory(entry.address,
                entry.frozenValue.data(), entry.frozenValue.size());
        }

        std::vector<uint8_t> curVal(valSize, 0);
        if (g_ProcessManager.ReadMemory(entry.address, curVal.data(), valSize)) {
            auto valStr = MemoryScanner::FormatValue(curVal.data(), entry.type);
            ListView_SetItemText(g_hAddressTable, i, 4, const_cast<LPWSTR>(valStr.c_str()));
        } else {
            ListView_SetItemText(g_hAddressTable, i, 4, const_cast<LPWSTR>(L"???"));
        }
    }
}

static LRESULT CALLBACK MainWndProc(HWND hWnd, UINT msg,
                                     WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        g_hMainWnd = hWnd;
        CreateMainControls(hWnd);
        break;

    case WM_SIZE:
        OnResize(hWnd);
        break;

    case WM_TIMER:
        if (wParam == IDC_TIMER_UPDATE) OnTimer();
        break;

    case WM_ERASEBKGND: {
        // Dark background
        HDC hdc = (HDC)wParam;
        RECT rc;
        GetClientRect(hWnd, &rc);
        FillRect(hdc, &rc, g_hDarkBgBrush);
        return 1;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);

        RECT rc;
        GetClientRect(hWnd, &rc);

        // Draw header bar
        RECT headerRc = {0, 0, rc.right, HEADER_HEIGHT};
        FillRect(hdc, &headerRc, g_hHeaderBrush);

        // Draw accent line under header
        HPEN hAccentPen = CreatePen(PS_SOLID, 2, CLR_ACCENT);
        HPEN oldPen = (HPEN)SelectObject(hdc, hAccentPen);
        MoveToEx(hdc, 0, HEADER_HEIGHT - 1, nullptr);
        LineTo(hdc, rc.right, HEADER_HEIGHT - 1);
        SelectObject(hdc, oldPen);
        DeleteObject(hAccentPen);

        // Draw eye logo
        DrawEyeLogo(hdc, 14, 8, 48, 34);

        // Draw title text
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, CLR_ACCENT);
        if (g_hTitleFont) SelectObject(hdc, g_hTitleFont);
        RECT titleRc = {72, 6, rc.right - 10, 30};
        DrawTextW(hdc, L"Cheat Engine Pro v3.0", -1, &titleRc,
                  DT_LEFT | DT_SINGLELINE);

        // Subtitle
        SetTextColor(hdc, CLR_TEXT_DIM);
        if (g_hFont) SelectObject(hdc, g_hFont);
        RECT subRc = {72, 28, rc.right - 10, 48};
        DrawTextW(hdc,
            L"\x0645\x0627\x0633\x062D \x0648\x0645\x062D\x0631\x0631 \x0627\x0644\x0630\x0627\x0643\x0631\x0629 | Memory Scanner & Editor",
            -1, &subRc, DT_LEFT | DT_SINGLELINE);

        EndPaint(hWnd, &ps);
        break;
    }

    // Dark theme color handlers
    case WM_CTLCOLORSTATIC: {
        HDC hdcCtrl = (HDC)wParam;
        HWND hCtrl = (HWND)lParam;
        SetTextColor(hdcCtrl, CLR_TEXT);
        SetBkMode(hdcCtrl, TRANSPARENT);

        // GroupBox controls get panel bg
        wchar_t clsName[64];
        GetClassNameW(hCtrl, clsName, 64);
        if (wcscmp(clsName, L"Button") == 0) {
            LONG style = GetWindowLongW(hCtrl, GWL_STYLE) & 0x0FL;
            if (style == BS_GROUPBOX) {
                SetTextColor(hdcCtrl, CLR_ACCENT);
                return (LRESULT)g_hDarkBgBrush;
            }
        }
        return (LRESULT)g_hDarkBgBrush;
    }

    case WM_CTLCOLOREDIT: {
        HDC hdcCtrl = (HDC)wParam;
        SetTextColor(hdcCtrl, CLR_TEXT);
        SetBkColor(hdcCtrl, CLR_BG_INPUT);
        return (LRESULT)g_hInputBgBrush;
    }

    case WM_CTLCOLORLISTBOX: {
        HDC hdcCtrl = (HDC)wParam;
        SetTextColor(hdcCtrl, CLR_TEXT);
        SetBkColor(hdcCtrl, CLR_BG_DARK);
        return (LRESULT)g_hDarkBgBrush;
    }

    case WM_CTLCOLORBTN: {
        return (LRESULT)g_hDarkBgBrush;
    }

    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT lpDIS = (LPDRAWITEMSTRUCT)lParam;
        if (lpDIS->CtlType == ODT_BUTTON) {
            // Process button and first scan button are "accent" buttons
            bool isAccent = (lpDIS->CtlID == IDC_PROCESS_BTN ||
                            lpDIS->CtlID == IDC_FIRST_SCAN_BTN ||
                            lpDIS->CtlID == IDC_ANALYSIS_SEARCH_BTN);
            DrawDarkButton(lpDIS, isAccent);
            return TRUE;
        }
        // Owner-draw tab control
        if (lpDIS->CtlType == ODT_TAB) {
            HDC hdc = lpDIS->hDC;
            RECT rc = lpDIS->rcItem;

            bool selected = (lpDIS->itemState & ODS_SELECTED) != 0;
            COLORREF bg = selected ? CLR_BG_CARD : CLR_BG_PANEL;
            HBRUSH hBr = CreateSolidBrush(bg);
            FillRect(hdc, &rc, hBr);
            DeleteObject(hBr);

            // Bottom accent line for selected tab
            if (selected) {
                HPEN hPen = CreatePen(PS_SOLID, 2, CLR_ACCENT);
                HPEN oldP = (HPEN)SelectObject(hdc, hPen);
                MoveToEx(hdc, rc.left + 2, rc.bottom - 1, nullptr);
                LineTo(hdc, rc.right - 2, rc.bottom - 1);
                SelectObject(hdc, oldP);
                DeleteObject(hPen);
            }

            // Tab text
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, selected ? CLR_ACCENT : CLR_TEXT_DIM);
            if (g_hFont) SelectObject(hdc, g_hFont);

            wchar_t tabText[128] = {};
            TCITEMW tci = {};
            tci.mask = TCIF_TEXT;
            tci.pszText = tabText;
            tci.cchTextMax = 128;
            TabCtrl_GetItem(g_hTabCtrl, lpDIS->itemID, &tci);
            DrawTextW(hdc, tabText, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            return TRUE;
        }
        break;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_PROCESS_BTN:          OnSelectProcess(); break;
        case IDC_FIRST_SCAN_BTN:       OnFirstScan();     break;
        case IDC_NEXT_SCAN_BTN:        OnNextScan();      break;
        case IDC_UNDO_SCAN_BTN:        OnUndoScan();      break;
        case IDC_RESET_BTN:            OnResetScan();      break;
        case IDC_ADD_TO_TABLE_BTN:     OnAddToTable();    break;
        case IDC_WRITE_VALUE_BTN:      OnWriteFoundValue(); break;
        case IDC_ADD_ADDR_BTN:         OnAddAddressManual(); break;
        case IDC_REMOVE_ADDR_BTN:      OnRemoveAddress(); break;
        case IDC_EDIT_VALUE_BTN:       OnEditValue();     break;
        case IDC_ANALYSIS_SEARCH_BTN:  OnAnalysisSearch(); break;
        case IDC_ANALYSIS_NEARBY_BTN:  OnAnalysisNearby(); break;

        case IDC_SCAN_TYPE_COMBO:
            if (HIWORD(wParam) == CBN_SELCHANGE) UpdateScanUI();
            break;
        case IDC_GUIDE_LIST:
            if (HIWORD(wParam) == LBN_SELCHANGE) OnGuideSelChange();
            break;
        }
        break;

    case WM_NOTIFY: {
        LPNMHDR nm = reinterpret_cast<LPNMHDR>(lParam);

        if (nm->hwndFrom == g_hTabCtrl && nm->code == TCN_SELCHANGE) {
            int tab = TabCtrl_GetCurSel(g_hTabCtrl);
            SwitchTab(tab);
            break;
        }

        // NM_CUSTOMDRAW for dark ListViews
        if (nm->code == NM_CUSTOMDRAW) {
            LPNMLVCUSTOMDRAW lpCD = reinterpret_cast<LPNMLVCUSTOMDRAW>(lParam);
            if (nm->hwndFrom == g_hFoundList ||
                nm->hwndFrom == g_hAnalysisList ||
                nm->hwndFrom == g_hAddressTable) {
                switch (lpCD->nmcd.dwDrawStage) {
                case CDDS_PREPAINT:
                    return CDRF_NOTIFYITEMDRAW;
                case CDDS_ITEMPREPAINT:
                    lpCD->clrText = CLR_TEXT;
                    lpCD->clrTextBk = (lpCD->nmcd.dwItemSpec % 2 == 0) ?
                        CLR_BG_DARK : RGB(18, 21, 30);
                    // Highlight addresses in cyan
                    if (nm->hwndFrom == g_hFoundList ||
                        nm->hwndFrom == g_hAddressTable) {
                        return CDRF_NOTIFYSUBITEMDRAW;
                    }
                    return CDRF_NEWFONT;
                case CDDS_ITEMPREPAINT | CDDS_SUBITEM:
                    if (lpCD->iSubItem == 0) {
                        lpCD->clrText = CLR_ACCENT;
                    } else {
                        lpCD->clrText = CLR_TEXT;
                    }
                    return CDRF_NEWFONT;
                }
            }
        }

        // Virtual ListView - found list
        if (nm->hwndFrom == g_hFoundList && nm->code == LVN_GETDISPINFOW) {
            NMLVDISPINFOW* pDI = reinterpret_cast<NMLVDISPINFOW*>(lParam);
            int idx = pDI->item.iItem;
            if (idx < 0 || idx >= (int)g_Scanner.GetResultCount()) break;
            const auto& result = g_Scanner.GetResults()[idx];
            static wchar_t bufAddr[32], bufVal[128], bufPrev[128];

            if (pDI->item.mask & LVIF_TEXT) {
                switch (pDI->item.iSubItem) {
                case 0:
                    swprintf(bufAddr, 32, L"0x%llX", (unsigned long long)result.address);
                    pDI->item.pszText = bufAddr;
                    break;
                case 1: {
                    auto s = MemoryScanner::FormatValue(result.value.data(), g_Scanner.GetValueType());
                    wcsncpy_s(bufVal, s.c_str(), 127);
                    pDI->item.pszText = bufVal;
                    break;
                }
                case 2: {
                    auto s = MemoryScanner::FormatValue(result.previousValue.data(), g_Scanner.GetValueType());
                    wcsncpy_s(bufPrev, s.c_str(), 127);
                    pDI->item.pszText = bufPrev;
                    break;
                }
                }
            }
            break;
        }

        if (nm->hwndFrom == g_hFoundList && nm->code == NM_DBLCLK) {
            OnAddToTable(); break;
        }

        if (nm->hwndFrom == g_hAddressTable && nm->code == NM_DBLCLK) {
            OnEditValue(); break;
        }

        if (nm->hwndFrom == g_hAnalysisList && nm->code == LVN_ITEMCHANGED) {
            LPNMLISTVIEW pNM = reinterpret_cast<LPNMLISTVIEW>(lParam);
            if (pNM->uNewState & LVIS_SELECTED) OnAnalysisSelChange();
            break;
        }

        if (nm->hwndFrom == g_hAddressTable && nm->code == LVN_ITEMCHANGED) {
            LPNMLISTVIEW pNM = reinterpret_cast<LPNMLISTVIEW>(lParam);
            if (pNM->uChanged & LVIF_STATE) {
                int idx = pNM->iItem;
                if (idx >= 0 && idx < (int)g_AddressTable.size()) {
                    bool checked = ListView_GetCheckState(g_hAddressTable, idx);
                    auto& entry = g_AddressTable[idx];
                    if (checked != entry.frozen) {
                        entry.frozen = checked;
                        if (checked) {
                            size_t valSize = MemoryScanner::GetValueSize(entry.type);
                            if (valSize == 0) valSize = 64;
                            entry.frozenValue.resize(valSize, 0);
                            g_ProcessManager.ReadMemory(entry.address,
                                entry.frozenValue.data(), valSize);
                            AddLogf(L"\x062A\x062C\x0645\x064A\x062F: %s", entry.description.c_str());
                        } else {
                            AddLogf(L"\x0625\x0644\x063A\x0627\x0621 \x062A\x062C\x0645\x064A\x062F: %s", entry.description.c_str());
                        }
                    }
                }
            }
            break;
        }
        break;
    }

    case WM_GETMINMAXINFO: {
        MINMAXINFO* mmi = reinterpret_cast<MINMAXINFO*>(lParam);
        mmi->ptMinTrackSize.x = 900;
        mmi->ptMinTrackSize.y = 600;
        break;
    }

    case WM_DESTROY:
        KillTimer(hWnd, IDC_TIMER_UPDATE);
        if (g_hFont)        DeleteObject(g_hFont);
        if (g_hBoldFont)    DeleteObject(g_hBoldFont);
        if (g_hMonoFont)    DeleteObject(g_hMonoFont);
        if (g_hTitleFont)   DeleteObject(g_hTitleFont);
        if (g_hDarkBgBrush) DeleteObject(g_hDarkBgBrush);
        if (g_hPanelBgBrush)DeleteObject(g_hPanelBgBrush);
        if (g_hCardBgBrush) DeleteObject(g_hCardBgBrush);
        if (g_hInputBgBrush)DeleteObject(g_hInputBgBrush);
        if (g_hHeaderBrush) DeleteObject(g_hHeaderBrush);
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    g_hInst = hInstance;
    ProcessManager::EnableDebugPrivilege();

    INITCOMMONCONTROLSEX icex = {};
    icex.dwSize = sizeof(icex);
    icex.dwICC  = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES |
                  ICC_STANDARD_CLASSES | ICC_TAB_CLASSES;
    InitCommonControlsEx(&icex);

    WNDCLASSEXW wc = {};
    wc.cbSize       = sizeof(wc);
    wc.style        = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc  = MainWndProc;
    wc.hInstance     = hInstance;
    wc.hIcon         = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hIconSm       = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(CLR_BG_DARK);
    wc.lpszClassName = L"CheatEngineProMainWndV3";

    if (!RegisterClassExW(&wc)) {
        MessageBoxW(nullptr, L"Failed to register window class.",
                    L"Error", MB_ICONERROR);
        return 1;
    }

    HWND hWnd = CreateWindowExW(0, L"CheatEngineProMainWndV3",
        L"Cheat Engine Pro v3.0 - \x0645\x0627\x0633\x062D \x0648\x0645\x062D\x0631\x0631 \x0627\x0644\x0630\x0627\x0643\x0631\x0629",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1100, 700,
        nullptr, nullptr, hInstance, nullptr);

    if (!hWnd) {
        MessageBoxW(nullptr, L"Failed to create main window.", L"Error", MB_ICONERROR);
        return 1;
    }

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN &&
            msg.hwnd == g_hAnalysisSearchEdit) {
            OnAnalysisSearch();
            continue;
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return (int)msg.wParam;
}
