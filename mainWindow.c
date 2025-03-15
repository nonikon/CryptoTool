#include "mainWindow.h"
#include "resource.h"
#include "ini.h"

#define WND_CLASSNAME   _T("MainWindowClass")

HINSTANCE hMainInstance;
HWND hMainWindow;

static HFONT hContentFont;
static HFONT hTitleFont;
static HWND hMainTab;

static HWND hTabWnds[] = {
    NULL, NULL, NULL, NULL,
};
static CONST TCHAR* tabItems[] = {
    _T("SYMM"), _T("DIGEST"), _T("RANDOM"), _T("CONVERT"),
};
enum {
    TAB_SYMM, TAB_DGST, TAB_RANDOM, TAB_CONVERT,
};

static void resizeWindows(HWND hWnd)
{
    CONST UINT iDpi = GetDpiForSystem();
    CONST UINT iFontSz = MulDiv(WND_FONTSIZE, iDpi, 96);
    HFONT hFont;
    RECT tRect;
    RECT wRect; /* window rect */
    RECT cRect;	/* client rect */
    INT w, h, i;

    hFont = CreateFont(iFontSz, 0, 0, 0, FW_MEDIUM, 0, 0, 0,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH, WND_FONTNAME);
    SetChildWindowsFont(hWnd, hFont);
    if (hTitleFont) {
        DeleteObject(hTitleFont);
    }
    hTitleFont = hFont;

    hFont = CreateFont(iFontSz, 0, 0, 0, FW_NORMAL, 0, 0, 0,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH, WND_FONTNAME);
    for (i = 0; i < ARRAYSIZE(hTabWnds); ++i) {
        SetChildWindowsFont(hTabWnds[i], hFont);
    }
    if (hContentFont) {
        DeleteObject(hContentFont);
    }
    hContentFont = hFont;

    GetClientRect(hTabWnds[TAB_SYMM], &tRect);

    SendMessage(hMainTab, TCM_ADJUSTRECT, TRUE, (LPARAM) &tRect);
    w = tRect.right - tRect.left;
    h = tRect.bottom - tRect.top;
    MoveWindow(hMainTab, 0, 0, w, h, FALSE);

    tRect.left = 0;
    tRect.top = 0;
    tRect.right = w;
    tRect.bottom = h;
    SendMessage(hMainTab, TCM_ADJUSTRECT, FALSE, (LPARAM) &tRect);
    for (i = 0; i < ARRAYSIZE(hTabWnds); ++i) {
        MoveWindow(hTabWnds[i], tRect.left, tRect.top,
            tRect.right - tRect.left, tRect.bottom - tRect.top, FALSE);
    }

    GetWindowRect(hWnd, &wRect);
    GetClientRect(hWnd, &cRect);
    w += cRect.left - wRect.left + wRect.right - cRect.right;
    h += cRect.top - wRect.top + wRect.bottom - cRect.bottom;

    /* move to center of the screen */
    MoveWindow(hWnd, (GetSystemMetrics(SM_CXSCREEN) - w) / 2,
        (GetSystemMetrics(SM_CYSCREEN) - h) / 2, w, h, TRUE);
}

static void switchTabTo(INT idx)
{
    INT old = TabCtrl_GetCurSel(hMainTab);

    SendMessage(hMainTab, TCM_SETCURSEL, (WPARAM) idx, 0);
    ShowWindow(hTabWnds[old], SW_HIDE);
    ShowWindow(hTabWnds[idx], SW_SHOW);
}

static int onConfigItem(void* user, const char* section,
                const char* name, const char* value)
{
    static TCHAR symmSecName[32] = _T("SYMM");
    static TCHAR dgstSecName[32] = _T("DIGEST");
    static TCHAR randSecName[32] = _T("RANDOM");
    static TCHAR convSecName[32] = _T("CONVERT");
    int i;

    if (!section[0]) {
        if (!lstrcmp(name, _T("INITTAB"))) {
            for (i = 0; i < ARRAYSIZE(tabItems); ++i) {
                if (!lstrcmp(value, tabItems[i])) {
                    switchTabTo(i);
                    break;
                }
            }
        } else if (!lstrcmp(name, _T("SYMMCFG"))) {
            if (value[0]) {
                lstrcpyn(symmSecName, value, sizeof(symmSecName));
            }
        } else if (!lstrcmp(name, _T("DGSTCFG"))) {
            if (value[0]) {
                lstrcpyn(dgstSecName, value, sizeof(dgstSecName));
            }
        } else if (!lstrcmp(name, _T("RANDCFG"))) {
            if (value[0]) {
                lstrcpyn(randSecName, value, sizeof(randSecName));
            }
        } else if (!lstrcmp(name, _T("CONVCFG"))) {
            if (value[0]) {
                lstrcpyn(convSecName, value, sizeof(convSecName));
            }
        }
    } else if (!lstrcmp(section, symmSecName)) {
        OnSymmConfigItem(name, value);
    } else if (!lstrcmp(section, dgstSecName)) {
        OnDigestConfigItem(name, value);
    } else if (!lstrcmp(section, randSecName)) {
        OnRandomConfigItem(name, value);
    } else if (!lstrcmp(section, convSecName)) {
        OnConvertConfigItem(name, value);
    }

    return 1;
}

static void onWindowCreate(HWND hWnd)
{
    TCITEM tci;

    hMainTab = CreateWindow(WC_TABCONTROL, NULL, WS_VISIBLE | WS_CHILD/*  | WS_CLIPSIBLINGS */,
                    0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);

    tci.mask = TCIF_TEXT;

    hTabWnds[TAB_SYMM] = CreateSymmWindow(hMainTab);
    tci.pszText = (PSTR) tabItems[TAB_SYMM];
    SendMessage(hMainTab, TCM_INSERTITEM, (WPARAM) TAB_SYMM, (LPARAM) &tci);

    hTabWnds[TAB_DGST] = CreateDigestWindow(hMainTab);
    tci.pszText = (PSTR) tabItems[TAB_DGST];
    SendMessage(hMainTab, TCM_INSERTITEM, (WPARAM) TAB_DGST, (LPARAM) &tci);

    hTabWnds[TAB_RANDOM] = CreateRandomWindow(hMainTab);
    tci.pszText = (PSTR) tabItems[TAB_RANDOM];
    SendMessage(hMainTab, TCM_INSERTITEM, (WPARAM) TAB_RANDOM, (LPARAM) &tci);

    hTabWnds[TAB_CONVERT] = CreateConvertWindow(hMainTab);
    tci.pszText = (PSTR) tabItems[TAB_CONVERT];
    SendMessage(hMainTab, TCM_INSERTITEM, (WPARAM) TAB_CONVERT, (LPARAM) &tci);

    resizeWindows(hWnd);
    switchTabTo(TAB_SYMM);

    ini_parse(CONFIG_FILENAME, onConfigItem, NULL);
}

static BOOL onTabNotified(HWND hWnd, UINT code)
{
    INT idx = TabCtrl_GetCurSel(hMainTab);

    switch (code) {
    case TCN_SELCHANGING:
        ShowWindow(hTabWnds[idx], SW_HIDE);
        /* return FALSE to allow the selection to change */
        return FALSE;

    case TCN_SELCHANGE:
        ShowWindow(hTabWnds[idx], SW_SHOW);
        return TRUE;

    default:
        return TRUE;
    }
}

static void sendCmdToCurTabWnd(HWND hWnd, INT cmd)
{
    HWND hTabWnd = hTabWnds[TabCtrl_GetCurSel(hMainTab)];

    SendMessage(hTabWnd, WM_COMMAND, (WPARAM) cmd, 0);
}

static void onWindowClose(HWND hWnd)
{
    if (!OnSymmWindowClose()
            && !OnDigestWindowClose()
            && !OnRandomWindowClose()
            && !OnConvertWindowClose()) {
        DestroyWindow(hWnd);
    }
}

static void onWindowDestroy(HWND hWnd)
{
    DeleteObject(hTitleFont);
    DeleteObject(hContentFont);
}

static LRESULT CALLBACK WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg) {
    case WM_NOTIFY:
        return onTabNotified(((LPNMHDR) lParam)->hwndFrom, ((LPNMHDR) lParam)->code);

    // case WM_DPICHANGED:
    //     return 0;

    case WM_CREATE:
        onWindowCreate(hWnd);
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_ACC_EXIT:
            onWindowClose(hWnd);
            break;
        case IDC_ACC_DONE:
            sendCmdToCurTabWnd(hWnd, IDC_ACC_DONE);
            break;
        case IDC_ACC_STOP:
            sendCmdToCurTabWnd(hWnd, IDC_ACC_STOP);
            break;
        case IDC_ACC_NEXT:
            switchTabTo((TabCtrl_GetCurFocus(hMainTab) + 1) % ARRAYSIZE(hTabWnds));
            break;
        }
        return 0;

    case WM_CLOSE:
        onWindowClose(hWnd);
        return 0;

    case WM_DESTROY:
        onWindowDestroy(hWnd);
        PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProc(hWnd, uMsg, wParam, lParam);
    }
}

int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
    INITCOMMONCONTROLSEX ic;
    WNDCLASSEX wc;
    MSG msg;
    HACCEL acc;

    ic.dwSize = sizeof(INITCOMMONCONTROLSEX);
    ic.dwICC = ICC_TAB_CLASSES | ICC_PROGRESS_CLASS;

    InitCommonControlsEx(&ic);

    wc.cbSize = sizeof(WNDCLASSEX);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_CRYPT_MAIN));
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH) COLOR_WINDOW;
    wc.lpszMenuName = NULL;
    wc.lpszClassName = WND_CLASSNAME;
    wc.hIconSm = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_CRYPT_MAIN));

    RegisterClassEx(&wc);

    acc = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDA_CRYPT_MAIN));

    hMainInstance = hInstance;
    hMainWindow = CreateWindow(WND_CLASSNAME, WND_TITLE,
                        WS_SYSMENU | WS_MINIMIZEBOX,
                        0, 0, 0, 0, NULL, NULL, hInstance, NULL);

    ShowWindow(hMainWindow, nCmdShow);
    UpdateWindow(hMainWindow);

    while (GetMessage(&msg, NULL, 0, 0)) {
        if (!TranslateAccelerator(hMainWindow, acc, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return 0;
}
