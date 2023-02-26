#include "mainWindow.h"
#include "resource.h"
#include "ini.h"

#define WND_CLASSNAME   _T("MainWindowClass")

HINSTANCE hMainInstance;
HWND hMainWindow;

static HFONT hDefaultFont;
static HWND hMainTab;

static HWND hTabWnds[] = {
    NULL, NULL,
};
static CONST TCHAR* tabItems[] = {
    _T("SYMM"), _T("DIGEST"),
};
enum {
    TAB_SYMM, TAB_DGST,
};

static void resizeWindows(HWND hWnd)
{
    RECT tRect;
    RECT wRect; /* window rect */
    RECT cRect;	/* client rect */
    INT w, h, i;

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
        }
    } else if (!lstrcmp(section, symmSecName)) {
        OnSymmConfigItem(name, value);
    } else if (!lstrcmp(section, dgstSecName)) {
        OnDigestConfigItem(name, value);
    }

    return 1;
}

static void onWindowCreate(HWND hWnd)
{
    TCITEM tci;

    hDefaultFont = CreateFont(WND_FONTSIZE, 0, 0, 0,
                        FW_NORMAL, 0, 0, 0,
                        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                        DEFAULT_QUALITY, DEFAULT_PITCH,
                        WND_FONTNAME);

    hMainTab = CreateWindow(WC_TABCONTROL, NULL, WS_VISIBLE | WS_CHILD/*  | WS_CLIPSIBLINGS */,
                    0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);

    tci.mask = TCIF_TEXT;

    hTabWnds[TAB_SYMM] = CreateSymmWindow(hMainTab);
    tci.pszText = (PSTR) tabItems[TAB_SYMM];
    SendMessage(hMainTab, TCM_INSERTITEM, (WPARAM) TAB_SYMM, (LPARAM) &tci);

    hTabWnds[TAB_DGST] = CreateDigestWindow(hMainTab);
    tci.pszText = (PSTR) tabItems[TAB_DGST];
    SendMessage(hMainTab, TCM_INSERTITEM, (WPARAM) TAB_DGST, (LPARAM) &tci);

    SetChildWindowsFont(hTabWnds[TAB_SYMM], hDefaultFont);
    SetChildWindowsFont(hTabWnds[TAB_DGST], hDefaultFont);
    SetChildWindowsFont(hWnd, hDefaultFont);

    switchTabTo(TAB_SYMM);
    resizeWindows(hWnd);

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

static void onWindowDone(HWND hWnd)
{
    HWND hTabWnd = hTabWnds[TabCtrl_GetCurSel(hMainTab)];

    SendMessage(hTabWnd, WM_COMMAND, (WPARAM) IDC_ACC_DONE, 0);
}

static void onWindowClose(HWND hWnd)
{
    if (!OnSymmWindowClose()
            && !OnDigestWindowClose()) {
        DestroyWindow(hWnd);
    }
}

static void onWindowDestroy(HWND hWnd)
{
    DeleteObject(hDefaultFont);
}

static LRESULT CALLBACK WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg) {
    case WM_NOTIFY:
        return onTabNotified(((LPNMHDR) lParam)->hwndFrom, ((LPNMHDR) lParam)->code);

    case WM_CREATE:
        onWindowCreate(hWnd);
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_ACC_EXIT:
            onWindowClose(hWnd);
            return 0;
        case IDC_ACC_DONE:
            onWindowDone(hWnd);
            return 0;
        default:
            return 0;
        }

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
    wc.hIconSm = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_CRYPT_MAIN_SM));

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
