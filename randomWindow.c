#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "mainWindow.h"
#include "encode.h"

#define WND_CLASSNAME       _T("RandomWindowClass")

#define WM_USER_RANDOM      (WM_USER + 1)

static HWND hOutformatStaticText;
static HWND hOutformatComboBox;
static HWND hOutbytesStaticText;
static HWND hOutbytesEditBox;
static HWND hOutputStaticText;
static HWND hOutputEditBox;
static HWND hRandomButton;

static CONST TCHAR* outformatItems[] = {
    _T("BASE64"), _T("C-ARRAY"), _T("C-STRING"), _T("HEX"),
};
enum {
    OFMT_BASE64, OFMT_C_ARRAY, OFMT_C_STRING, OFMT_HEX,
};


static void onRandomClicked(HWND hWnd)
{
    INT outfmt = GETCBOPT(hOutformatComboBox);
    TCHAR* outbytes = GetTextOnce(hOutbytesEditBox);
    VOID* out = NULL;
    TCHAR* outs = NULL;
    UINT outl = AsciiToInteger(outbytes, NULL, 10);

    if (!outl) {
        WARN(_T("OUT-BYTES is not a number"));
        goto cleanup;
    }
    if (outl > MAX_INFILE_SIZE) {
        WARN(_T("OUT-BYTES should less than %u"), MAX_INFILE_SIZE);
        goto cleanup;
    }

    out = malloc(outl);

    if (!RAND_bytes(out, outl)) {
        WARN(_T("RAND_bytes failed, code 0x%08X"), ERR_get_error());
        goto cleanup;
    }
    FormatTextTo(hOutputStaticText, _T("OUTPUT %d"), outl);

    switch (outfmt) {
    case OFMT_HEX:
        outs = BinaryToHexChars(out, outl);
        break;
    case OFMT_BASE64:
        outs = BinaryToBase64Chars(out, outl);
        break;
    case OFMT_C_ARRAY:
        outs = BinaryToCArrayChars(out, outl);
        break;
    case OFMT_C_STRING:
        outs = BinaryToCStringChars(out, outl);
        break;
    default:
        WARN(_T("Invalid OUT-FORMAT"));
        goto cleanup;
    }

    SetWindowText(hOutputEditBox, outs);
cleanup:
    free(out);
    free(outs);
    free(outbytes);
}

static void resizeWindows(HWND hWnd)
{
    CONST UINT iDpi = GetDpiForSystem();
    CONST UINT iAlign = MulDiv(WND_ALIGN, iDpi, 96);
    CONST UINT iLineH = MulDiv(WND_LINEH, iDpi, 96);
    CONST UINT iComboxW = MulDiv(WND_COMBOXW, iDpi, 96);
    CONST UINT iButtonW = MulDiv(WND_BUTTONW, iDpi, 96);
    INT w = iAlign;
    INT h = iAlign;

    MoveWindow(hOutformatStaticText, w, h, iComboxW, iLineH, FALSE);
    MoveWindow(hOutformatComboBox, w, h + iLineH, iComboxW, iLineH, FALSE);
    w += iComboxW + iAlign;
    MoveWindow(hOutbytesStaticText, w, h, iComboxW * 4 + iAlign * 3, iLineH, FALSE);
    MoveWindow(hOutbytesEditBox, w, h + iLineH, iComboxW * 4 + iAlign * 3, iLineH, FALSE);
    w += iComboxW * 4 + iAlign * 3 + iAlign;

    h += iLineH + iLineH + iAlign;

    MoveWindow(hOutputStaticText, iAlign, h, w - iAlign * 2, iLineH, FALSE);
    h += iLineH;
    MoveWindow(hOutputEditBox, iAlign, h, w - iAlign * 2, iLineH * 17 + iAlign * 3, FALSE);
    h += iLineH * 17 + iAlign * 3 + iAlign;

    MoveWindow(hRandomButton, w / 2 - iButtonW / 2, h, iButtonW, iLineH, FALSE);
    h += iLineH + iAlign;

    MoveWindow(hWnd, 0, 0, w, h, FALSE);
}

static void onWindowCreate(HWND hWnd)
{
    INT i;

    hOutformatStaticText = CreateWindow(_T("STATIC"), _T("OUT-FORMAT"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hOutformatComboBox = CreateWindow(_T("COMBOBOX"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWNLIST,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);

    hOutbytesStaticText = CreateWindow(_T("STATIC"), _T("OUT-BYTES"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hOutbytesEditBox = CreateWindow(_T("EDIT"), _T("16"), WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_AUTOHSCROLL,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);

    hOutputStaticText = CreateWindow(_T("STATIC"), _T("OUTPUT"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hOutputEditBox = CreateWindow(_T("EDIT"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_LEFT | ES_AUTOVSCROLL | ES_MULTILINE/*  | ES_READONLY */,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);

    hRandomButton = CreateWindow(_T("BUTTON"), _T("RANDOM"), WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                                0, 0, 0, 0, hWnd, (HMENU) WM_USER_RANDOM, hMainInstance, NULL);

    for (i = 0; i < ARRAYSIZE(outformatItems); ++i)
        SendMessage(hOutformatComboBox, CB_ADDSTRING, 0, (LPARAM) outformatItems[i]);
	SETCBOPT(hOutformatComboBox, OFMT_HEX);

    SendMessage(hOutputEditBox, EM_SETLIMITTEXT, (WPARAM) (MAX_INFILE_SIZE * 5), 0);

    resizeWindows(hWnd);
}

static void onWindowDestroy(HWND hWnd)
{
    /* NOOP */
}

static LRESULT CALLBACK WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg) {
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_ACC_DONE:
        case WM_USER_RANDOM:
            onRandomClicked(hWnd);
            break;
        }
        return 0;

    case WM_CREATE:
        onWindowCreate(hWnd);
        return 0;

    case WM_DESTROY:
        onWindowDestroy(hWnd);
        // PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProc(hWnd, uMsg, wParam, lParam);
    }
}

VOID OnRandomConfigSave(FILE* fp)
{
    TCHAR* outbytes = GetTextOnce(hOutbytesEditBox);

    TrimSpace(outbytes);

    /* note: OUTPUT not included */
    _ftprintf(fp, _T("OUT-FORMAT=%s\r\nOUT-BYTES=%s\r\n"),
        outformatItems[GETCBOPT(hOutformatComboBox)], outbytes);

    free(outbytes);
}

VOID OnRandomConfigItem(CONST TCHAR* name, CONST TCHAR* value)
{
    UINT i;
#define __SELECT_OPTION(items, hbox) __SELECT_OPTION_EX(items, hbox, NULL)
#define __SELECT_OPTION_EX(items, hbox, oper) \
        for (i = 0; i < ARRAYSIZE(items); ++i) { \
            if (!lstrcmp(value, items[i])) { \
                SETCBOPT(hbox, i); \
                oper; \
                break; \
            } \
        }

    if (!lstrcmp(name, _T("OUT-FORMAT"))) {
        __SELECT_OPTION(outformatItems, hOutformatComboBox);
    } else if (!lstrcmp(name, _T("OUT-BYTES"))) {
        SetWindowText(hOutbytesEditBox, value);
    } else if (!lstrcmp(name, _T("OUTPUT"))) {
        SetWindowText(hOutputEditBox, value);
    }

#undef __SELECT_OPTION_EX
#undef __SELECT_OPTION
}

BOOL OnRandomWindowClose()
{
    return FALSE;
}

HWND CreateRandomWindow(HWND hWnd)
{
    WNDCLASS wc;

    wc.style = 0;
    wc.lpfnWndProc = WndProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = hMainInstance;
    wc.hIcon = NULL;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH) COLOR_WINDOW;
    wc.lpszMenuName = NULL;
    wc.lpszClassName = WND_CLASSNAME;

    RegisterClass(&wc);

    return CreateWindowEx(WS_EX_ACCEPTFILES, WND_CLASSNAME, NULL, WS_CHILD,
                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
}