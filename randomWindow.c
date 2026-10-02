#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "mainWindow.h"
#include "encode.h"

#define WND_CLASSNAME       _T("RandomWindowClass")

#define WM_USER_RANDOM      (WM_USER + 1)
#define WM_USER_OUTFMT      (WM_USER + 2)

static HWND hOutformatStaticText;
static HWND hOutformatComboBox;
static HWND hOutbytesStaticText;
static HWND hOutbytesEditBox;
static HWND hAllowcharsStaticText;
static HWND hAllowcharsEditBox;
static HWND hOutputStaticText;
static HWND hOutputEditBox;
static HWND hRandomButton;

static CONST TCHAR* outformatItems[] = {
    _T("BASE64"), _T("C-ARRAY"), _T("C-STRING"), _T("HEX"), _T("TEXT"),
};
enum {
    OFMT_BASE64, OFMT_C_ARRAY, OFMT_C_STRING, OFMT_HEX, OFMT_TEXT,
};


static void onOutformChanged()
{
    INT outfmt = GETCBOPT(hOutformatComboBox);

    EnableWindow(hAllowcharsEditBox, outfmt == OFMT_TEXT);
}

static INT getAllowChars(HWND hWnd, TCHAR* chars)
{
    INT i, len = GetWindowTextLength(hWnd);

    if (len > 0) {
        TCHAR* buf = malloc(sizeof(TCHAR) * (len + 1));

        GetWindowText(hWnd, buf, len + 1);
        memset(chars, 0, 128);
        for (i = 0; i < len; ++i) {
            if (!isprint(buf[i])) {
                free(buf);
                return 0;
            }
            chars[buf[i]] = 1;
        }
        free(buf);
        for (len = 0, i = 0; i < 128; ++i) {
            if (chars[i]) {
                chars[len++] = i;
            }
        }
        chars[len] = 0; // NOTE: len < 127
    } else {
        // set default alowed characters
        const char s[] = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
        memcpy(chars, s, sizeof(s));
        len = (int) sizeof(s) - 1;
    }

    return len;
}

static char* randText(const unsigned char* rnd, unsigned rndl, const char* allows, int allowsl)
{
    char* outs = malloc(rndl + 1);

    outs[rndl] = 0;
    while (rndl > 0) {
        --rndl;
        outs[rndl] = allows[rnd[rndl] % allowsl];
    }
    return outs;
}

static void onRandomClicked(HWND hWnd)
{
    INT outfmt = GETCBOPT(hOutformatComboBox);
    TCHAR* outbytes = GetTextOnce(hOutbytesEditBox);
    TCHAR allows[128];
    VOID* out = NULL;
    TCHAR* outs = NULL;
    UINT outl = AsciiToInteger(outbytes, NULL, 10);
    INT allowsl = 0;

    if (!outl) {
        WARN(_T("OUT-BYTES is not a number"));
        goto cleanup;
    }
    if (outl > MAX_INFILE_SIZE) {
        WARN(_T("OUT-BYTES should less than %u"), MAX_INFILE_SIZE);
        goto cleanup;
    }

    if (outfmt == OFMT_TEXT) {
        allowsl = getAllowChars(hAllowcharsEditBox, allows);
        if (allowsl < 2) {
            WARN("Invalid ALLOW-CHARS");
            goto cleanup;
        }
        SetWindowText(hAllowcharsEditBox, allows);
        FormatTextTo(hAllowcharsStaticText, _T("ALLOW-CHARS %d"), allowsl);
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
    case OFMT_TEXT:
        outs = randText(out, outl, allows, allowsl);
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

    MoveWindow(hAllowcharsStaticText, iAlign, h, w - iAlign * 2, iLineH, FALSE);
    h += iLineH;
    MoveWindow(hAllowcharsEditBox, iAlign, h, w - iAlign * 2, iLineH, FALSE);
    h += iLineH;
    MoveWindow(hOutputStaticText, iAlign, h, w - iAlign * 2, iLineH, FALSE);
    h += iLineH;
    MoveWindow(hOutputEditBox, iAlign, h, w - iAlign * 2, iLineH * 15 + iAlign * 3, FALSE);
    h += iLineH * 15 + iAlign * 3 + iAlign;

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
                                0, 0, 0, 0, hWnd, (HMENU) WM_USER_OUTFMT, hMainInstance, NULL);

    hOutbytesStaticText = CreateWindow(_T("STATIC"), _T("OUT-BYTES"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hOutbytesEditBox = CreateWindow(_T("EDIT"), _T("16"), WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_AUTOHSCROLL,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);

    hAllowcharsStaticText = CreateWindow(_T("STATIC"), _T("ALLOW-CHARS"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hAllowcharsEditBox = CreateWindow(_T("EDIT"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_AUTOHSCROLL,
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

    onOutformChanged();
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
        case WM_USER_OUTFMT:
            if (HIWORD(wParam) == CBN_SELCHANGE)
                onOutformChanged();
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
    TCHAR* allows = GetTextOnce(hAllowcharsEditBox);

    TrimSpace(outbytes);

    /* note: OUTPUT not included */
    _ftprintf(fp, _T("OUT-FORMAT=%s\r\nOUT-BYTES=%s\r\nALLOW-CHARS=%s\r\n"),
        outformatItems[GETCBOPT(hOutformatComboBox)], outbytes, allows);

    free(allows);
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
        __SELECT_OPTION_EX(outformatItems, hOutformatComboBox, onOutformChanged());
    } else if (!lstrcmp(name, _T("OUT-BYTES"))) {
        SetWindowText(hOutbytesEditBox, value);
    } else if (!lstrcmp(name, _T("ALLOW-CHARS"))) {
        SetWindowText(hAllowcharsEditBox, value);
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