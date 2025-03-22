#include "mainWindow.h"
#include "encode.h"

#define WND_CLASSNAME       _T("ConvertWindowClass")

#define WM_USER_CONVERT      (WM_USER + 1)
#define WM_USER_SWAP         (WM_USER + 2)

static HWND hInformatStaticText;
static HWND hInformatComboBox;
static HWND hOutformatStaticText;
static HWND hOutformatComboBox;
static HWND hInputStaticText;
static HWND hInputEditBox;
static HWND hOutputStaticText;
static HWND hOutputEditBox;
static HWND hConvertButton;
static HWND hSwapButton;

static CONST TCHAR* informatItems[] = {
    _T("BASE64"), _T("C-ARRAY"), _T("C-STRING"), _T("FILE"), _T("HEX"), _T("TEXT"),
};
static CONST TCHAR* outformatItems[] = {
    _T("BASE64"), _T("C-ARRAY"), _T("C-STRING"), _T("FILE"), _T("HEX"), _T("TEXT"),
};
enum {
    IFMT_BASE64, IFMT_C_ARRAY, IFMT_C_STRING, IFMT_FILE, IFMT_HEX, IFMT_TEXT,
};
enum {
    OFMT_BASE64, OFMT_C_ARRAY, OFMT_C_STRING, OFMT_FILE, OFMT_HEX, OFMT_TEXT,
};


static void onDropFiles(HWND hWnd, HDROP hDrop)
{
    TCHAR* buf;
    UINT len;

    len = DragQueryFile(hDrop, 0, NULL, 0); /* >=0 */
    buf = malloc(sizeof(TCHAR) * (len + 1));

    memset(buf, 0, sizeof(TCHAR) * (len + 1));
    DragQueryFile(hDrop, 0, buf, len + 1);

    if (IsFile(buf)) {
        SetWindowText(hInputEditBox, buf);
        SETCBOPT(hInformatComboBox, IFMT_FILE);
    }

    DragFinish(hDrop);
    free(buf);
}

static void onConvertClicked(HWND hWnd)
{
    INT infmt = GETCBOPT(hInformatComboBox);
    INT outfmt = GETCBOPT(hOutformatComboBox);
    VOID* in = GetTextOnce(hInputEditBox);
    TCHAR* outs = NULL;
    INT inl;

#define __CONVERT_INPUT_NOTRIM(func, notify) \
        inl = func(in); \
        if (inl <= 0) { \
            WARN(notify); \
            goto cleanup; \
        }

#define __CONVERT_INPUT(func, notify) \
        if (TrimSpace(in)) \
            SetWindowText(hInputEditBox, in); \
        __CONVERT_INPUT_NOTRIM(func, notify)

    switch (infmt) {
    case IFMT_HEX:
        __CONVERT_INPUT(HexCharsToBinary, _T("INPUT is not a HEX string"));
        break;
    case IFMT_BASE64:
        __CONVERT_INPUT(Base64CharsToBinary, _T("INPUT is not a BASE64 string"));
        break;
    case IFMT_C_ARRAY:
        __CONVERT_INPUT(CArrayCharsToBinary, _T("INPUT is not a C-ARRAY string"));
        break;
    case IFMT_C_STRING:
        __CONVERT_INPUT(CStringCharsToBinary, _T("INPUT is not a C-STRING string"));
        break;
    case IFMT_TEXT:
        __CONVERT_INPUT_NOTRIM(TextCharsToBinary, _T("INPUT is not a TEXT string"));
        break;
    case IFMT_FILE: {
        TCHAR* _in;
        inl = MAX_INFILE_SIZE;
        _in = ReadFileOnce(in, (UINT*) &inl);
        if (!_in) {
            WARN(_T("file [%s] does not exist or > %uKB"), TRIMPATH(in), MAX_INFILE_SIZE / 1024);
            goto cleanup;
        }
        free(in);
        in = _in;
        break;
    }
    default:
        WARN(_T("Invalid IN-FORMAT"));
        goto cleanup;
    }
    FormatTextTo(hInputStaticText, _T("INPUT %d"), inl);
    FormatTextTo(hOutputStaticText, _T("OUTPUT %d"), inl);

    switch (outfmt) {
    case OFMT_HEX:
        outs = BinaryToHexChars(in, inl);
        break;
    case OFMT_BASE64:
        outs = BinaryToBase64Chars(in, inl);
        break;
    case OFMT_C_ARRAY:
        outs = BinaryToCArrayChars(in, inl);
        break;
    case OFMT_C_STRING:
        outs = BinaryToCStringChars(in, inl);
        break;
    case OFMT_TEXT:
        outs = BinaryToTextChars(in, inl);
        break;
    case OFMT_FILE: {
        TCHAR* path = GetTextOnce(hOutputEditBox);
        if (!IsFile(path) || CONFIRM(_T("OUTPUT file will be overwrite, continue?")) == IDOK) {
            if (WriteFileOnce(path, in, inl))
                FormatTextTo(hOutputStaticText, _T("OUTPUT %d (File)"), inl);
            else
                WARN(_T("Write output to [%s] failed"), TRIMPATH(path));
        }
        free(path);
        goto cleanup;
    }
    default:
        WARN(_T("Invalid OUT-FORMAT"));
        goto cleanup;
    }

    SetWindowText(hOutputEditBox, outs);
cleanup:
    free(in);
    free(outs);
#undef __CONVERT_INPUT
#undef __CONVERT_INPUT_NOTRIM
}

static void onSwapClicked(HWND hWnd)
{
    INT infmt = GETCBOPT(hInformatComboBox);
    INT outfmt = GETCBOPT(hOutformatComboBox);
    VOID* in = GetTextOnce(hInputEditBox);
    VOID* out = GetTextOnce(hOutputEditBox);

	SETCBOPT(hInformatComboBox, outfmt);
	SETCBOPT(hOutformatComboBox, infmt);
    SetWindowText(hInputEditBox, out);
    SetWindowText(hOutputEditBox, in);

    free(in);
    free(out);
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

    MoveWindow(hInformatStaticText, w, h, iComboxW, iLineH, FALSE);
    MoveWindow(hInformatComboBox, w, h + iLineH, iComboxW, iLineH, FALSE);
    w += iComboxW + iAlign;
    MoveWindow(hOutformatStaticText, w, h, iComboxW, iLineH, FALSE);
    MoveWindow(hOutformatComboBox, w, h + iLineH, iComboxW, iLineH, FALSE);
    w += iComboxW * 4 + iAlign * 3 + iAlign;

    h += iLineH + iLineH + iAlign;

    MoveWindow(hInputStaticText, iAlign, h, w - iAlign * 2, iLineH, FALSE);
    h += iLineH;
    MoveWindow(hInputEditBox, iAlign, h, w - iAlign * 2, iLineH * 8 + iAlign, FALSE);
    h += iLineH * 8 + iAlign + iAlign;
    MoveWindow(hOutputStaticText, iAlign, h, w - iAlign * 2, iLineH, FALSE);
    h += iLineH;
    MoveWindow(hOutputEditBox, iAlign, h, w - iAlign * 2, iLineH * 8 + iAlign, FALSE);
    h += iLineH * 8 + iAlign + iAlign;

    MoveWindow(hConvertButton, w / 2 - iButtonW - iAlign / 2, h, iButtonW, iLineH, FALSE);
    MoveWindow(hSwapButton, w / 2 + iAlign / 2, h, iButtonW, iLineH, FALSE);
    h += iLineH + iAlign;

    MoveWindow(hWnd, 0, 0, w, h, FALSE);
}

static void onWindowCreate(HWND hWnd)
{
    INT i;

    hInformatStaticText = CreateWindow(_T("STATIC"), _T("IN-FORMAT"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hInformatComboBox = CreateWindow(_T("COMBOBOX"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWNLIST,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hOutformatStaticText = CreateWindow(_T("STATIC"), _T("OUT-FORMAT"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hOutformatComboBox = CreateWindow(_T("COMBOBOX"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWNLIST,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);

    hInputStaticText = CreateWindow(_T("STATIC"), _T("INPUT"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hInputEditBox = CreateWindow(_T("EDIT"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_LEFT | ES_AUTOVSCROLL | ES_MULTILINE/*  | ES_READONLY */,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hOutputStaticText = CreateWindow(_T("STATIC"), _T("OUTPUT"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hOutputEditBox = CreateWindow(_T("EDIT"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_LEFT | ES_AUTOVSCROLL | ES_MULTILINE/*  | ES_READONLY */,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);

    hConvertButton = CreateWindow(_T("BUTTON"), _T("CONVERT"), WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                                0, 0, 0, 0, hWnd, (HMENU) WM_USER_CONVERT, hMainInstance, NULL);
    hSwapButton = CreateWindow(_T("BUTTON"), _T("SWAP"), WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                                0, 0, 0, 0, hWnd, (HMENU) WM_USER_SWAP, hMainInstance, NULL);

    for (i = 0; i < ARRAYSIZE(informatItems); ++i)
        SendMessage(hInformatComboBox, CB_ADDSTRING, 0, (LPARAM) informatItems[i]);
	SETCBOPT(hInformatComboBox, IFMT_HEX);
    for (i = 0; i < ARRAYSIZE(outformatItems); ++i)
        SendMessage(hOutformatComboBox, CB_ADDSTRING, 0, (LPARAM) outformatItems[i]);
	SETCBOPT(hOutformatComboBox, OFMT_HEX);

    SendMessage(hInputEditBox, EM_SETLIMITTEXT, (WPARAM) (MAX_INFILE_SIZE * 5), 0);
    // SendMessage(hOutputEditBox, EM_SETLIMITTEXT, (WPARAM) (MAX_INFILE_SIZE * 5), 0);

    resizeWindows(hWnd);
}

static void onWindowDestroy(HWND hWnd)
{
    /* NOOP */
}

static LRESULT CALLBACK WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg) {
    case WM_DROPFILES:
        onDropFiles(hWnd, (HDROP) wParam);
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_ACC_DONE:
        case WM_USER_CONVERT:
            onConvertClicked(hWnd);
            break;
        case WM_USER_SWAP:
            onSwapClicked(hWnd);
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

VOID OnConvertConfigItem(CONST TCHAR* name, CONST TCHAR* value)
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

    if (!lstrcmp(name, _T("IN-FORMAT"))) {
        __SELECT_OPTION(informatItems, hInformatComboBox);
    } else if (!lstrcmp(name, _T("OUT-FORMAT"))) {
        __SELECT_OPTION(outformatItems, hOutformatComboBox);
    } else if (!lstrcmp(name, _T("INPUT"))) {
        SetWindowText(hInputEditBox, value);
    } else if (!lstrcmp(name, _T("OUTPUT"))) {
        SetWindowText(hOutputEditBox, value);
    }

#undef __SELECT_OPTION_EX
#undef __SELECT_OPTION
}

BOOL OnConvertWindowClose()
{
    return FALSE;
}

HWND CreateConvertWindow(HWND hWnd)
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