#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#include "mainWindow.h"
#include "encode.h"

#define WND_CLASSNAME       _T("DigestWindowClass")

#define WM_USER_DIGEST      (WM_USER + 1)
#define WM_USER_ALGORITHM   (WM_USER + 2)
#define WM_USER_HMAC        (WM_USER + 3)
#define WM_USER_THREAD      (WM_USER + 4)

typedef struct stDigestThreadParams {
    /* IN */
    HWND hWnd;
    TCHAR* inPath;
    TCHAR* outPath;
    CONST EVP_MD* md;
    BYTE* key;
    INT keyl;
    INT outfmt;
    /* OUT */
    INT resultl;
    TCHAR result[EVP_MAX_MD_SIZE];
    TCHAR errorMsg[256];
} DigestThreadParams;

static HANDLE hDigestThread;
static DigestThreadParams digestThreadParams;

static HWND hAlgorithmStaticText;
static HWND hAlgorithmComboBox;
static HWND hBitsStaticText;
static HWND hBitsComboBox;
static HWND hInformatStaticText;
static HWND hInformatComboBox;
static HWND hOutformatStaticText;
static HWND hOutformatComboBox;
static HWND hHMacCheckBox;
static HWND hKeyStaticText;
static HWND hKeyEditBox;
static HWND hInputStaticText;
static HWND hInputEditBox;
static HWND hOutputStaticText;
static HWND hOutputEditBox;
static HWND hDigestButton;
static HWND hDigestProgressBar;

static CONST TCHAR* algorithmItems[] = {
    _T("BLAKE2B"), _T("BLAKE2S"), _T("MD4"), _T("MD5"), _T("RMD160"), _T("SHA1"), _T("SHA2"), _T("SHA3"), _T("SM3"), _T("WHIRLPOOL"),
};
enum {
    ALG_BLAKE2B, ALG_BLAKE2S, ALG_MD4, ALG_MD5, ALG_RMD160, ALG_SHA1, ALG_SHA2, ALG_SHA3, ALG_SM3, ALG_WHIRLPOOL,
};
static CONST TCHAR* bitsItems[] = {
    _T("128"), _T("224"), _T("256"), _T("384"), _T("512"),
};
enum {
    BITS_128, BITS_224, BITS_256, BITS_384, BITS_512,
};
static CONST TCHAR* informatItems[] = {
    _T("BASE64"), _T("C-ARRAY"), _T("C-STRING"), _T("FILE"), _T("HEX"), _T("TEXT"),
};
enum {
    IFMT_BASE64, IFMT_C_ARRAY, IFMT_C_STRING, IFMT_FILE, IFMT_HEX, IFMT_TEXT,
};
static CONST TCHAR* outformatItems[] = {
    _T("BASE64"), _T("C-ARRAY"), _T("C-STRING"), _T("HEX"),
};
enum {
    OFMT_BASE64, OFMT_C_ARRAY, OFMT_C_STRING, OFMT_HEX,
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

static void onHMacClicked(HWND hWnd)
{
    EnableWindow(hKeyEditBox, GETBTCHCK(hHMacCheckBox));
}

static void onAlgorithmChanged(HWND hWnd)
{
    INT alg = GETCBOPT(hAlgorithmComboBox);

    switch (alg) {
    case ALG_SHA2:
    case ALG_SHA3:
        EnableWindow(hBitsComboBox, TRUE);
        break;
    default:
        EnableWindow(hBitsComboBox, FALSE);
        break;
    }
}

static BOOL showDigestResult(CONST VOID* out, INT outl, INT outfmt)
{
    TCHAR* outs = NULL;

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
        return FALSE;
    }

    SetWindowText(hOutputEditBox, outs);
    free(outs);
    return TRUE;
}

static DWORD doDigestFile(VOID* arg)
{
    union { EVP_MD_CTX* md; HMAC_CTX* hmac; } ctx;
    DigestThreadParams* params = arg;
    BOOL ishmac = params->key != NULL;
    HANDLE hIn = INVALID_HANDLE_VALUE;
    UCHAR* rBuf = NULL;
    DWORD progressPercent = 0;
    DWORD tempPercent;
    DWORD nRead;
    DWORD beginTickCnt;
    DWORD endTickCnt;
    LARGE_INTEGER current;
    LARGE_INTEGER total;

    params->resultl = 0;
    beginTickCnt = GetTickCount();
    if (ishmac) {
        ctx.hmac = HMAC_CTX_new();
        HMAC_Init_ex(ctx.hmac, params->key, params->keyl, params->md, NULL);
    } else {
        ctx.md = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx.md, params->md, NULL);
    }

    hIn = CreateFile(params->inPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hIn == INVALID_HANDLE_VALUE) {
        wsprintf(params->errorMsg, _T("open INPUT file [%s] failed"), TRIMPATH(params->inPath));
        goto done;
    }
    if (!GetFileSizeEx(hIn, &total)) {
        wsprintf(params->errorMsg, _T("get INPUT file size [%s] failed"), TRIMPATH(params->inPath));
        goto done;
    }

    current.QuadPart = 0;
    rBuf = malloc(FILE_RBUF_SIZE);

    while (1) {
        ReadFile(hIn, rBuf, FILE_RBUF_SIZE, &nRead, NULL);

        if (!nRead) {
            if (!(ishmac ? HMAC_Final(ctx.hmac, params->result, &params->resultl)
                         : EVP_DigestFinal(ctx.md, params->result, &params->resultl))) {
                wsprintf(params->errorMsg, _T("EVP_DigestFinal/HMAC_Final failed, code 0x%08X"), ERR_get_error());
                goto done;
            }
            break;
        }
        current.QuadPart += nRead;

        if (!(ishmac ? HMAC_Update(ctx.hmac, rBuf, nRead)
                     : EVP_DigestUpdate(ctx.md, rBuf, nRead))) {
            wsprintf(params->errorMsg, _T("EVP_DigestUpdate/HMAC_Update failed, code 0x%08X"), ERR_get_error());
            goto done;
        }

        tempPercent = (current.QuadPart * 100 / total.QuadPart) & 0xFFFFFFFF;
        if (progressPercent != tempPercent) {
            PostMessage(hDigestProgressBar, PBM_SETPOS, (WPARAM) tempPercent, 0);
            progressPercent = tempPercent;
        }
    }

    endTickCnt = GetTickCount();

    wsprintf(params->errorMsg, _T("digest done, time %u.%us"),
        (endTickCnt - beginTickCnt) / 1000, (endTickCnt - beginTickCnt) % 1000);
done:
    CloseHandle(hIn);
    free(rBuf);
    if (ishmac)
        HMAC_CTX_free(ctx.hmac);
    else
        EVP_MD_CTX_free(ctx.md);
    PostMessage(params->hWnd, WM_COMMAND, (WPARAM) WM_USER_THREAD, (LPARAM) arg);
    return 0;
}
static void onDigestThreadDone(HWND hWnd, DigestThreadParams* params)
{
    WaitForSingleObject(hDigestThread, INFINITE);
    CloseHandle(hDigestThread);

    ShowWindow(hDigestProgressBar, SW_HIDE);
    SendMessage(hDigestProgressBar, PBM_SETPOS, 0, 0);

    if (params->resultl) {
        INFO(params->errorMsg);
        showDigestResult(params->result, params->resultl, params->outfmt);
    } else {
        WARN(params->errorMsg);
    }

    free(params->inPath);
    free(params->outPath);
    free(params->key);
    hDigestThread = NULL;
}

static void onDigestClicked(HWND hWnd)
{
    CONST EVP_MD* md;
    INT alg = GETCBOPT(hAlgorithmComboBox);
    INT bits = GETCBOPT(hBitsComboBox);
    INT infmt = GETCBOPT(hInformatComboBox);
    INT outfmt = GETCBOPT(hOutformatComboBox);
    VOID* key = GETBTCHCK(hHMacCheckBox) ? GetTextOnce(hKeyEditBox) : NULL;
    VOID* in = GetTextOnce(hInputEditBox);
    VOID* out = NULL;
    INT keyl;
    INT inl;
    INT outl;

#define __CONVERT_INPUT(func, notify) \
        if (TrimSpace(in)) \
            SetWindowText(hInputEditBox, in); \
        inl = func(in); \
        if (inl <= 0) { \
            WARN(notify); \
            goto cleanup; \
        }

    if (key) {
        if (TrimSpace(key))
            SetWindowText(hKeyEditBox, key);
        keyl = HexCharsToBinary(key);
        if (keyl < 0) {
            WARN(_T("KEY is not a HEX string"));
            goto cleanup;
        }
    }

    switch (alg) {
    case ALG_BLAKE2B:
        md = EVP_blake2b512();
        break;
    case ALG_BLAKE2S:
        md = EVP_blake2s256();
        break;
    case ALG_MD4:
        md = EVP_md4();
        break;
    case ALG_MD5:
        md = EVP_md5();
        break;
    case ALG_RMD160:
        md = EVP_ripemd160();
        break;
    case ALG_SHA1:
        md = EVP_sha1();
        break;
    case ALG_SHA2:
        switch (bits) {
        case BITS_224: md = EVP_sha224(); break;
        case BITS_256: md = EVP_sha256(); break;
        case BITS_384: md = EVP_sha384(); break;
        case BITS_512: md = EVP_sha512(); break;
        default:
            WARN(_T("SHA2 BITS should be 224/256/384/512"));
            goto cleanup;
        }
        break;
    case ALG_SHA3:
        switch (bits) {
        case BITS_224: md = EVP_sha3_224(); break;
        case BITS_256: md = EVP_sha3_256(); break;
        case BITS_384: md = EVP_sha3_384(); break;
        case BITS_512: md = EVP_sha3_512(); break;
        default:
            WARN(_T("SHA3 BITS should be 224/256/384/512"));
            goto cleanup;
        }
        break;
    case ALG_SM3:
        md = EVP_sm3();
        break;
    case ALG_WHIRLPOOL:
        md = EVP_whirlpool();
        break;
    default:
        WARN(_T("Invalid ALGORITHM"));
        goto cleanup;
    }

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
        __CONVERT_INPUT(TextCharsToBinary, _T("INPUT is not a TEXT string"));
        break;
    case IFMT_FILE:
        /* start digest file int the thread. */
        if (hDigestThread) {
            WARN(_T("digest thread already running"));
            goto cleanup;
        }
        out = GetTextOnce(hOutputEditBox);

        if (IsFile(out) && CONFIRM(_T("OUTPUT file will be overwrite, continue?")) != IDOK)
            goto cleanup;

        digestThreadParams.hWnd = hWnd;
        digestThreadParams.inPath = in;
        digestThreadParams.outPath = out;
        digestThreadParams.md = md;
        digestThreadParams.key = key;
        if (key)
            digestThreadParams.keyl = keyl;
        digestThreadParams.outfmt = outfmt;

        hDigestThread = CreateThread(NULL, 0, doDigestFile, &digestThreadParams, 0, NULL);
        if (!hDigestThread) {
            WARN(_T("create digest thread failed"));
            goto cleanup;
        }
        ShowWindow(hDigestProgressBar, SW_SHOW);
        /* something else is freed when digest thread done */
        return;
    default:
        WARN(_T("Invalid IN-FORMAT"));
        goto cleanup;
    }
    FormatTextTo(hInputStaticText, _T("INPUT %d"), inl);

    out = malloc(EVP_MAX_MD_SIZE);

    if (key) {
        /* keyl == 0 is allowed */
        if (!HMAC(md, key, keyl, in, inl, out, &outl)) {
            WARN(_T("HMAC failed, code 0x%08X"), ERR_get_error());
            goto cleanup;
        }
    } else {
        if (!EVP_Digest(in, inl, out, &outl, md, NULL)) {
            WARN(_T("EVP_Digest failed, code 0x%08X"), ERR_get_error());
            goto cleanup;
        }
    }
    FormatTextTo(hOutputStaticText, _T("OUTPUT %d"), outl);

    showDigestResult(out, outl, outfmt);
cleanup:
    free(key);
    free(in);
    free(out);
#undef __CONVERT_INPUT
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

    MoveWindow(hAlgorithmStaticText, w, h, iComboxW, iLineH, FALSE);
    MoveWindow(hAlgorithmComboBox, w, h + iLineH, iComboxW, iLineH, FALSE);
    w += iComboxW + iAlign;
    MoveWindow(hBitsStaticText, w, h, iComboxW, iLineH, FALSE);
    MoveWindow(hBitsComboBox, w, h + iLineH, iComboxW, iLineH, FALSE);
    w += iComboxW + iAlign;
    MoveWindow(hInformatStaticText, w, h, iComboxW, iLineH, FALSE);
    MoveWindow(hInformatComboBox, w, h + iLineH, iComboxW, iLineH, FALSE);
    w += iComboxW + iAlign;
    MoveWindow(hOutformatStaticText, w, h, iComboxW, iLineH, FALSE);
    MoveWindow(hOutformatComboBox, w, h + iLineH, iComboxW, iLineH, FALSE);
    w += iComboxW + iAlign;
    MoveWindow(hHMacCheckBox, w + iAlign * 2, h + iLineH, iComboxW - iAlign * 2, iLineH, FALSE);
    w += iComboxW + iAlign;

    h += iLineH + iLineH + iAlign;

    MoveWindow(hKeyStaticText, iAlign, h, w - iAlign * 2, iLineH, FALSE);
    h += iLineH;
    MoveWindow(hKeyEditBox, iAlign, h, w - iAlign * 2, iLineH, FALSE);
    h += iLineH + iAlign;

    MoveWindow(hInputStaticText, iAlign, h, w - iAlign * 2, iLineH, FALSE);
    h += iLineH;
    MoveWindow(hInputEditBox, iAlign, h, w - iAlign * 2, iLineH * 8, FALSE);
    h += iLineH * 8 + iAlign;

    MoveWindow(hOutputStaticText, iAlign, h, w / 2 - iAlign, iLineH, FALSE);
    h += iLineH;
    MoveWindow(hOutputEditBox, iAlign, h, w - iAlign * 2, iLineH * 6 + iAlign, FALSE);
    h += iLineH * 6 + iAlign * 2;

    MoveWindow(hDigestProgressBar, iAlign, h, w / 2 - iButtonW / 2 - iAlign * 2, iLineH, FALSE);
    MoveWindow(hDigestButton, w / 2 - iButtonW / 2, h, iButtonW, iLineH, FALSE);
    h += iLineH + iAlign;

    MoveWindow(hWnd, 0, 0, w, h, FALSE);
}

static void onWindowCreate(HWND hWnd)
{
    INT i;

    hAlgorithmStaticText = CreateWindow(_T("STATIC"), _T("ALGORITHM"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hAlgorithmComboBox = CreateWindow(_T("COMBOBOX"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWNLIST,
                                0, 0, 0, 0, hWnd, (HMENU) WM_USER_ALGORITHM, hMainInstance, NULL);
    hBitsStaticText = CreateWindow(_T("STATIC"), _T("BITS"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hBitsComboBox = CreateWindow(_T("COMBOBOX"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWNLIST,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hInformatStaticText = CreateWindow(_T("STATIC"), _T("IN-FORMAT"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hInformatComboBox = CreateWindow(_T("COMBOBOX"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWNLIST,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hOutformatStaticText = CreateWindow(_T("STATIC"), _T("OUT-FORMAT"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hOutformatComboBox = CreateWindow(_T("COMBOBOX"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWNLIST,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hHMacCheckBox = CreateWindow(_T("BUTTON"), _T("HMAC"), WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                0, 0, 0, 0, hWnd, (HMENU) WM_USER_HMAC, hMainInstance, NULL);

    hKeyStaticText = CreateWindow(_T("STATIC"), _T("KEY <HEX>"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, NULL, NULL);
    hKeyEditBox = CreateWindow(_T("EDIT"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_AUTOHSCROLL,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);

    hInputStaticText = CreateWindow(_T("STATIC"), _T("INPUT"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hInputEditBox = CreateWindow(_T("EDIT"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_LEFT | ES_AUTOVSCROLL | ES_MULTILINE,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);

    hOutputStaticText = CreateWindow(_T("STATIC"), _T("OUTPUT"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hOutputEditBox = CreateWindow(_T("EDIT"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_LEFT | ES_AUTOVSCROLL | ES_MULTILINE/*  | ES_READONLY */,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);

    hDigestButton = CreateWindow(_T("BUTTON"), _T("DIGEST"), WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                                0, 0, 0, 0, hWnd, (HMENU) WM_USER_DIGEST, hMainInstance, NULL);

    hDigestProgressBar = CreateWindow(PROGRESS_CLASS, NULL, /* WS_VISIBLE |  */WS_CHILD | PBS_SMOOTH,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);

    for (i = 0; i < ARRAYSIZE(algorithmItems); ++i)
        SendMessage(hAlgorithmComboBox, CB_ADDSTRING, 0, (LPARAM) algorithmItems[i]);
	SETCBOPT(hAlgorithmComboBox, ALG_MD5);
    for (i = 0; i < ARRAYSIZE(bitsItems); ++i)
        SendMessage(hBitsComboBox, CB_ADDSTRING, 0, (LPARAM) bitsItems[i]);
    SETCBOPT(hBitsComboBox, BITS_256);
    for (i = 0; i < ARRAYSIZE(informatItems); ++i)
        SendMessage(hInformatComboBox, CB_ADDSTRING, 0, (LPARAM) informatItems[i]);
	SETCBOPT(hInformatComboBox, IFMT_HEX);
    for (i = 0; i < ARRAYSIZE(outformatItems); ++i)
        SendMessage(hOutformatComboBox, CB_ADDSTRING, 0, (LPARAM) outformatItems[i]);
	SETCBOPT(hOutformatComboBox, OFMT_HEX);

    SendMessage(hInputEditBox, EM_SETLIMITTEXT, (WPARAM) (MAX_INFILE_SIZE * 5), 0);
    // SendMessage(hOutputEditBox, EM_SETLIMITTEXT, (WPARAM) (MAX_INFILE_SIZE * 5), 0);

    onHMacClicked(hWnd);
    onAlgorithmChanged(hWnd);
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
        case WM_USER_ALGORITHM:
            onAlgorithmChanged(hWnd);
            break;
        case WM_USER_HMAC:
            onHMacClicked(hWnd);
            break;
        case IDC_ACC_DONE:
        case WM_USER_DIGEST:
            onDigestClicked(hWnd);
            break;
        case WM_USER_THREAD:
            onDigestThreadDone(hWnd, (DigestThreadParams*) lParam);
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

VOID OnDigestConfigItem(CONST TCHAR* name, CONST TCHAR* value)
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

    if (!lstrcmp(name, _T("ALGRITHM"))) {
        __SELECT_OPTION_EX(algorithmItems, hAlgorithmComboBox, onAlgorithmChanged(NULL));
    } else if (!lstrcmp(name, _T("BITS"))) {
        __SELECT_OPTION(bitsItems, hBitsComboBox);
    } else if (!lstrcmp(name, _T("IN-FORMAT"))) {
        __SELECT_OPTION(informatItems, hInformatComboBox);
    } else if (!lstrcmp(name, _T("OUT-FORMAT"))) {
        __SELECT_OPTION(outformatItems, hOutformatComboBox);
    } else if (!lstrcmp(name, _T("KEY"))) {
        SetWindowText(hKeyEditBox, value);
    } else if (!lstrcmp(name, _T("INPUT"))) {
        SetWindowText(hInputEditBox, value);
    } else if (!lstrcmp(name, _T("OUTPUT"))) {
        SetWindowText(hOutputEditBox, value);
    } else if (!lstrcmp(name, _T("HMAC"))) {
        if (!lstrcmp(value, _T("ON"))) {
            SETBTCHCK(hHMacCheckBox, TRUE);
            onHMacClicked(NULL);
        } else if (!lstrcmp(value, _T("OFF"))) {
            SETBTCHCK(hHMacCheckBox, FALSE);
            onHMacClicked(NULL);
        }
    }

#undef __SELECT_OPTION_EX
#undef __SELECT_OPTION
}

BOOL OnDigestWindowClose()
{
    if (hDigestThread && CONFIRM(_T("digest thread running, exit?")) != IDOK)
        return TRUE;
    return FALSE;
}

HWND CreateDigestWindow(HWND hWnd)
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