#include <windows.h>
#include <commctrl.h>
#include <tchar.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "endec.h"
#include "utils.h"
#include "ini.h"

#define VERSION_STRING  _T("V1.0")

#define CONFIG_FILENAME _T("CryptoTool.ini")
#define MAX_INFILE_SIZE (128 * 1024)
#define FILE_RBUF_SIZE  (16 * 1024)

#define WND_TITLE       _T("CryptoTool ") VERSION_STRING
#define WND_CLASSNAME   _T("CryptoToolClass")
#define WND_FONTNAME    _T("Consolas")
#define WND_FONTSIZE    18
#define WND_ALIGN       6
#define WND_LINEH       (WND_FONTSIZE + 6)
#define WND_COMBOXW     90
#define WND_BUTTONW     80

#define WM_MAIN_ENCRYPT     (WM_USER + 1)
#define WM_MAIN_DECRYPT     (WM_USER + 2)
#define WM_MAIN_ALGORITHM   (WM_USER + 3)
#define WM_MAIN_MODE        (WM_USER + 4)
#define WM_MAIN_THREAD      (WM_USER + 5)

#define INFO(hWnd, ...)     formatMessageBox(hWnd, MB_OK, _T("INFO"), ##__VA_ARGS__)
#define WARN(hWnd, ...)     formatMessageBox(hWnd, MB_OK, _T("WARN"), ##__VA_ARGS__)
#define CONFIRM(hWnd, ...)  formatMessageBox(hWnd, MB_OKCANCEL, _T("WARN"), ##__VA_ARGS__)

#pragma comment(linker, "/manifestdependency:\" \
            type='win32' \
            name='Microsoft.Windows.Common-Controls' \
            version='6.0.0.0' \
            processorArchitecture='*' \
            publicKeyToken='6595b64144ccf1df' \
            language='*' \
        \"")

typedef struct stCryptThreadParams {
    /* IN */
    HWND hMainWnd;
    EVP_CIPHER_CTX* ciphCtx;
    TCHAR* inPath;
    TCHAR* outPath;
    BOOL needChkSize;
    /* OUT */
    BOOL isSucc;
    TCHAR resultMsg[256];
} CryptThreadParams;

static HANDLE hCryptThread;
static CryptThreadParams cryptThreadParams;

static HFONT hDefaultFont;

static HWND hAlgorithmStaticText;
static HWND hAlgorithmComboBox;
static HWND hModeStaticText;
static HWND hModeComboBox;
static HWND hPaddingStaticText;
static HWND hPaddingComboBox;
static HWND hInformatStaticText;
static HWND hInformatComboBox;
static HWND hOutformatStaticText;
static HWND hOutformatComboBox;
static HWND hKeyStaticText;
static HWND hKeyEditBox;
static HWND hIVStaticText;
static HWND hIVEditBox;
static HWND hInputStaticText;
static HWND hInputEditBox;
static HWND hOutputStaticText;
static HWND hOutputEditBox;
static HWND hEncryptButton;
static HWND hDecryptButton;
static HWND hCryptProgressBar;

static CONST TCHAR* algorithmItems[] = {
    _T("AES"), _T("ARIA"), _T("BLOWFISH"), _T("CAMELLIA"), _T("CAST"), _T("CHACHA"), _T("IDEA"), _T("SEED"), _T("SM4"),
};
enum {
    ALG_AES, ALG_ARIA, ALG_BLOWFISH, ALG_CAMELLIA, ALG_CAST, ALG_CHACHA, ALG_IDEA, ALG_SEED, ALG_SM4,
};
static CONST TCHAR* modeItems[] = {
    _T("ECB"), _T("CBC"), _T("CFB"), _T("OFB"), _T("CTR"),
};
enum {
    MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, MODE_CTR,
};
static CONST TCHAR* paddingItems[] = {
    _T("NONE"), _T("PKCS")
};
enum {
    PAD_NONE, PAD_PKCS,
};
static CONST TCHAR* informatItems[] = {
    _T("HEX"), _T("BASE64"), _T("C-ARRAY"), _T("C-STRING"), _T("FILE"),
};
enum {
    IFMT_HEX, IFMT_BASE64, IFMT_C_ARRAY, IFMT_C_STRING, IFMT_FILE,
};
static CONST TCHAR* outformatItems[] = {
    _T("HEX"), _T("BASE64"), _T("C-ARRAY"), _T("C-STRING"), _T("FILE"),
};
enum {
    OFMT_HEX, OFMT_BASE64, OFMT_C_ARRAY, OFMT_C_STRING, OFMT_FILE,
};


static INT getOption(HWND hWnd)
{
    return (INT) SendMessage(hWnd, CB_GETCURSEL, 0, 0);
}

static TCHAR* getText(HWND hWnd)
{
    TCHAR* buf;
    int len;
    
    len = GetWindowTextLength(hWnd); /* >=0 */
    buf = malloc(sizeof(TCHAR) * (len + 1));

    memset(buf, 0, sizeof(TCHAR) * (len + 1));
    GetWindowText(hWnd, buf, len + 1);
    return buf;
}

static int formatMessageBox(HWND hWnd, UINT type, CONST TCHAR* title, CONST TCHAR* fmt, ...)
{
    TCHAR buf[512];
    va_list ap;

    va_start(ap, fmt);
    wvsprintf(buf, fmt, ap);
    va_end(ap);

    return MessageBox(hWnd, buf, title, type);
}

static void formatTextTo(HWND hWnd, CONST TCHAR* fmt, ...)
{
    TCHAR buf[512];
    va_list ap;

    va_start(ap, fmt);
    wvsprintf(buf, fmt, ap);
    va_end(ap);

    SetWindowText(hWnd, buf);
}

static void onDropFiles(HWND hWnd, HDROP hDrop)
{
    TCHAR* buf;
    UINT len;

    len = DragQueryFile(hDrop, 0, NULL, 0); /* >=0 */
    buf = malloc(sizeof(TCHAR) * (len + 4 + 1)); /* .out */

    memset(buf, 0, sizeof(TCHAR) * (len + 4 + 1));
    DragQueryFile(hDrop, 0, buf, len + 1);
    if (IsFile(buf)) {
        SetWindowText(hInputEditBox, buf);
        memcpy(buf + len, _T(".out"), sizeof(TCHAR) * 4);
        SetWindowText(hOutputEditBox, buf);
    }

    DragFinish(hDrop);
    free(buf);
}

static BOOL isPaddingNeeded(INT mode)
{
    switch (mode) {
    case MODE_ECB:
    case MODE_CBC:
        return TRUE;
    default:
        return FALSE;
    }
}
static BOOL isIVNeeded(INT mode)
{
    switch (mode) {
    case MODE_ECB:
        return FALSE;
    default:
        return TRUE;
    }
}

static void onModeChanged(HWND hWnd)
{
    INT mode = getOption(hModeComboBox);

    EnableWindow(hPaddingComboBox, isPaddingNeeded(mode));
    EnableWindow(hIVEditBox, isIVNeeded(mode));
}

static void onAlgorithmChanged(HWND hWnd)
{
    INT alg = getOption(hAlgorithmComboBox);

    if (alg == ALG_CHACHA) {
        SendMessage(hModeComboBox, CB_SETCURSEL, MODE_CTR, 0);
        onModeChanged(hWnd);
    }
}

static DWORD doCryptFile(VOID* arg)
{
    CryptThreadParams* params = &cryptThreadParams;
    HANDLE hIn = INVALID_HANDLE_VALUE;
    HANDLE hOut = INVALID_HANDLE_VALUE;
    UCHAR* rBuf = NULL;
    UCHAR* wBuf = NULL;
    DWORD progressPercent = 0;
    DWORD tempPercent;
    DWORD nReadWrite;
    DWORD beginTickCnt;
    DWORD endTickCnt;
    LARGE_INTEGER current;
    LARGE_INTEGER total;
    int outl;

    params->isSucc = FALSE;
    beginTickCnt = GetTickCount();

    hIn = CreateFile(params->inPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hIn == INVALID_HANDLE_VALUE) {
        wsprintf(params->resultMsg, _T("open INPUT file [%s] failed"),
            trimFilePath(params->inPath, 32));
        goto done;
    }
    if (!GetFileSizeEx(hIn, &total)) {
        wsprintf(params->resultMsg, _T("get INPUT file size [%s] failed"),
            trimFilePath(params->inPath, 32));
        goto done;
    }
    if (params->needChkSize && total.QuadPart % EVP_CIPHER_CTX_block_size(params->ciphCtx) != 0) {
        wsprintf(params->resultMsg, _T("INPUT file size is not a multiple of %d"),
            EVP_CIPHER_CTX_block_size(params->ciphCtx));
        goto done;
    }

    hOut = CreateFile(params->outPath, GENERIC_WRITE, 0, NULL,
                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) {
        wsprintf(params->resultMsg, _T("open OUTPUT file [%s] failed"),
            trimFilePath(params->outPath, 32));
        goto done;
    }

    current.QuadPart = 0;
    rBuf = malloc(FILE_RBUF_SIZE);
    wBuf = malloc(FILE_RBUF_SIZE + EVP_MAX_BLOCK_LENGTH); /* big enough to store encrypt/decrypt result */

    while (1) {
        ReadFile(hIn, rBuf, FILE_RBUF_SIZE, &nReadWrite, NULL);

        if (!nReadWrite) {
            if (!EVP_CipherFinal(params->ciphCtx, wBuf, &outl)) {
                wsprintf(params->resultMsg, _T("EVP_CipherFinal failed (INPUT error), code 0x%08X"), ERR_get_error());
                goto done;
            }
            if (outl && !WriteFile(hOut, wBuf, outl, &nReadWrite, NULL)) {
                wsprintf(params->resultMsg, _T("write to [%s] failed"),
                    trimFilePath(params->outPath, 32));
                goto done;
            }
            break;
        }
        current.QuadPart += nReadWrite;

        if (!EVP_CipherUpdate(params->ciphCtx, wBuf, &outl, rBuf, nReadWrite)) {
            wsprintf(params->resultMsg, _T("EVP_CipherUpdate failed, code 0x%08X"), ERR_get_error());
            goto done;
        }
        if (!WriteFile(hOut, wBuf, outl, &nReadWrite, NULL)) {
            wsprintf(params->resultMsg, _T("write to [%s] failed"),
                trimFilePath(params->outPath, 32));
            goto done;
        }

        tempPercent = (current.QuadPart * 100 / total.QuadPart) & 0xFFFFFFFF;
        if (progressPercent != tempPercent) {
            PostMessage(hCryptProgressBar, PBM_SETPOS, (WPARAM) tempPercent, 0);
            progressPercent = tempPercent;
        }
    }

    params->isSucc = TRUE;
    endTickCnt = GetTickCount();

    wsprintf(params->resultMsg, _T("crypt done, time %u.%us"),
        (endTickCnt - beginTickCnt) / 1000, (endTickCnt - beginTickCnt) % 1000);
done:
    CloseHandle(hIn);
    CloseHandle(hOut);
    free(rBuf);
    free(wBuf);
    free(params->inPath);
    free(params->outPath);
    EVP_CIPHER_CTX_free(params->ciphCtx);
    PostMessage(params->hMainWnd, WM_COMMAND, (WPARAM) WM_MAIN_THREAD, 0);
    return 0;
}
static void onCryptThreadDone(HWND hWnd)
{
    WaitForSingleObject(hCryptThread, INFINITE);

    ShowWindow(hCryptProgressBar, SW_HIDE);
    SendMessage(hCryptProgressBar, PBM_SETPOS, 0, 0);

    if (cryptThreadParams.isSucc)
        INFO(hWnd, cryptThreadParams.resultMsg);
    else
        WARN(hWnd, cryptThreadParams.resultMsg);

    CloseHandle(hCryptThread);
    hCryptThread = NULL;
}

static void doCrypt(HWND hWnd, BOOL isDec)
{
    CONST EVP_CIPHER* ciph;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    INT alg = getOption(hAlgorithmComboBox);
    INT mode = getOption(hModeComboBox);
    INT pad = getOption(hPaddingComboBox);
    INT infmt = getOption(hInformatComboBox);
    INT outfmt = getOption(hOutformatComboBox);
    VOID* key = getText(hKeyEditBox);
    VOID* iv = getText(hIVEditBox);
    VOID* in = getText(hInputEditBox);
    VOID* out = NULL;
    INT keyl;
    INT ivl;
    INT inl;
    INT outl;
    INT tmpl;

#define __SELECT_CIPHER_BY_MODE(name) \
        switch (mode) { \
        case MODE_ECB: ciph = EVP_##name##_ecb(); ivl = 0; /* ignore input IV */ break; \
        case MODE_CBC: ciph = EVP_##name##_cbc(); break; \
        case MODE_CFB: ciph = EVP_##name##_cfb(); break; \
        case MODE_OFB: ciph = EVP_##name##_ofb(); break; \
        case MODE_CTR: ciph = EVP_##name##_ctr(); break; \
        default: \
            WARN(hWnd, _T("Invalid MODE %d"), mode); \
            goto cleanup; \
        }

#define __SELECT_CIPHER_BY_MODE_NOCTR(name, notify) \
        switch (mode) { \
        case MODE_ECB: ciph = EVP_##name##_ecb(); ivl = 0; /* ignore input IV */ break; \
        case MODE_CBC: ciph = EVP_##name##_cbc(); break; \
        case MODE_CFB: ciph = EVP_##name##_cfb(); break; \
        case MODE_OFB: ciph = EVP_##name##_ofb(); break; \
        case MODE_CTR: \
            WARN(hWnd, _T(#notify"-CTR is not supported")); \
            goto cleanup; \
        default: \
            WARN(hWnd, _T("Invalid MODE %d"), mode); \
            goto cleanup; \
        }

#define __SELECT_CIPHER_BY_KEYL(name) \
        switch (keyl) { \
        case 128 / 8: \
            __SELECT_CIPHER_BY_MODE(name##_128) \
            break; \
        case 192 / 8: \
            __SELECT_CIPHER_BY_MODE(name##_192) \
            break; \
        case 256 / 8: \
            __SELECT_CIPHER_BY_MODE(name##_256) \
            break; \
        default: \
            WARN(hWnd, _T("KEY length should be 128/192/256 bits")); \
            goto cleanup; \
        }

    if (TrimSpace(key))
        SetWindowText(hKeyEditBox, key);
    keyl = HexCharsToBinary(key);
    if (keyl < 0) {
        WARN(hWnd, _T("KEY is not a HEX string"));
        goto cleanup;
    }

    if (TrimSpace(iv))
        SetWindowText(hIVEditBox, iv);
    ivl = HexCharsToBinary(iv);
    if (ivl < 0) {
        WARN(hWnd, _T("IV is not a HEX string"));
        goto cleanup;
    }

    switch (alg) {
    case ALG_AES:
        __SELECT_CIPHER_BY_KEYL(aes)
        break;
    case ALG_ARIA:
        __SELECT_CIPHER_BY_KEYL(aria)
        break;
    case ALG_BLOWFISH:
        __SELECT_CIPHER_BY_MODE_NOCTR(bf, BLOWFISH)
        break;
    case ALG_CAMELLIA:
        __SELECT_CIPHER_BY_KEYL(camellia)
        break;
    case ALG_CAST:
        __SELECT_CIPHER_BY_MODE_NOCTR(cast5, CAST5)
        break;
    case ALG_CHACHA:
        if (mode != MODE_CTR) {
            WARN(hWnd, _T("CHACHA20 only supports CTR mode"));
            goto cleanup;
        }
        ciph = EVP_chacha20();
        break;
    case ALG_IDEA:
        __SELECT_CIPHER_BY_MODE_NOCTR(idea, IDEA)
        break;
    case ALG_SEED:
        __SELECT_CIPHER_BY_MODE_NOCTR(seed, SEED)
        break;
    case ALG_SM4:
        __SELECT_CIPHER_BY_MODE(sm4)
        break;
    default:
        WARN(hWnd, _T("Invalid ALGORITHM"));
        goto cleanup;
    }

    if (keyl != EVP_CIPHER_key_length(ciph)) {
        WARN(hWnd, _T("KEY length should be %d bits"), EVP_CIPHER_key_length(ciph) * 8);
        goto cleanup;
    }
    if (ivl != EVP_CIPHER_iv_length(ciph)) {
        WARN(hWnd, _T("IV length should be %d bits"), EVP_CIPHER_iv_length(ciph) * 8);
        goto cleanup;
    }

    if (!EVP_CipherInit(ctx, ciph, key, ivl > 0 ? iv : NULL, !isDec)) {
        WARN(hWnd, _T("EVP_CipherInit failed"));
        goto cleanup;
    }

    switch (pad) {
    case PAD_NONE:
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        break;
    case PAD_PKCS:
        // EVP_CIPHER_CTX_set_padding(ctx, 1); /* padding is ON by default. */
        break;
    default:
        WARN(hWnd, _T("Invalid PADDING"));
        goto cleanup;
    }

    switch (infmt) {
    case IFMT_HEX:
        if (TrimSpace(in))
            SetWindowText(hInputEditBox, in);
        inl = HexCharsToBinary(in);
        if (inl < 0) {
            WARN(hWnd, _T("INPUT is not a HEX string"));
            goto cleanup;
        }
        break;
    case IFMT_BASE64:
        if (TrimSpace(in))
            SetWindowText(hInputEditBox, in);
        inl = Base64CharsToBinary(in);
        if (inl < 0) {
            WARN(hWnd, _T("INPUT is not a BASE64 string"));
            goto cleanup;
        }
        break;
    case IFMT_FILE: 
        if (outfmt != OFMT_FILE) {
            TCHAR* _in;
            inl = MAX_INFILE_SIZE;
            _in = ReadFileOnce(in, (UINT*) &inl);
            if (!_in) {
                WARN(hWnd, _T("file [%s] does not exist or > %uKB when OUT-FORMAT is not a FILE"),
                    trimFilePath(in, 32), MAX_INFILE_SIZE / 1024);
                goto cleanup;
            }
            free(in);
            in = _in;
            break;
        }
        /* outfmt == OFMT_FILE, start crypt file int the thread. */
        if (hCryptThread) {
            WARN(hWnd, _T("crypt thread already running"));
            goto cleanup;
        }
        out = getText(hOutputEditBox);

        if (IsFile(out) && CONFIRM(hWnd,
                _T("OUTPUT file will be overwrite, continue?")) != IDOK)
            goto cleanup;

        cryptThreadParams.hMainWnd = hWnd;
        cryptThreadParams.ciphCtx = ctx;
        cryptThreadParams.inPath = in;
        cryptThreadParams.outPath = out;
        if (isDec) {
            /* input file size needs to be a multiple of block size when MODE is ECB/CBC. */
            cryptThreadParams.needChkSize = isPaddingNeeded(mode);
        } else {
            /* input file size needs to be a multiple of block size when MODE is ECB/CBC and padding is OFF. */
            cryptThreadParams.needChkSize = isPaddingNeeded(mode) && pad == PAD_NONE;
        }

        hCryptThread = CreateThread(NULL, 0, doCryptFile, NULL, 0, NULL);
        if (!hCryptThread) {
            WARN(hWnd, _T("create crypt thread failed"));
            goto cleanup;
        }
        free(key);
        free(iv);
        ShowWindow(hCryptProgressBar, SW_SHOW);
        /* something else is freed in crypt thread */
        return;
    case IFMT_C_ARRAY:
        if (TrimSpace(in))
            SetWindowText(hInputEditBox, in);
        inl = CArrayCharsToBinary(in);
        if (inl < 0) {
            WARN(hWnd, _T("INPUT is not a C-ARRAY string"));
            goto cleanup;
        }
        break;
    case IFMT_C_STRING:
        if (TrimSpace(in))
            SetWindowText(hInputEditBox, in);
        inl = CStringCharsToBinary(in);
        if (inl < 0) {
            WARN(hWnd, _T("INPUT is not a C-STRING string"));
            goto cleanup;
        }
        break;
    default:
        WARN(hWnd, _T("Invalid IN-FORMAT"));
        goto cleanup;
    }
    formatTextTo(hInputStaticText, _T("INPUT %d"), inl);

    out = malloc(inl + EVP_CIPHER_block_size(ciph));

    if (!EVP_CipherUpdate(ctx, out, &outl, in, inl)) {
        WARN(hWnd, _T("EVP_CipherUpdate failed, code 0x%08X"), ERR_get_error());
        goto cleanup;
    }
    if (!EVP_CipherFinal(ctx, (UCHAR*) out + outl, &tmpl)) {
        WARN(hWnd, _T("EVP_CipherFinal failed (INPUT error), code 0x%08X"), ERR_get_error());
        goto cleanup;
    }
    outl += tmpl;
    formatTextTo(hOutputStaticText, _T("OUTPUT %d"), outl);

    switch (outfmt) {
    case OFMT_HEX:
        out = BinaryToHexChars(out, outl);
        SetWindowText(hOutputEditBox, out);
        break;
    case OFMT_BASE64:
        out = BinaryToBase64Chars(out, outl);
        SetWindowText(hOutputEditBox, out);
        break;
    case OFMT_FILE: {
            TCHAR* path = getText(hOutputEditBox);

            if (IsFile(path) && CONFIRM(hWnd,
                    _T("OUTPUT file will be overwrite, continue?")) != IDOK) {
                free(path);
                goto cleanup;
            }
            if (WriteFileOnce(path, out, outl))
                INFO(hWnd, _T("Write output to [%s] done"), trimFilePath(path, 32));
            else
                WARN(hWnd, _T("Write output to [%s] failed"), trimFilePath(path, 32));
            free(path);
        }
        break;
    case OFMT_C_ARRAY:
        out = BinaryToCArrayChars(out, outl);
        SetWindowText(hOutputEditBox, out);
        break;
    case OFMT_C_STRING:
        out = BinaryToCStringChars(out, outl);
        SetWindowText(hOutputEditBox, out);
        break;
    default:
        WARN(hWnd, _T("Invalid OUT-FORMAT"));
        goto cleanup;
    }

cleanup:
    free(key);
    free(iv);
    free(in);
    free(out);
    EVP_CIPHER_CTX_free(ctx);
#undef __SELECT_CIPHER_BY_KEYL
#undef __SELECT_CIPHER_BY_MODE_NOCTR
#undef __SELECT_CIPHER_BY_MODE
}

static void onEncryptClicked(HWND hWnd)
{
    doCrypt(hWnd, FALSE);
}

static void onDecryptClicked(HWND hWnd)
{
    doCrypt(hWnd, TRUE);
}

static int onConfigItem(void* user, const char* section,
                           const char* name, const char* value)
{
    UINT i;
#define __SELECT_OPTION(items, hbox) \
        for (i = 0; i < ARRAYSIZE(items); ++i) { \
            if (!lstrcmp(value, items[i])) { \
                SendMessage(hbox, CB_SETCURSEL, i, 0); \
                break; \
            } \
        }

    if (lstrcmp(section, _T("main"))) {
        /* NOOP */
    } else if (!lstrcmp(name, _T("ALGRITHM"))) {
        __SELECT_OPTION(algorithmItems, hAlgorithmComboBox);
    } else if (!lstrcmp(name, _T("MODE"))) {
        __SELECT_OPTION(modeItems, hModeComboBox);
    } else if (!lstrcmp(name, _T("PADDING"))) {
        __SELECT_OPTION(paddingItems, hPaddingComboBox);
    } else if (!lstrcmp(name, _T("IN-FORMAT"))) {
        __SELECT_OPTION(informatItems, hInformatComboBox);
    } else if (!lstrcmp(name, _T("OUT-FORMAT"))) {
        __SELECT_OPTION(outformatItems, hOutformatComboBox);
    } else if (!lstrcmp(name, _T("KEY"))) {
        SetWindowText(hKeyEditBox, value);
    } else if (!lstrcmp(name, _T("IV"))) {
        SetWindowText(hIVEditBox, value);
    } else if (!lstrcmp(name, _T("INPUT"))) {
        SetWindowText(hInputEditBox, value);
    } else if (!lstrcmp(name, _T("OUTPUT"))) {
        SetWindowText(hOutputEditBox, value);
    }

#undef __SELECT_OPTION
    return 1;
}

static void resizeControls(HWND hWnd)
{
    RECT wRect; /* window rect */
    RECT cRect;	/* client rect */
    LONG w = WND_ALIGN;
    LONG h = WND_ALIGN;

    MoveWindow(hAlgorithmStaticText, w, h, WND_COMBOXW, WND_LINEH, FALSE);
    MoveWindow(hAlgorithmComboBox, w, h + WND_LINEH, WND_COMBOXW, WND_LINEH, FALSE);
    w += WND_COMBOXW + WND_ALIGN;
    MoveWindow(hModeStaticText, w, h, WND_COMBOXW, WND_LINEH, FALSE);
    MoveWindow(hModeComboBox, w, h + WND_LINEH, WND_COMBOXW, WND_LINEH, FALSE);
    w += WND_COMBOXW + WND_ALIGN;
    MoveWindow(hPaddingStaticText, w, h, WND_COMBOXW, WND_LINEH, FALSE);
    MoveWindow(hPaddingComboBox, w, h + WND_LINEH, WND_COMBOXW, WND_LINEH, FALSE);
    w += WND_COMBOXW + WND_ALIGN;
    MoveWindow(hInformatStaticText, w, h, WND_COMBOXW, WND_LINEH, FALSE);
    MoveWindow(hInformatComboBox, w, h + WND_LINEH, WND_COMBOXW, WND_LINEH, FALSE);
    w += WND_COMBOXW + WND_ALIGN;
    MoveWindow(hOutformatStaticText, w, h, WND_COMBOXW, WND_LINEH, FALSE);
    MoveWindow(hOutformatComboBox, w, h + WND_LINEH, WND_COMBOXW, WND_LINEH, FALSE);
    w += WND_COMBOXW + WND_ALIGN;

    h += WND_LINEH + WND_LINEH + WND_ALIGN;

    MoveWindow(hKeyStaticText, WND_ALIGN, h, w - WND_ALIGN * 2, WND_LINEH, FALSE);
    h += WND_LINEH;
    MoveWindow(hKeyEditBox, WND_ALIGN, h, w - WND_ALIGN * 2, WND_LINEH, FALSE);
    h += WND_LINEH + WND_ALIGN;

    MoveWindow(hIVStaticText, WND_ALIGN, h, w - WND_ALIGN * 2, WND_LINEH, FALSE);
    h += WND_LINEH;
    MoveWindow(hIVEditBox, WND_ALIGN, h, w - WND_ALIGN * 2, WND_LINEH, FALSE);
    h += WND_LINEH + WND_ALIGN;

    MoveWindow(hInputStaticText, WND_ALIGN, h, w - WND_ALIGN * 2, WND_LINEH, FALSE);
    h += WND_LINEH;
    MoveWindow(hInputEditBox, WND_ALIGN, h, w - WND_ALIGN * 2, WND_LINEH * 5, FALSE);
    h += WND_LINEH * 5 + WND_ALIGN;

    MoveWindow(hOutputStaticText, WND_ALIGN, h, w / 2 - WND_ALIGN, WND_LINEH, FALSE);
    h += WND_LINEH;
    MoveWindow(hOutputEditBox, WND_ALIGN, h, w - WND_ALIGN * 2, WND_LINEH * 5, FALSE);
    h += WND_LINEH * 5 + WND_ALIGN;

    MoveWindow(hCryptProgressBar, WND_ALIGN, h, w / 2 - WND_BUTTONW - WND_ALIGN / 2 - WND_ALIGN * 2, WND_LINEH, FALSE);
    MoveWindow(hEncryptButton, w / 2 - WND_BUTTONW - WND_ALIGN / 2, h, WND_BUTTONW, WND_LINEH, FALSE);
    MoveWindow(hDecryptButton, w / 2 + WND_ALIGN / 2, h, WND_BUTTONW, WND_LINEH, FALSE);
    h += WND_LINEH + WND_ALIGN;

    GetWindowRect(hWnd, &wRect);
    GetClientRect(hWnd, &cRect);

    w += cRect.left - wRect.left + wRect.right - cRect.right;
    h += cRect.top - wRect.top + wRect.bottom - cRect.bottom;

    /* move to center of the screen */
    MoveWindow(hWnd, (GetSystemMetrics(SM_CXSCREEN) - w) / 2,
        (GetSystemMetrics(SM_CYSCREEN) - h) / 2, w, h, TRUE);
}

static void onWindowCreate(HWND hWnd)
{
    INT i;

    hAlgorithmStaticText = CreateWindow(_T("STATIC"), _T("ALGORITHM"),
                            WS_CHILD | WS_VISIBLE | SS_LEFT,
                            0, 0, 0, 0,
                            hWnd, NULL, NULL, NULL);
    hAlgorithmComboBox = CreateWindow(_T("COMBOBOX"), NULL,
                            WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWNLIST,
                            0, 0, 0, 0,
                            hWnd, (HMENU) WM_MAIN_ALGORITHM, NULL, NULL);
    hModeStaticText = CreateWindow(_T("STATIC"), _T("MODE"),
                            WS_CHILD | WS_VISIBLE | SS_LEFT,
                            0, 0, 0, 0,
                            hWnd, NULL, NULL, NULL);
    hModeComboBox = CreateWindow(_T("COMBOBOX"), NULL,
                            WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWNLIST,
                            0, 0, 0, 0,
                            hWnd, (HMENU) WM_MAIN_MODE, NULL, NULL);
    hPaddingStaticText = CreateWindow(_T("STATIC"), _T("PADDING"),
                            WS_CHILD | WS_VISIBLE | SS_LEFT,
                            0, 0, 0, 0,
                            hWnd, NULL, NULL, NULL);
    hPaddingComboBox = CreateWindow(_T("COMBOBOX"), NULL,
                            WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWNLIST,
                            0, 0, 0, 0,
                            hWnd, NULL, NULL, NULL);
    hInformatStaticText = CreateWindow(_T("STATIC"), _T("IN-FORMAT"),
                            WS_CHILD | WS_VISIBLE | SS_LEFT,
                            0, 0, 0, 0,
                            hWnd, NULL, NULL, NULL);
    hInformatComboBox = CreateWindow(_T("COMBOBOX"), NULL,
                            WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWNLIST,
                            0, 0, 0, 0,
                            hWnd, NULL, NULL, NULL);
    hOutformatStaticText = CreateWindow(_T("STATIC"), _T("OUT-FORMAT"),
                            WS_CHILD | WS_VISIBLE | SS_LEFT,
                            0, 0, 0, 0,
                            hWnd, NULL, NULL, NULL);
    hOutformatComboBox = CreateWindow(_T("COMBOBOX"), NULL,
                            WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWNLIST,
                            0, 0, 0, 0,
                            hWnd, NULL, NULL, NULL);

    hKeyStaticText = CreateWindow(_T("STATIC"), _T("KEY <HEX>"),
                            WS_CHILD | WS_VISIBLE | SS_LEFT,
                            0, 0, 0, 0,
                            hWnd, NULL, NULL, NULL);
    hKeyEditBox = CreateWindow(_T("EDIT"), NULL,
                            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_AUTOHSCROLL,
                            0, 0, 0, 0,
                            hWnd, NULL, NULL, NULL);

    hIVStaticText = CreateWindow(_T("STATIC"), _T("IV <HEX>"),
                            WS_CHILD | WS_VISIBLE | SS_LEFT,
                            0, 0, 0, 0,
                            hWnd, NULL, NULL, NULL);
    hIVEditBox = CreateWindow(_T("EDIT"), NULL,
                            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_AUTOHSCROLL,
                            0, 0, 0, 0,
                            hWnd, NULL, NULL, NULL);

    hInputStaticText = CreateWindow(_T("STATIC"), _T("INPUT"),
                            WS_CHILD | WS_VISIBLE | SS_LEFT,
                            0, 0, 0, 0,
                            hWnd, NULL, NULL, NULL);
    hInputEditBox = CreateWindow(_T("EDIT"), NULL,
                            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_LEFT | ES_AUTOVSCROLL | ES_MULTILINE,
                            0, 0, 0, 0,
                            hWnd, NULL, NULL, NULL);

    hOutputStaticText = CreateWindow(_T("STATIC"), _T("OUTPUT"),
                            WS_CHILD | WS_VISIBLE | SS_LEFT,
                            0, 0, 0, 0,
                            hWnd, NULL, NULL, NULL);
    hOutputEditBox = CreateWindow(_T("EDIT"), NULL,
                            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_LEFT | ES_AUTOVSCROLL | ES_MULTILINE/*  | ES_READONLY */,
                            0, 0, 0, 0,
                            hWnd, NULL, NULL, NULL);

    hEncryptButton = CreateWindow(_T("BUTTON"), _T("ENCRYPT"),
                            WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
		                    0, 0, 0, 0,
                            hWnd, (HMENU) WM_MAIN_ENCRYPT, NULL, NULL);
    hDecryptButton = CreateWindow(_T("BUTTON"), _T("DECRYPT"),
                            WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
		                    0, 0, 0, 0,
                            hWnd, (HMENU) WM_MAIN_DECRYPT, NULL, NULL);

    hCryptProgressBar = CreateWindow(PROGRESS_CLASS, NULL,
                            /* WS_VISIBLE |  */WS_CHILD | PBS_SMOOTH,
		                    0, 0, 0, 0,
                            hWnd, NULL, NULL, NULL);

    hDefaultFont = CreateFont(WND_FONTSIZE, 0, 0, 0,
                            FW_NORMAL, 0, 0, 0,
                            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                            DEFAULT_QUALITY, DEFAULT_PITCH,
                            WND_FONTNAME);

    SendMessage(hAlgorithmStaticText, WM_SETFONT, (WPARAM) hDefaultFont, TRUE);
    SendMessage(hAlgorithmComboBox, WM_SETFONT, (WPARAM) hDefaultFont, TRUE);
    SendMessage(hModeStaticText, WM_SETFONT, (WPARAM) hDefaultFont, TRUE);
    SendMessage(hModeComboBox, WM_SETFONT, (WPARAM) hDefaultFont, TRUE);
    SendMessage(hPaddingStaticText, WM_SETFONT, (WPARAM) hDefaultFont, TRUE);
    SendMessage(hPaddingComboBox, WM_SETFONT, (WPARAM) hDefaultFont, TRUE);
    SendMessage(hInformatStaticText, WM_SETFONT, (WPARAM) hDefaultFont, TRUE);
    SendMessage(hInformatComboBox, WM_SETFONT, (WPARAM) hDefaultFont, TRUE);
    SendMessage(hOutformatStaticText, WM_SETFONT, (WPARAM) hDefaultFont, TRUE);
    SendMessage(hOutformatComboBox, WM_SETFONT, (WPARAM) hDefaultFont, TRUE);

    SendMessage(hKeyStaticText, WM_SETFONT, (WPARAM) hDefaultFont, TRUE);
    SendMessage(hKeyEditBox, WM_SETFONT, (WPARAM) hDefaultFont, TRUE);
    SendMessage(hIVStaticText, WM_SETFONT, (WPARAM) hDefaultFont, TRUE);
    SendMessage(hIVEditBox, WM_SETFONT, (WPARAM) hDefaultFont, TRUE);
    SendMessage(hInputStaticText, WM_SETFONT, (WPARAM) hDefaultFont, TRUE);
    SendMessage(hInputEditBox, WM_SETFONT, (WPARAM) hDefaultFont, TRUE);
    SendMessage(hOutputStaticText, WM_SETFONT, (WPARAM) hDefaultFont, TRUE);
    SendMessage(hOutputEditBox, WM_SETFONT, (WPARAM) hDefaultFont, TRUE);

    SendMessage(hInputEditBox, EM_SETLIMITTEXT, (WPARAM) (MAX_INFILE_SIZE * 5), 0);
    SendMessage(hOutputEditBox, EM_SETLIMITTEXT, (WPARAM) (MAX_INFILE_SIZE * 5), 0);

    SendMessage(hEncryptButton, WM_SETFONT, (WPARAM) hDefaultFont, TRUE);
    SendMessage(hDecryptButton, WM_SETFONT, (WPARAM) hDefaultFont, TRUE);

    for (i = 0; i < ARRAYSIZE(algorithmItems); ++i)
        SendMessage(hAlgorithmComboBox, CB_ADDSTRING, 0, (LPARAM) algorithmItems[i]);
	SendMessage(hAlgorithmComboBox, CB_SETCURSEL, ALG_AES, 0);
    for (i = 0; i < ARRAYSIZE(modeItems); ++i)
        SendMessage(hModeComboBox, CB_ADDSTRING, 0, (LPARAM) modeItems[i]);
    SendMessage(hModeComboBox, CB_SETCURSEL, MODE_CBC, 0);
    for (i = 0; i < ARRAYSIZE(paddingItems); ++i)
        SendMessage(hPaddingComboBox, CB_ADDSTRING, 0, (LPARAM) paddingItems[i]);
	SendMessage(hPaddingComboBox, CB_SETCURSEL, PAD_NONE, 0);
    for (i = 0; i < ARRAYSIZE(informatItems); ++i)
        SendMessage(hInformatComboBox, CB_ADDSTRING, 0, (LPARAM) informatItems[i]);
	SendMessage(hInformatComboBox, CB_SETCURSEL, IFMT_HEX, 0);
    for (i = 0; i < ARRAYSIZE(outformatItems); ++i)
        SendMessage(hOutformatComboBox, CB_ADDSTRING, 0, (LPARAM) outformatItems[i]);
	SendMessage(hOutformatComboBox, CB_SETCURSEL, OFMT_HEX, 0);

    resizeControls(hWnd);

    ini_parse(CONFIG_FILENAME, onConfigItem, NULL);

    i = getOption(hModeComboBox);
    EnableWindow(hPaddingComboBox, isPaddingNeeded(i));
    EnableWindow(hIVEditBox, isIVNeeded(i));
}

static void onWindowDestroy(HWND hWnd)
{
    DeleteObject(hDefaultFont);
}

static LRESULT CALLBACK WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg) {
    case WM_DROPFILES:
        onDropFiles(hWnd, (HDROP)wParam);
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case WM_MAIN_ALGORITHM:
            if (HIWORD(wParam) == CBN_SELCHANGE)
                onAlgorithmChanged(hWnd);
            break;
        case WM_MAIN_MODE:
            if (HIWORD(wParam) == CBN_SELCHANGE)
                onModeChanged(hWnd);
            break;
        case WM_MAIN_ENCRYPT:
            onEncryptClicked(hWnd);
            break;
        case WM_MAIN_DECRYPT:
            onDecryptClicked(hWnd);
            break;
        case WM_MAIN_THREAD:
            onCryptThreadDone(hWnd);
            break;
        }
        return 0;

    case WM_KEYDOWN:
        switch (wParam) {
        case VK_ESCAPE:
            SendMessage(hWnd, WM_CLOSE, 0, 0);
            break;
        }
        return 0;

    // case WM_SIZE:
    //     onWindowResize(LOWORD(lParam), HIWORD(lParam));
    //     return 0;

    case WM_CREATE:
        onWindowCreate(hWnd);
        return 0;

    case WM_CLOSE:
        if (hCryptThread && CONFIRM(hWnd,
                _T("crypt thread running, exit?")) != IDOK)
            return 0;
        DestroyWindow(hWnd);
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
    WNDCLASSEX wcex;
    HWND hWnd;
    MSG msg;

    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH) COLOR_WINDOW;
    wcex.lpszMenuName = NULL;
    wcex.lpszClassName = WND_CLASSNAME;
    wcex.hIconSm = LoadIcon(NULL, IDI_APPLICATION);

    if (!RegisterClassEx(&wcex))
        return 0;

    if (!(hWnd = CreateWindowEx(WS_EX_ACCEPTFILES,
                    WND_CLASSNAME,
                    WND_TITLE,
                    WS_SYSMENU | WS_MINIMIZEBOX,
                    0, 0, 0, 0,
                    NULL,
                    NULL,
                    hInstance,
                    NULL)))
        return 0;

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}
