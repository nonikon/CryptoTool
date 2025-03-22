#include <openssl/evp.h>
#include <openssl/err.h>

#include "mainWindow.h"
#include "encode.h"

#define WND_CLASSNAME       _T("SymmWindowClass")

#define WM_USER_ENCRYPT     (WM_USER + 1)
#define WM_USER_DECRYPT     (WM_USER + 2)
#define WM_USER_ALGORITHM   (WM_USER + 3)
#define WM_USER_MODE        (WM_USER + 4)
#define WM_USER_THREAD      (WM_USER + 5)

typedef struct stCryptThreadParams {
    /* IN */
    HWND hWnd;
    EVP_CIPHER_CTX* ciphCtx;
    TCHAR* inPath;
    TCHAR* outPath;
    BOOL needChkSize;
    /* OUT */
    BOOL isSucc;
    TCHAR errorMsg[256];
    LARGE_INTEGER inLen;
    LARGE_INTEGER outLen;
    DWORD time;
} CryptThreadParams;

static HANDLE hCryptThread;
static CryptThreadParams cryptThreadParams;
static BOOL bCryptThreadCanceled;

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
static HWND hKeyformatStaticText;
static HWND hKeyformatComboBox;
static HWND hKeyStaticText;
static HWND hKeyEditBox;
static HWND hIVformatStaticText;
static HWND hIVformatComboBox;
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
    _T("AES"), _T("ARIA"), _T("BLOWFISH"), _T("CAMELLIA"), _T("CAST5"), _T("CHACHA20"), _T("DES"), _T("DESEDE3"),
    _T("IDEA"), _T("RC2"), _T("RC4"), _T("RC5"), _T("SEED"), _T("SM4"),
};
enum {
    ALG_AES, ALG_ARIA, ALG_BLOWFISH, ALG_CAMELLIA, ALG_CAST5, ALG_CHACHA20, ALG_DES, ALG_DESEDE3,
    ALG_IDEA, ALG_RC2, ALG_RC4, ALG_RC5, ALG_SEED, ALG_SM4,
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
    _T("BASE64"), _T("C-ARRAY"), _T("C-STRING"), _T("FILE"), _T("HEX"), _T("TEXT"),
};
enum {
    IFMT_BASE64, IFMT_C_ARRAY, IFMT_C_STRING, IFMT_FILE, IFMT_HEX, IFMT_TEXT,
};
static CONST TCHAR* outformatItems[] = {
    _T("BASE64"), _T("C-ARRAY"), _T("C-STRING"), _T("FILE"), _T("HEX"), _T("TEXT"),
};
enum {
    OFMT_BASE64, OFMT_C_ARRAY, OFMT_C_STRING, OFMT_FILE, OFMT_HEX, OFMT_TEXT,
};
static CONST TCHAR* kvformatItems[] = {
    _T("BASE64"), _T("C-ARRAY"), _T("C-STRING"), _T("HEX"),
};
enum {
    KVFMT_BASE64, KVFMT_C_ARRAY, KVFMT_C_STRING, KVFMT_HEX,
};


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
        SETCBOPT(hInformatComboBox, IFMT_FILE);
        SETCBOPT(hOutformatComboBox, OFMT_FILE);
    }

    DragFinish(hDrop);
    free(buf);
}

static BOOL isModeNeeded(INT alg)
{
    switch (alg) {
    case ALG_CHACHA20:
    case ALG_RC4:
        return FALSE;
    default:
        return TRUE;
    }
}
static BOOL isPaddingNeeded(INT alg, INT mode)
{
    switch (alg) {
    case ALG_CHACHA20:
    case ALG_RC4:
        return FALSE;
    default:
        break;
    }
    switch (mode) {
    case MODE_ECB:
    case MODE_CBC:
        return TRUE;
    default:
        return FALSE;
    }
}
static BOOL isIVNeeded(INT alg, INT mode)
{
    switch (alg) {
    case ALG_CHACHA20:
        return TRUE;
    case ALG_RC4:
        return FALSE;
    default:
        break;
    }
    switch (mode) {
    case MODE_ECB:
        return FALSE;
    default:
        return TRUE;
    }
}

static void onAlgorithmOrModeChanged(HWND hWnd)
{
    INT alg = GETCBOPT(hAlgorithmComboBox);
    INT mode = GETCBOPT(hModeComboBox);
    BOOL ivneeded = isIVNeeded(alg, mode);

    EnableWindow(hModeComboBox, isModeNeeded(alg));
    EnableWindow(hPaddingComboBox, isPaddingNeeded(alg, mode));
    EnableWindow(hIVEditBox, ivneeded);
    EnableWindow(hIVformatComboBox, ivneeded);
}

static DWORD doCryptFile(VOID* arg)
{
    CryptThreadParams* params = arg;
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
    int outl;

    params->isSucc = FALSE;
    params->inLen.QuadPart = 0;
    params->outLen.QuadPart = 0;
    beginTickCnt = GetTickCount();

    hIn = CreateFile(params->inPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hIn == INVALID_HANDLE_VALUE) {
        wsprintf(params->errorMsg, _T("open INPUT file [%s] failed"), TRIMPATH(params->inPath));
        goto done;
    }
    if (!GetFileSizeEx(hIn, &params->inLen)) {
        wsprintf(params->errorMsg, _T("get INPUT file size [%s] failed"), TRIMPATH(params->inPath));
        goto done;
    }
    if (params->needChkSize && params->inLen.QuadPart % EVP_CIPHER_CTX_block_size(params->ciphCtx) != 0) {
        wsprintf(params->errorMsg, _T("INPUT file size is not a multiple of %d"),
            EVP_CIPHER_CTX_block_size(params->ciphCtx));
        goto done;
    }

    hOut = CreateFile(params->outPath, GENERIC_WRITE, 0, NULL,
                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) {
        wsprintf(params->errorMsg, _T("open OUTPUT file [%s] failed"), TRIMPATH(params->outPath));
        goto done;
    }

    current.QuadPart = 0;
    rBuf = malloc(FILE_RBUF_SIZE);
    wBuf = malloc(FILE_RBUF_SIZE + EVP_MAX_BLOCK_LENGTH); /* big enough to store encrypt/decrypt result */

    while (1) {
        if (bCryptThreadCanceled) {
            wsprintf(params->errorMsg, _T("crypt thread canceled"));
            goto done;
        }
        ReadFile(hIn, rBuf, FILE_RBUF_SIZE, &nReadWrite, NULL);

        if (!nReadWrite) {
            if (!EVP_CipherFinal(params->ciphCtx, wBuf, &outl)) {
                wsprintf(params->errorMsg, _T("EVP_CipherFinal failed (INPUT error), code 0x%08X"), ERR_get_error());
                goto done;
            }
            if (outl && !WriteFile(hOut, wBuf, outl, &nReadWrite, NULL)) {
                wsprintf(params->errorMsg, _T("write to [%s] failed"), TRIMPATH(params->outPath));
                goto done;
            }
            params->outLen.QuadPart += outl;
            break;
        }
        current.QuadPart += nReadWrite;

        if (!EVP_CipherUpdate(params->ciphCtx, wBuf, &outl, rBuf, nReadWrite)) {
            wsprintf(params->errorMsg, _T("EVP_CipherUpdate failed, code 0x%08X"), ERR_get_error());
            goto done;
        }
        if (!WriteFile(hOut, wBuf, outl, &nReadWrite, NULL)) {
            wsprintf(params->errorMsg, _T("write to [%s] failed"), TRIMPATH(params->outPath));
            goto done;
        }
        params->outLen.QuadPart += outl;

        tempPercent = (current.QuadPart * 100 / params->inLen.QuadPart) & 0xFFFFFFFF;
        if (progressPercent != tempPercent) {
            PostMessage(hCryptProgressBar, PBM_SETPOS, (WPARAM) tempPercent, 0);
            progressPercent = tempPercent;
        }
    }

    endTickCnt = GetTickCount();
    params->isSucc = TRUE;
    params->time = endTickCnt - beginTickCnt;
done:
    CloseHandle(hIn);
    CloseHandle(hOut);
    free(rBuf);
    free(wBuf);
    PostMessage(params->hWnd, WM_COMMAND, (WPARAM) WM_USER_THREAD, (LPARAM) arg);
    return 0;
}
static void onCryptThreadDone(HWND hWnd, CryptThreadParams* params)
{
    WaitForSingleObject(hCryptThread, INFINITE);
    CloseHandle(hCryptThread);

    if (params->isSucc) {
        FormatTextTo(hInputStaticText, _T("INPUT %ld"), params->inLen.QuadPart);
        FormatTextTo(hOutputStaticText, _T("OUTPUT %ld (%u.%us)"), params->outLen.QuadPart,
            params->time / 1000, params->time % 1000);
    } else {
        WARN(params->errorMsg);
    }

    ShowWindow(hCryptProgressBar, SW_HIDE);
    SendMessage(hCryptProgressBar, PBM_SETPOS, 0, 0);

    free(params->inPath);
    free(params->outPath);
    EVP_CIPHER_CTX_free(params->ciphCtx);
    hCryptThread = NULL;
}

static void doCrypt(HWND hWnd, BOOL isDec)
{
    CONST EVP_CIPHER* ciph;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    INT alg = GETCBOPT(hAlgorithmComboBox);
    INT mode = GETCBOPT(hModeComboBox);
    INT pad = GETCBOPT(hPaddingComboBox);
    INT infmt = GETCBOPT(hInformatComboBox);
    INT outfmt = GETCBOPT(hOutformatComboBox);
    INT keyfmt = GETCBOPT(hKeyformatComboBox);
    INT ivfmt = GETCBOPT(hIVformatComboBox);
    VOID* key = GetTextOnce(hKeyEditBox);
    VOID* iv = GetTextOnce(hIVEditBox);
    VOID* in = GetTextOnce(hInputEditBox);
    VOID* out = NULL;
    TCHAR* outs = NULL;
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
            WARN(_T("Invalid MODE %d"), mode); \
            goto cleanup; \
        }

#define __SELECT_CIPHER_BY_MODE_NOCTR(name, notify) \
        switch (mode) { \
        case MODE_ECB: ciph = EVP_##name##_ecb(); ivl = 0; /* ignore input IV */ break; \
        case MODE_CBC: ciph = EVP_##name##_cbc(); break; \
        case MODE_CFB: ciph = EVP_##name##_cfb(); break; \
        case MODE_OFB: ciph = EVP_##name##_ofb(); break; \
        case MODE_CTR: \
            WARN(_T(#notify"-CTR is not supported")); \
            goto cleanup; \
        default: \
            WARN(_T("Invalid MODE %d"), mode); \
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
            WARN(_T("KEY length should be 128/192/256 bits")); \
            goto cleanup; \
        }

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

#define __CONVERT_KEY(func, notify) \
        if (TrimSpace(key)) \
            SetWindowText(hKeyEditBox, key); \
        keyl = func(key); \
        if (keyl <= 0) { \
            WARN(notify); \
            goto cleanup; \
        }

#define __CONVERT_IV(func, notify) \
        if (TrimSpace(iv)) \
            SetWindowText(hIVEditBox, iv); \
        ivl = func(iv); \
        if (ivl <= 0) { \
            WARN(notify); \
            goto cleanup; \
        }

    switch (keyfmt) {
    case KVFMT_HEX:
        __CONVERT_KEY(HexCharsToBinary, _T("KEY is not a HEX string"))
        break;
    case KVFMT_BASE64:
        __CONVERT_KEY(Base64CharsToBinary, _T("KEY is not a BASE64 string"))
        break;
    case IFMT_C_ARRAY:
        __CONVERT_KEY(CArrayCharsToBinary, _T("KEY is not a C-ARRAY string"));
        break;
    case IFMT_C_STRING:
        __CONVERT_KEY(CStringCharsToBinary, _T("KEY is not a C-STRING string"));
        break;
    default:
        WARN(_T("Invalid KEY-FORMAT"));
        goto cleanup;
    }

    switch (ivfmt) {
    case KVFMT_HEX:
        __CONVERT_IV(HexCharsToBinary, _T("IV is not a HEX string"))
        break;
    case KVFMT_BASE64:
        __CONVERT_IV(Base64CharsToBinary, _T("IV is not a BASE64 string"))
        break;
    case IFMT_C_ARRAY:
        __CONVERT_IV(CArrayCharsToBinary, _T("IV is not a C-ARRAY string"));
        break;
    case IFMT_C_STRING:
        __CONVERT_IV(CStringCharsToBinary, _T("IV is not a C-STRING string"));
        break;
    default:
        WARN(_T("Invalid IV-FORMAT"));
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
    case ALG_CAST5:
        __SELECT_CIPHER_BY_MODE_NOCTR(cast5, CAST5)
        break;
    case ALG_CHACHA20:
        ciph = EVP_chacha20();
        break;
    case ALG_DES: // DES with 8 bytes key length
        __SELECT_CIPHER_BY_MODE_NOCTR(des, DES);
        break;
    case ALG_DESEDE3: // DESede (Triple-DES) with triple (3*8 bytes) key length
        __SELECT_CIPHER_BY_MODE_NOCTR(des_ede3, DESEDE3);
        break;
    case ALG_IDEA:
        __SELECT_CIPHER_BY_MODE_NOCTR(idea, IDEA)
        break;
    case ALG_RC2:
        __SELECT_CIPHER_BY_MODE_NOCTR(rc2, RC2);
        break;
    case ALG_RC4:
        switch (keyl) {
        case 128 / 8: ciph = EVP_rc4(); break;
        case 40  / 8: ciph = EVP_rc4_40(); break;
        default:
            WARN(_T("RC4 KEY length only supports 40/128 bits"));
            goto cleanup;
        }
        ivl = 0; /* ignore input IV */
        break;
    case ALG_RC5: // rc5_32_12_16: 32 bits word size, 12 rounds, 16 bytes key length. And 64 bits block size
        __SELECT_CIPHER_BY_MODE_NOCTR(rc5_32_12_16, RC5);
        break;
    case ALG_SEED:
        __SELECT_CIPHER_BY_MODE_NOCTR(seed, SEED)
        break;
    case ALG_SM4:
        __SELECT_CIPHER_BY_MODE(sm4)
        break;
    default:
        WARN(_T("Invalid ALGORITHM"));
        goto cleanup;
    }

    if (keyl != EVP_CIPHER_key_length(ciph)) {
        WARN(_T("KEY length should be %d bits"), EVP_CIPHER_key_length(ciph) * 8);
        goto cleanup;
    }
    if (ivl != EVP_CIPHER_iv_length(ciph)) {
        WARN(_T("IV length should be %d bits"), EVP_CIPHER_iv_length(ciph) * 8);
        goto cleanup;
    }

    if (!EVP_CipherInit(ctx, ciph, key, ivl > 0 ? iv : NULL, !isDec)) {
        WARN(_T("EVP_CipherInit failed"));
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
        WARN(_T("Invalid PADDING"));
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
        __CONVERT_INPUT_NOTRIM(TextCharsToBinary, _T("INPUT is not a TEXT string"));
        break;
    case IFMT_FILE:
        if (outfmt != OFMT_FILE) {
            TCHAR* _in;
            inl = MAX_INFILE_SIZE;
            _in = ReadFileOnce(in, (UINT*) &inl);
            if (!_in) {
                WARN(_T("file [%s] does not exist or > %uKB when OUT-FORMAT is not a FILE"),
                    TRIMPATH(in), MAX_INFILE_SIZE / 1024);
                goto cleanup;
            }
            free(in);
            in = _in;
            break;
        }
        /* outfmt == OFMT_FILE, start crypt file int the thread. */
        if (hCryptThread) {
            WARN(_T("crypt thread already running"));
            goto cleanup;
        }
        outs = GetTextOnce(hOutputEditBox);

        if (IsFile(outs) && CONFIRM(_T("OUTPUT file will be overwrite, continue?")) != IDOK)
            goto cleanup;

        cryptThreadParams.hWnd = hWnd;
        cryptThreadParams.ciphCtx = ctx;
        cryptThreadParams.inPath = in;
        cryptThreadParams.outPath = outs;
        if (isDec) {
            /* input file size needs to be a multiple of block size when MODE is ECB/CBC. */
            cryptThreadParams.needChkSize = isPaddingNeeded(alg, mode);
        } else {
            /* input file size needs to be a multiple of block size when MODE is ECB/CBC and padding is OFF. */
            cryptThreadParams.needChkSize = isPaddingNeeded(alg, mode) && pad == PAD_NONE;
        }
        bCryptThreadCanceled = FALSE;
        hCryptThread = CreateThread(NULL, 0, doCryptFile, &cryptThreadParams, 0, NULL);
        if (!hCryptThread) {
            WARN(_T("create crypt thread failed"));
            goto cleanup;
        }
        free(key);
        free(iv);
        ShowWindow(hCryptProgressBar, SW_SHOW);
        /* something else is freed when crypt thread done */
        return;
    default:
        WARN(_T("Invalid IN-FORMAT"));
        goto cleanup;
    }
    FormatTextTo(hInputStaticText, _T("INPUT %d"), inl);

    if (isPaddingNeeded(alg, mode) && pad == PAD_NONE
            && inl % EVP_CIPHER_block_size(ciph) != 0) {
        WARN(_T("INPUT length needs to be a multiple of %d when PADDING is NONE"),
            EVP_CIPHER_block_size(ciph));
        goto cleanup;
    }

    out = malloc(inl + EVP_CIPHER_block_size(ciph));

    if (!EVP_CipherUpdate(ctx, out, &outl, in, inl)) {
        WARN(_T("EVP_CipherUpdate failed, code 0x%08X"), ERR_get_error());
        goto cleanup;
    }
    if (!EVP_CipherFinal(ctx, (UCHAR*) out + outl, &tmpl)) {
        WARN(_T("EVP_CipherFinal failed, code 0x%08X"), ERR_get_error());
        goto cleanup;
    }
    outl += tmpl;
    FormatTextTo(hOutputStaticText, _T("OUTPUT %d"), outl);

    switch (outfmt) {
    case OFMT_HEX:
        outs = BinaryToHexChars(out, outl);
        SetWindowText(hOutputEditBox, outs);
        break;
    case OFMT_BASE64:
        outs = BinaryToBase64Chars(out, outl);
        SetWindowText(hOutputEditBox, outs);
        break;
    case OFMT_C_ARRAY:
        outs = BinaryToCArrayChars(out, outl);
        SetWindowText(hOutputEditBox, outs);
        break;
    case OFMT_C_STRING:
        outs = BinaryToCStringChars(out, outl);
        SetWindowText(hOutputEditBox, outs);
        break;
    case OFMT_TEXT:
        outs = BinaryToTextChars(out, outl);
        SetWindowText(hOutputEditBox, outs);
        break;
    case OFMT_FILE:
        outs = GetTextOnce(hOutputEditBox);
        if (IsFile(outs) && CONFIRM(_T("OUTPUT file will be overwrite, continue?")) != IDOK)
            goto cleanup;
        if (!WriteFileOnce(outs, out, outl))
            FormatTextTo(hOutputStaticText, _T("OUTPUT %d (File)"), outl);
        else
            WARN(_T("Write output to [%s] failed"), TRIMPATH(outs));
        break;
    default:
        WARN(_T("Invalid OUT-FORMAT"));
        goto cleanup;
    }

cleanup:
    free(key);
    free(iv);
    free(in);
    free(out);
    free(outs);
    EVP_CIPHER_CTX_free(ctx);
#undef __CONVERT_IV
#undef __CONVERT_KEY
#undef __CONVERT_INPUT
#undef __CONVERT_INPUT_NOTRIM
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

static void resizeWindows(HWND hWnd)
{
    CONST UINT iDpi = GetDpiForSystem();
    CONST UINT iAlign = MulDiv(WND_ALIGN, iDpi, 96);
    CONST UINT iLineH = MulDiv(WND_LINEH, iDpi, 96);
    CONST UINT iComboxW = MulDiv(WND_COMBOXW, iDpi, 96);
    CONST UINT iButtonW = MulDiv(WND_BUTTONW, iDpi, 96);
    UINT w = iAlign;
    UINT h = iAlign;

    MoveWindow(hAlgorithmStaticText, w, h, iComboxW, iLineH, FALSE);
    MoveWindow(hAlgorithmComboBox, w, h + iLineH, iComboxW, iLineH, FALSE);
    w += iComboxW + iAlign;
    MoveWindow(hModeStaticText, w, h, iComboxW, iLineH, FALSE);
    MoveWindow(hModeComboBox, w, h + iLineH, iComboxW, iLineH, FALSE);
    w += iComboxW + iAlign;
    MoveWindow(hPaddingStaticText, w, h, iComboxW, iLineH, FALSE);
    MoveWindow(hPaddingComboBox, w, h + iLineH, iComboxW, iLineH, FALSE);
    w += iComboxW + iAlign;
    MoveWindow(hInformatStaticText, w, h, iComboxW, iLineH, FALSE);
    MoveWindow(hInformatComboBox, w, h + iLineH, iComboxW, iLineH, FALSE);
    w += iComboxW + iAlign;
    MoveWindow(hOutformatStaticText, w, h, iComboxW, iLineH, FALSE);
    MoveWindow(hOutformatComboBox, w, h + iLineH, iComboxW, iLineH, FALSE);
    w += iComboxW + iAlign;

    h += iLineH + iLineH + iAlign;

    MoveWindow(hKeyformatStaticText, iAlign, h, iComboxW, iLineH, FALSE);
    MoveWindow(hKeyStaticText, iComboxW + iAlign * 2, h, w - iComboxW - iAlign * 3, iLineH, FALSE);
    h += iLineH;
    MoveWindow(hKeyformatComboBox, iAlign, h, iComboxW, iLineH, FALSE);
    MoveWindow(hKeyEditBox, iComboxW + iAlign * 2, h, w - iComboxW - iAlign * 3, iLineH, FALSE);
    h += iLineH + iAlign;

    MoveWindow(hIVformatStaticText, iAlign, h, iComboxW, iLineH, FALSE);
    MoveWindow(hIVStaticText, iComboxW + iAlign * 2, h, w - iComboxW - iAlign * 3, iLineH, FALSE);
    h += iLineH;
    MoveWindow(hIVformatComboBox, iAlign, h, iComboxW, iLineH, FALSE);
    MoveWindow(hIVEditBox, iComboxW + iAlign * 2, h, w - iComboxW - iAlign * 3, iLineH, FALSE);
    h += iLineH + iAlign;

    MoveWindow(hInputStaticText, iAlign, h, w - iAlign * 2, iLineH, FALSE);
    h += iLineH;
    MoveWindow(hInputEditBox, iAlign, h, w - iAlign * 2, iLineH * 6, FALSE);
    h += iLineH * 6 + iAlign;

    MoveWindow(hOutputStaticText, iAlign, h, w - iAlign * 2, iLineH, FALSE);
    h += iLineH;
    MoveWindow(hOutputEditBox, iAlign, h, w - iAlign * 2, iLineH * 6, FALSE);
    h += iLineH * 6 + iAlign;

    MoveWindow(hCryptProgressBar, iAlign, h, w / 2 - iButtonW - iAlign / 2 - iAlign * 2, iLineH, FALSE);
    MoveWindow(hEncryptButton, w / 2 - iButtonW - iAlign / 2, h, iButtonW, iLineH, FALSE);
    MoveWindow(hDecryptButton, w / 2 + iAlign / 2, h, iButtonW, iLineH, FALSE);
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
    hModeStaticText = CreateWindow(_T("STATIC"), _T("MODE"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hModeComboBox = CreateWindow(_T("COMBOBOX"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWNLIST,
                                0, 0, 0, 0, hWnd, (HMENU) WM_USER_MODE, hMainInstance, NULL);
    hPaddingStaticText = CreateWindow(_T("STATIC"), _T("PADDING"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hPaddingComboBox = CreateWindow(_T("COMBOBOX"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWNLIST,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hInformatStaticText = CreateWindow(_T("STATIC"), _T("IN-FORMAT"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hInformatComboBox = CreateWindow(_T("COMBOBOX"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWNLIST,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hOutformatStaticText = CreateWindow(_T("STATIC"), _T("OUT-FORMAT"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hOutformatComboBox = CreateWindow(_T("COMBOBOX"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWNLIST,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);

    hKeyformatStaticText = CreateWindow(_T("STATIC"), _T("KEY-FORMAT"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hKeyformatComboBox = CreateWindow(_T("COMBOBOX"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWNLIST,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hKeyStaticText = CreateWindow(_T("STATIC"), _T("KEY"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, NULL, NULL);
    hKeyEditBox = CreateWindow(_T("EDIT"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_AUTOVSCROLL | ES_MULTILINE,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);

    hIVformatStaticText = CreateWindow(_T("STATIC"), _T("IV-FORMAT"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hIVformatComboBox = CreateWindow(_T("COMBOBOX"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWNLIST,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hIVStaticText = CreateWindow(_T("STATIC"), _T("IV"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hIVEditBox = CreateWindow(_T("EDIT"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_AUTOVSCROLL | ES_MULTILINE,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);

    hInputStaticText = CreateWindow(_T("STATIC"), _T("INPUT"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hInputEditBox = CreateWindow(_T("EDIT"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_LEFT | ES_AUTOVSCROLL | ES_MULTILINE,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);

    hOutputStaticText = CreateWindow(_T("STATIC"), _T("OUTPUT"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hOutputEditBox = CreateWindow(_T("EDIT"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_LEFT | ES_AUTOVSCROLL | ES_MULTILINE/*  | ES_READONLY */,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);

    hEncryptButton = CreateWindow(_T("BUTTON"), _T("ENCRYPT"), WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                                0, 0, 0, 0, hWnd, (HMENU) WM_USER_ENCRYPT, hMainInstance, NULL);
    hDecryptButton = CreateWindow(_T("BUTTON"), _T("DECRYPT"), WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                                0, 0, 0, 0, hWnd, (HMENU) WM_USER_DECRYPT, hMainInstance, NULL);

    hCryptProgressBar = CreateWindow(PROGRESS_CLASS, NULL, /* WS_VISIBLE |  */WS_CHILD | PBS_SMOOTH,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);

    for (i = 0; i < ARRAYSIZE(algorithmItems); ++i)
        SendMessage(hAlgorithmComboBox, CB_ADDSTRING, 0, (LPARAM) algorithmItems[i]);
	SETCBOPT(hAlgorithmComboBox, ALG_AES);
    for (i = 0; i < ARRAYSIZE(modeItems); ++i)
        SendMessage(hModeComboBox, CB_ADDSTRING, 0, (LPARAM) modeItems[i]);
    SETCBOPT(hModeComboBox, MODE_CBC);
    for (i = 0; i < ARRAYSIZE(paddingItems); ++i)
        SendMessage(hPaddingComboBox, CB_ADDSTRING, 0, (LPARAM) paddingItems[i]);
	SETCBOPT(hPaddingComboBox, PAD_NONE);
    for (i = 0; i < ARRAYSIZE(informatItems); ++i)
        SendMessage(hInformatComboBox, CB_ADDSTRING, 0, (LPARAM) informatItems[i]);
	SETCBOPT(hInformatComboBox, IFMT_HEX);
    for (i = 0; i < ARRAYSIZE(outformatItems); ++i)
        SendMessage(hOutformatComboBox, CB_ADDSTRING, 0, (LPARAM) outformatItems[i]);
	SETCBOPT(hOutformatComboBox, OFMT_HEX);
    for (i = 0; i < ARRAYSIZE(kvformatItems); ++i) {
        SendMessage(hKeyformatComboBox, CB_ADDSTRING, 0, (LPARAM) kvformatItems[i]);
        SendMessage(hIVformatComboBox, CB_ADDSTRING, 0, (LPARAM) kvformatItems[i]);
    }
	SETCBOPT(hKeyformatComboBox, KVFMT_HEX);
	SETCBOPT(hIVformatComboBox, KVFMT_HEX);

    SendMessage(hInputEditBox, EM_SETLIMITTEXT, (WPARAM) (MAX_INFILE_SIZE * 5), 0);
    SendMessage(hOutputEditBox, EM_SETLIMITTEXT, (WPARAM) (MAX_INFILE_SIZE * 5), 0);

    onAlgorithmOrModeChanged(hWnd);
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
        case WM_USER_MODE:
            if (HIWORD(wParam) == CBN_SELCHANGE)
                onAlgorithmOrModeChanged(hWnd);
            break;
        case IDC_ACC_DONE:
        case WM_USER_ENCRYPT:
            onEncryptClicked(hWnd);
            break;
        case WM_USER_DECRYPT:
            onDecryptClicked(hWnd);
            break;
        case WM_USER_THREAD:
            onCryptThreadDone(hWnd, (CryptThreadParams*) lParam);
            break;
        case IDC_ACC_STOP:
            bCryptThreadCanceled = TRUE;
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

VOID OnSymmConfigItem(CONST TCHAR* name, CONST TCHAR* value)
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
        __SELECT_OPTION(algorithmItems, hAlgorithmComboBox);
    } else if (!lstrcmp(name, _T("MODE"))) {
        __SELECT_OPTION_EX(modeItems, hModeComboBox, onAlgorithmOrModeChanged(NULL));
    } else if (!lstrcmp(name, _T("PADDING"))) {
        __SELECT_OPTION(paddingItems, hPaddingComboBox);
    } else if (!lstrcmp(name, _T("IN-FORMAT"))) {
        __SELECT_OPTION(informatItems, hInformatComboBox);
    } else if (!lstrcmp(name, _T("OUT-FORMAT"))) {
        __SELECT_OPTION(outformatItems, hOutformatComboBox);
    } else if (!lstrcmp(name, _T("KEY-FORMAT"))) {
        __SELECT_OPTION(kvformatItems, hKeyformatComboBox);
    } else if (!lstrcmp(name, _T("IV-FORMAT"))) {
        __SELECT_OPTION(kvformatItems, hIVformatComboBox);
    } else if (!lstrcmp(name, _T("KEY"))) {
        SetWindowText(hKeyEditBox, value);
    } else if (!lstrcmp(name, _T("IV"))) {
        SetWindowText(hIVEditBox, value);
    } else if (!lstrcmp(name, _T("INPUT"))) {
        SetWindowText(hInputEditBox, value);
    } else if (!lstrcmp(name, _T("OUTPUT"))) {
        SetWindowText(hOutputEditBox, value);
    }

#undef __SELECT_OPTION_EX
#undef __SELECT_OPTION
}

BOOL OnSymmWindowClose()
{
    if (hCryptThread && CONFIRM(_T("crypt thread running, exit?")) != IDOK)
        return TRUE;
    return FALSE;
}

HWND CreateSymmWindow(HWND hWnd)
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