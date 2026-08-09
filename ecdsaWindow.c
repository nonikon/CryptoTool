#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "mainWindow.h"
#include "encode.h"

#define WND_CLASSNAME       _T("EcdsaWindowClass")

#define WM_USER_SIGN        (WM_USER + 1)
#define WM_USER_VERIFY      (WM_USER + 2)

static HWND hCurveStaticText;
static HWND hCurveComboBox;
static HWND hInformatStaticText;
static HWND hInformatComboBox;
static HWND hOutformatStaticText;
static HWND hOutformatComboBox;
static HWND hPriKeyformatStaticText;
static HWND hPriKeyformatComboBox;
static HWND hPriKeyStaticText;
static HWND hPriKeyEditBox;
static HWND hPubKeyformatStaticText;
static HWND hPubKeyformatComboBox;
static HWND hPubKeyStaticText;
static HWND hPubKeyEditBox;
static HWND hTbsDataStaticText;
static HWND hTbsDataEditBox;
static HWND hSignatureStaticText;
static HWND hSignatureEditBox;
static HWND hSignButton;
static HWND hVerifyButton;

static CONST TCHAR* curveItems[] = {
    _T("P-224"), _T("P-256"), _T("P-384"), _T("P-521"),
};
enum {
    CURVE_SCEP224R1, CURVE_SCEP256R1, CURVE_SCEP384R1, CURVE_SCEP521R1,
};
static CONST TCHAR* tbsformatItems[] = {
    _T("BASE64"), _T("C-ARRAY"), _T("C-STRING"), _T("HEX"),
};
enum {
    IFMT_BASE64, IFMT_C_ARRAY, IFMT_C_STRING, IFMT_HEX,
};
static CONST TCHAR* sigformatItems[] = {
    _T("BASE64"), _T("C-ARRAY"), _T("C-STRING"), _T("HEX"),
};
enum {
    OFMT_BASE64, OFMT_C_ARRAY, OFMT_C_STRING, OFMT_HEX,
};
static CONST TCHAR* keyformatItems[] = {
    _T("BASE64"), _T("C-ARRAY"), _T("C-STRING"), _T("HEX"),
};
enum {
    KEYFMT_BASE64, KEYFMT_C_ARRAY, KEYFMT_C_STRING, KEYFMT_HEX,
};


static void tryLoadPKey(UCHAR* data, UINT size)
{
    BIO* io = BIO_new_mem_buf(data, size);
    EVP_PKEY* key = NULL;

    if (!(key = PEM_read_bio_PrivateKey(io, NULL, NULL, NULL))) {
        BIO_reset(io);
        if (!(key = PEM_read_bio_PUBKEY(io, NULL, NULL, NULL))) {
            BIO_reset(io);
            if (!(key = d2i_PrivateKey_bio(io, NULL))) {
                BIO_reset(io);
                if (!(key = d2i_PUBKEY_bio(io, NULL))) {
                    X509* crt = NULL;
                    BIO_reset(io);
                    if (!(crt = PEM_read_bio_X509(io, NULL, NULL, NULL))) {
                        BIO_reset(io);
                        crt = d2i_X509_bio(io, NULL);
                    }
                    if (crt) {
                        key = X509_get_pubkey(crt); // NOTE: not get0
                        X509_free(crt);
                    }
                }
            }
        }
    }
    if (key) {
        EC_KEY* eck = EVP_PKEY_get0_EC_KEY(key);
        if (eck) {
            const EC_GROUP* grp = EC_KEY_get0_group(eck);
            INT curve = -1;
            switch (EC_GROUP_get_curve_name(grp)) {
            case NID_secp224r1:
                curve = CURVE_SCEP224R1;
                break;
            case NID_X9_62_prime256v1:
                curve = CURVE_SCEP256R1;
                break;
            case NID_secp384r1:
                curve = CURVE_SCEP384R1;
                break;
            case NID_secp521r1:
                curve = CURVE_SCEP521R1;
                break;
            }
            if (curve != -1) {
                UCHAR tbuf[(OPENSSL_ECC_MAX_FIELD_BITS + 7) / 8 * 2 + 1] = { 0 };
                INT bsz = (EC_GROUP_get_degree(grp) + 7) / 8;
                const BIGNUM* pri = EC_KEY_get0_private_key(eck);
                const EC_POINT* pub = EC_KEY_get0_public_key(eck);
                TCHAR* ks = NULL;
                if (pri) {
                    if (!pub) SetWindowText(hPubKeyEditBox, "");
                    BN_bn2binpad(pri, tbuf, bsz);
                    switch (GETCBOPT(hPriKeyformatComboBox)) {
                    case KEYFMT_HEX:
                        ks = BinaryToHexChars(tbuf, bsz);
                        break;
                    case KEYFMT_BASE64:
                        ks = BinaryToBase64Chars(tbuf, bsz);
                        break;
                    case KEYFMT_C_ARRAY:
                        ks = BinaryToCArrayChars(tbuf, bsz);
                        break;
                    case KEYFMT_C_STRING:
                        ks = BinaryToCStringChars(tbuf, bsz);
                        break;
                    }
                    SetWindowText(hPriKeyEditBox, ks);
                    free(ks);
                }
                if (pub) {
                    if (!pri) SetWindowText(hPriKeyEditBox, "");
                    EC_POINT_point2oct(grp, pub, POINT_CONVERSION_UNCOMPRESSED,
                        tbuf, 1 + bsz * 2, NULL);
                    switch (GETCBOPT(hPubKeyformatComboBox)) {
                    case KEYFMT_HEX:
                        ks = BinaryToHexChars(tbuf + 1, bsz * 2);
                        break;
                    case KEYFMT_BASE64:
                        ks = BinaryToBase64Chars(tbuf + 1, bsz * 2);
                        break;
                    case KEYFMT_C_ARRAY:
                        ks = BinaryToCArrayChars(tbuf + 1, bsz * 2);
                        break;
                    case KEYFMT_C_STRING:
                        ks = BinaryToCStringChars(tbuf + 1, bsz * 2);
                        break;
                    }
                    SetWindowText(hPubKeyEditBox, ks);
                    free(ks);
                }
                SETCBOPT(hCurveComboBox, curve);
            }
        }
        EVP_PKEY_free(key);
    }
    BIO_free(io);
}

static void onDropFiles(HWND hWnd, HDROP hDrop)
{
    TCHAR* buf;
    UINT len;

    len = DragQueryFile(hDrop, 0, NULL, 0); /* >=0 */
    buf = malloc(sizeof(TCHAR) * (len + 1));

    memset(buf, 0, sizeof(TCHAR) * (len + 1));
    DragQueryFile(hDrop, 0, buf, len + 1);

    if (IsFile(buf)) {
        UINT fsize = MAX_INFILE_SIZE;
        UCHAR* fdata = ReadFileOnce(buf, &fsize);
        if (fdata) {
            tryLoadPKey(fdata, fsize);
            free(fdata);
        }
    }

    DragFinish(hDrop);
    free(buf);
}

static void doEcdsa(HWND hWnd, BOOL isVerify)
{
    UCHAR tbuf[(OPENSSL_ECC_MAX_FIELD_BITS + 7) / 8 * 2 + 8] = { 0 }; // long enough to store public key or signature
    EC_KEY* eck = NULL;
    ECDSA_SIG* sig = NULL;
    INT curve = GETCBOPT(hCurveComboBox);
    INT tbsfmt = GETCBOPT(hInformatComboBox);
    INT sigfmt = GETCBOPT(hOutformatComboBox);
    INT prikfmt = GETCBOPT(hPriKeyformatComboBox);
    INT pubkfmt = GETCBOPT(hPubKeyformatComboBox);
    VOID* prik = GetTextOnce(hPriKeyEditBox);
    VOID* pubk = GetTextOnce(hPubKeyEditBox);
    VOID* tbs = GetTextOnce(hTbsDataEditBox);
    TCHAR* sigs = NULL;
    INT prikl;
    INT pubkl;
    INT bsz;
    INT tbsl;
    INT sigl;

#define __CONVERT_TBSDATA_NOTRIM(func, notify) \
        tbsl = func(tbs); \
        if (tbsl <= 0) { \
            WARN(notify); \
            goto cleanup; \
        }

#define __CONVERT_TBSDATA(func, notify) \
        if (TrimSpace(tbs)) \
            SetWindowText(hTbsDataEditBox, tbs); \
        __CONVERT_TBSDATA_NOTRIM(func, notify)

#define __CONVERT_PRIK(func, notify) \
        if (TrimSpace(prik)) \
            SetWindowText(hPriKeyEditBox, prik); \
        prikl = func(prik); \
        if (prikl < 0) { \
            WARN(notify); \
            goto cleanup; \
        }

#define __CONVERT_PUBK(func, notify) \
        if (TrimSpace(pubk)) \
            SetWindowText(hPubKeyEditBox, pubk); \
        pubkl = func(pubk); \
        if (pubkl < 0) { \
            WARN(notify); \
            goto cleanup; \
        }

#define __CONVERT_SIG(func, notify) \
        if (TrimSpace(sigs)) \
            SetWindowText(hSignatureEditBox, sigs); \
        sigl = func(sigs); \
        if (sigl <= 0) { \
            WARN(notify); \
            goto cleanup; \
        }

    switch (prikfmt) {
    case KEYFMT_HEX:
        __CONVERT_PRIK(HexCharsToBinary, _T("PRIVATE-KEY is not a HEX string"))
        break;
    case KEYFMT_BASE64:
        __CONVERT_PRIK(Base64CharsToBinary, _T("PRIVATE-KEY is not a BASE64 string"))
        break;
    case KEYFMT_C_ARRAY:
        __CONVERT_PRIK(CArrayCharsToBinary, _T("PRIVATE-KEY is not a C-ARRAY string"));
        break;
    case KEYFMT_C_STRING:
        __CONVERT_PRIK(CStringCharsToBinary, _T("PRIVATE-KEY is not a C-STRING string"));
        break;
    default:
        WARN(_T("Invalid PRIK-FORMAT"));
        goto cleanup;
    }
    FormatTextTo(hPriKeyStaticText, _T("PRIVATE-KEY %d"), prikl);

    switch (pubkfmt) {
    case KEYFMT_HEX:
        __CONVERT_PUBK(HexCharsToBinary, _T("PUBLIC-KEY is not a HEX string"))
        break;
    case KEYFMT_BASE64:
        __CONVERT_PUBK(Base64CharsToBinary, _T("PUBLIC-KEY is not a BASE64 string"))
        break;
    case KEYFMT_C_ARRAY:
        __CONVERT_PUBK(CArrayCharsToBinary, _T("PUBLIC-KEY is not a C-ARRAY string"));
        break;
    case KEYFMT_C_STRING:
        __CONVERT_PUBK(CStringCharsToBinary, _T("PUBLIC-KEY is not a C-STRING string"));
        break;
    default:
        WARN(_T("Invalid PUBK-FORMAT"));
        goto cleanup;
    }
    FormatTextTo(hPubKeyStaticText, _T("PUBLIC-KEY %d"), pubkl);

    switch (curve) {
    case CURVE_SCEP224R1:
        eck = EC_KEY_new_by_curve_name(NID_secp224r1);
        break;
    case CURVE_SCEP256R1:
        eck = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        break;
    case CURVE_SCEP384R1:
        eck = EC_KEY_new_by_curve_name(NID_secp384r1);
        break;
    case CURVE_SCEP521R1:
        eck = EC_KEY_new_by_curve_name(NID_secp521r1);
        break;
    default:
        WARN(_T("Invalid CURVE"));
        goto cleanup;
    }

    bsz = (EC_GROUP_get_degree(EC_KEY_get0_group(eck)) + 7) / 8;

    if (prikl) {
        // load private key
        if (prikl != bsz) {
            WARN("PRIVATE-KEY length should be %d bytes", bsz);
            goto cleanup;
        }
        if (!EC_KEY_oct2priv(eck, prik, prikl)) {
            WARN("Invalid PRIVATE-KEY, code 0x%08X", ERR_get_error());
            goto cleanup;
        }
    }

    if (pubkl) {
        int rc = 0;
        // load public key
        if (pubkl == 1 + bsz) {
            // compressed public key
            if (((PUCHAR) pubk)[0] != 0x02 && ((PUCHAR) pubk)[0] != 0x03) {
                WARN("Compressed PUBLIC-KEY should begin with 0x02 or 0x03");
                goto cleanup;
            }
            rc = EC_KEY_oct2key(eck, pubk, pubkl, NULL);
        } else if (pubkl == 1 + bsz * 2) {
            // uncompressed public key
            if (((PUCHAR) pubk)[0] != 0x04) {
                WARN("Uncompressed PUBLIC-KEY should begin with 0x04");
                goto cleanup;
            }
            rc = EC_KEY_oct2key(eck, pubk, pubkl, NULL);
        } else {
            // raw public key (x + y)
            if (pubkl != bsz * 2) {
                WARN("PUBLIC-KEY length should be %d (raw) or %d (compressed) or %d (uncompressed) bytes",
                    bsz * 2, bsz + 1, bsz * 2 + 1);
                goto cleanup;
            }
            tbuf[0] = 0x04; // add 0x04 prefix
            memcpy(tbuf + 1, pubk, pubkl);
            rc = EC_KEY_oct2key(eck, tbuf, pubkl + 1, NULL);
        }
        if (!rc) {
            WARN("Invalid PUBLIC-KEY, code 0x%08X", ERR_get_error());
            goto cleanup;
        }
    } else if (prikl) {
        // public key not present, compute it
        const EC_GROUP* group = EC_KEY_get0_group(eck);
        EC_POINT* point = EC_POINT_new(group);
        EC_POINT_mul(group, point, EC_KEY_get0_private_key(eck), NULL, NULL, NULL);
        EC_KEY_set_public_key(eck, point);
        EC_POINT_free(point);
    } else {
        WARN("Both PRIVATE-KEY and PUBLIC-KEY are empty");
        goto cleanup;
    }
    if (!EC_KEY_check_key(eck)) {
        WARN("Invalid PRIVATE-KEY or PUBLIC-KEY, code 0x%08X", ERR_get_error());
        goto cleanup;
    }
    if (pubkl != bsz * 2) {
        TCHAR* ks = NULL;
        // PUBLIC-KEY is not a raw key, convert it into tbuf
        EC_POINT_point2oct(EC_KEY_get0_group(eck), EC_KEY_get0_public_key(eck),
            POINT_CONVERSION_UNCOMPRESSED, tbuf, 1 + bsz * 2, NULL);
        // update raw key into PUBLIC-KEY
        switch (pubkfmt) {
        case KEYFMT_HEX:
            ks = BinaryToHexChars(tbuf + 1, bsz * 2);
            break;
        case KEYFMT_BASE64:
            ks = BinaryToBase64Chars(tbuf + 1, bsz * 2);
            break;
        case KEYFMT_C_ARRAY:
            ks = BinaryToCArrayChars(tbuf + 1, bsz * 2);
            break;
        case KEYFMT_C_STRING:
            ks = BinaryToCStringChars(tbuf + 1, bsz * 2);
            break;
        }
        SetWindowText(hPubKeyEditBox, ks);
        FormatTextTo(hPubKeyStaticText, _T("PUBLIC-KEY %d"), bsz * 2);
        free(ks);
    }

    switch (tbsfmt) {
    case IFMT_HEX:
        __CONVERT_TBSDATA(HexCharsToBinary, _T("TBSDATA is not a HEX string"));
        break;
    case IFMT_BASE64:
        __CONVERT_TBSDATA(Base64CharsToBinary, _T("TBSDATA is not a BASE64 string"));
        break;
    case IFMT_C_ARRAY:
        __CONVERT_TBSDATA(CArrayCharsToBinary, _T("TBSDATA is not a C-ARRAY string"));
        break;
    case IFMT_C_STRING:
        __CONVERT_TBSDATA(CStringCharsToBinary, _T("TBSDATA is not a C-STRING string"));
        break;
    default:
        WARN(_T("Invalid TBS-FORMAT"));
        goto cleanup;
    }
    FormatTextTo(hTbsDataStaticText, _T("TBSDATA %d"), tbsl);

    if (isVerify) {
        sigs = GetTextOnce(hSignatureEditBox);
        switch (sigfmt) {
        case OFMT_HEX:
            __CONVERT_SIG(HexCharsToBinary, _T("SIGNATURE is not a HEX string"));
            break;
        case OFMT_BASE64:
            __CONVERT_SIG(Base64CharsToBinary, _T("SIGNATURE is not a BASE64 string"));
            break;
        case OFMT_C_ARRAY:
            __CONVERT_SIG(CArrayCharsToBinary, _T("SIGNATURE is not a C-ARRAY string"));
            break;
        case OFMT_C_STRING:
            __CONVERT_SIG(CStringCharsToBinary, _T("SIGNATURE is not a C-STRING string"));
            break;
        default:
            WARN(_T("Invalid SIG-FORMAT"));
            goto cleanup;
        }
        FormatTextTo(hSignatureStaticText, _T("SIGNATURE %d"), sigl);
        sig = ECDSA_SIG_new();
        if (sigl == bsz * 2) {
            // raw signature (r + s)
            ECDSA_SIG_set0(sig, BN_bin2bn(sigs, bsz, NULL), BN_bin2bn(sigs + bsz, bsz, NULL));
        } else if (sigl > bsz * 2 && sigl <= bsz * 2 + 8) {
            // der encoded signature
            const UCHAR* p = sigs;
            if (!d2i_ECDSA_SIG(&sig, &p, sigl)) {
                WARN("Invalid SIGNATURE, code 0x%08X", ERR_get_error());
                goto cleanup;
            }
        } else {
            WARN("SIGNATURE length should be %d (raw) or %d~%d (asn1) bytes",
                bsz * 2, bsz * 2, bsz * 2 + 8);
            goto cleanup;
        }
        if (!ECDSA_do_verify(tbs, tbsl, sig, eck) == 1) {
            WARN("Verify failed, code 0x%08X", ERR_get_error());
            goto cleanup;
        }
        FormatTextTo(hSignatureStaticText, _T("SIGNATURE %d OK"), bsz * 2);
    } else {
        if (prikl == 0) {
            WARN("PRIVATE-KEY is needed for signing");
            goto cleanup;
        }
        sig = ECDSA_do_sign(tbs, tbsl, eck);
        if (!sig) {
            WARN("Sign failed, code 0x%08X", ERR_get_error());
            goto cleanup;
        }
        FormatTextTo(hSignatureStaticText, _T("SIGNATURE %d"), bsz * 2);
        sigl = 0;
    }

    if (sigl != bsz * 2) {
        // convert ECDSA_SIG to raw signature
        BN_bn2binpad(ECDSA_SIG_get0_r(sig), tbuf, bsz);
        BN_bn2binpad(ECDSA_SIG_get0_s(sig), tbuf + bsz, bsz);
        switch (sigfmt) {
        case OFMT_HEX:
            sigs = BinaryToHexChars(tbuf, bsz * 2);
            break;
        case OFMT_BASE64:
            sigs = BinaryToBase64Chars(tbuf, bsz * 2);
            break;
        case OFMT_C_ARRAY:
            sigs = BinaryToCArrayChars(tbuf, bsz * 2);
            break;
        case OFMT_C_STRING:
            sigs = BinaryToCStringChars(tbuf, bsz * 2);
            break;
        default:
            WARN(_T("Invalid SIG-FORMAT"));
            goto cleanup;
        }
        SetWindowText(hSignatureEditBox, sigs);
    }

cleanup:
    free(prik);
    free(pubk);
    free(tbs);
    free(sigs);
    ECDSA_SIG_free(sig);
    EC_KEY_free(eck);
#undef __CONVERT_SIG
#undef __CONVERT_PUBK
#undef __CONVERT_PRIK
#undef __CONVERT_TBSDATA
#undef __CONVERT_TBSDATA_NOTRIM
}

static void onSignClicked(HWND hWnd)
{
    doEcdsa(hWnd, FALSE);
}

static void onVerifyClicked(HWND hWnd)
{
    doEcdsa(hWnd, TRUE);
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

    MoveWindow(hCurveStaticText, w, h, iComboxW, iLineH, FALSE);
    MoveWindow(hCurveComboBox, w, h + iLineH, iComboxW, iLineH, FALSE);
    w += iComboxW + iAlign;
    MoveWindow(hPriKeyformatStaticText, w, h, iComboxW, iLineH, FALSE);
    MoveWindow(hPriKeyformatComboBox, w, h + iLineH, iComboxW, iLineH, FALSE);
    w += iComboxW + iAlign;
    MoveWindow(hPubKeyformatStaticText, w, h, iComboxW, iLineH, FALSE);
    MoveWindow(hPubKeyformatComboBox, w, h + iLineH, iComboxW, iLineH, FALSE);
    w += iComboxW + iAlign;
    MoveWindow(hInformatStaticText, w, h, iComboxW, iLineH, FALSE);
    MoveWindow(hInformatComboBox, w, h + iLineH, iComboxW, iLineH, FALSE);
    w += iComboxW + iAlign;
    MoveWindow(hOutformatStaticText, w, h, iComboxW, iLineH, FALSE);
    MoveWindow(hOutformatComboBox, w, h + iLineH, iComboxW, iLineH, FALSE);
    w += iComboxW + iAlign;

    h += iLineH + iLineH + iAlign;

    MoveWindow(hPriKeyStaticText, iAlign, h, w - iAlign * 2, iLineH, FALSE);
    h += iLineH;
    MoveWindow(hPriKeyEditBox, iAlign, h, w - iAlign * 2, iLineH * 3, FALSE);
    h += iLineH * 3 + iAlign;

    MoveWindow(hPubKeyStaticText, iAlign, h, w - iAlign * 2, iLineH, FALSE);
    h += iLineH;
    MoveWindow(hPubKeyEditBox, iAlign, h, w - iAlign * 2, iLineH * 4, FALSE);
    h += iLineH * 4 + iAlign;

    MoveWindow(hTbsDataStaticText, iAlign, h, w - iAlign * 2, iLineH, FALSE);
    h += iLineH;
    MoveWindow(hTbsDataEditBox, iAlign, h, w - iAlign * 2, iLineH * 3, FALSE);
    h += iLineH * 3 + iAlign;

    MoveWindow(hSignatureStaticText, iAlign, h, w - iAlign * 2, iLineH, FALSE);
    h += iLineH;
    MoveWindow(hSignatureEditBox, iAlign, h, w - iAlign * 2, iLineH * 4, FALSE);
    h += iLineH * 4 + iAlign;

    MoveWindow(hSignButton, w / 2 - iButtonW - iAlign / 2, h, iButtonW, iLineH, FALSE);
    MoveWindow(hVerifyButton, w / 2 + iAlign / 2, h, iButtonW, iLineH, FALSE);
    h += iLineH + iAlign;

    MoveWindow(hWnd, 0, 0, w, h, FALSE);
}

static void onWindowCreate(HWND hWnd)
{
    INT i;

    hCurveStaticText = CreateWindow(_T("STATIC"), _T("CURVE"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hCurveComboBox = CreateWindow(_T("COMBOBOX"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWNLIST,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hInformatStaticText = CreateWindow(_T("STATIC"), _T("TBS-FORMAT"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hInformatComboBox = CreateWindow(_T("COMBOBOX"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWNLIST,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hOutformatStaticText = CreateWindow(_T("STATIC"), _T("SIG-FORMAT"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hOutformatComboBox = CreateWindow(_T("COMBOBOX"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWNLIST,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);

    hPriKeyformatStaticText = CreateWindow(_T("STATIC"), _T("PRIK-FORMAT"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hPriKeyformatComboBox = CreateWindow(_T("COMBOBOX"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWNLIST,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hPriKeyStaticText = CreateWindow(_T("STATIC"), _T("PRIVATE-KEY"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hPriKeyEditBox = CreateWindow(_T("EDIT"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_LEFT | ES_AUTOVSCROLL | ES_MULTILINE,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);

    hPubKeyformatStaticText = CreateWindow(_T("STATIC"), _T("PUBK-FORMAT"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hPubKeyformatComboBox = CreateWindow(_T("COMBOBOX"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWNLIST,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hPubKeyStaticText = CreateWindow(_T("STATIC"), _T("PUBLIC-KEY"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hPubKeyEditBox = CreateWindow(_T("EDIT"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_LEFT | ES_AUTOVSCROLL | ES_MULTILINE,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);

    hTbsDataStaticText = CreateWindow(_T("STATIC"), _T("TBSDATA"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hTbsDataEditBox = CreateWindow(_T("EDIT"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_LEFT | ES_AUTOVSCROLL | ES_MULTILINE,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);

    hSignatureStaticText = CreateWindow(_T("STATIC"), _T("SIGNATURE"), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);
    hSignatureEditBox = CreateWindow(_T("EDIT"), NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_LEFT | ES_AUTOVSCROLL | ES_MULTILINE/*  | ES_READONLY */,
                                0, 0, 0, 0, hWnd, NULL, hMainInstance, NULL);

    hSignButton = CreateWindow(_T("BUTTON"), _T("SIGN"), WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                                0, 0, 0, 0, hWnd, (HMENU) WM_USER_SIGN, hMainInstance, NULL);
    hVerifyButton = CreateWindow(_T("BUTTON"), _T("VERIFY"), WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                                0, 0, 0, 0, hWnd, (HMENU) WM_USER_VERIFY, hMainInstance, NULL);

    for (i = 0; i < ARRAYSIZE(curveItems); ++i)
        SendMessage(hCurveComboBox, CB_ADDSTRING, 0, (LPARAM) curveItems[i]);
	SETCBOPT(hCurveComboBox, CURVE_SCEP256R1);
    for (i = 0; i < ARRAYSIZE(tbsformatItems); ++i)
        SendMessage(hInformatComboBox, CB_ADDSTRING, 0, (LPARAM) tbsformatItems[i]);
	SETCBOPT(hInformatComboBox, IFMT_HEX);
    for (i = 0; i < ARRAYSIZE(sigformatItems); ++i)
        SendMessage(hOutformatComboBox, CB_ADDSTRING, 0, (LPARAM) sigformatItems[i]);
	SETCBOPT(hOutformatComboBox, OFMT_HEX);
    for (i = 0; i < ARRAYSIZE(keyformatItems); ++i) {
        SendMessage(hPriKeyformatComboBox, CB_ADDSTRING, 0, (LPARAM) keyformatItems[i]);
        SendMessage(hPubKeyformatComboBox, CB_ADDSTRING, 0, (LPARAM) keyformatItems[i]);
    }
	SETCBOPT(hPriKeyformatComboBox, KEYFMT_HEX);
	SETCBOPT(hPubKeyformatComboBox, KEYFMT_HEX);

    SendMessage(hTbsDataEditBox, EM_SETLIMITTEXT, (WPARAM) (MAX_INFILE_SIZE * 5), 0);
    SendMessage(hSignatureEditBox, EM_SETLIMITTEXT, (WPARAM) (MAX_INFILE_SIZE * 5), 0);

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
        case WM_USER_SIGN:
            onSignClicked(hWnd);
            break;
        case WM_USER_VERIFY:
            onVerifyClicked(hWnd);
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

VOID OnEcdsaConfigSave(FILE* fp)
{
    TCHAR* prik = GetTextOnce(hPriKeyEditBox);
    TCHAR* pubk = GetTextOnce(hPubKeyEditBox);
    TCHAR* tbsdata = GetTextOnce(hTbsDataEditBox);
    TCHAR* signature = GetTextOnce(hSignatureEditBox);

    TrimSpace(prik);
    TrimSpace(pubk);
    TrimSpace(tbsdata);
    TrimSpace(signature);

    _ftprintf(fp, _T("CURVE=%s\r\nTBS-FORMAT=%s\r\nSIG-FORMAT=%s\r\n")
        _T("PRIK-FORMAT=%s\r\nPUBK-FORMAT=%s\r\nPRIVATE-KEY=%s\r\nPUBLIC-KEY=%s\r\nTBSDATA=%s\r\nSIGNATURE=%s\r\n"),
        curveItems[GETCBOPT(hCurveComboBox)],
        tbsformatItems[GETCBOPT(hInformatComboBox)],
        sigformatItems[GETCBOPT(hOutformatComboBox)],
        keyformatItems[GETCBOPT(hPriKeyformatComboBox)],
        keyformatItems[GETCBOPT(hPubKeyformatComboBox)], prik, pubk, tbsdata, signature);

    free(prik);
    free(pubk);
    free(tbsdata);
    free(signature);
}

VOID OnEcdsaConfigItem(CONST TCHAR* name, CONST TCHAR* value)
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

    if (!lstrcmp(name, _T("CURVE"))) {
        __SELECT_OPTION(curveItems, hCurveComboBox);
    } else if (!lstrcmp(name, _T("TBS-FORMAT"))) {
        __SELECT_OPTION(tbsformatItems, hInformatComboBox);
    } else if (!lstrcmp(name, _T("SIG-FORMAT"))) {
        __SELECT_OPTION(sigformatItems, hOutformatComboBox);
    } else if (!lstrcmp(name, _T("PRIK-FORMAT"))) {
        __SELECT_OPTION(keyformatItems, hPriKeyformatComboBox);
    } else if (!lstrcmp(name, _T("PUBK-FORMAT"))) {
        __SELECT_OPTION(keyformatItems, hPubKeyformatComboBox);
    } else if (!lstrcmp(name, _T("PRIVATE-KEY"))) {
        SetWindowText(hPriKeyEditBox, value);
    } else if (!lstrcmp(name, _T("PUBLIC-KEY"))) {
        SetWindowText(hPubKeyEditBox, value);
    } else if (!lstrcmp(name, _T("TBSDATA"))) {
        SetWindowText(hTbsDataEditBox, value);
    } else if (!lstrcmp(name, _T("SIGNATURE"))) {
        SetWindowText(hSignatureEditBox, value);
    }

#undef __SELECT_OPTION_EX
#undef __SELECT_OPTION
}

BOOL OnEcdsaWindowClose()
{
    return FALSE;
}

HWND CreateEcdsaWindow(HWND hWnd)
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