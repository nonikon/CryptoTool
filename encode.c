#include <stdlib.h>
#include <ctype.h>

#include "encode.h"

static const char tb_hex_e[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
};

static const char tb_base64_e[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
};

static const unsigned char tb_hex_d[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*0~15*/
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*16~31*/
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*32~47*/
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1, /*48~63*/
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*64~79*/
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*80~95*/
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*64~79*/
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*112~127*/
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

static const unsigned char tb_base64_d[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*0~15*/
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*16~31*/
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, /*32~47*/
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, /*48~63*/
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, /*64~79*/
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, /*80~95*/
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, /*96~111*/
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, /*112~127*/
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

int TrimSpace(char* s)
{
    unsigned i = 0, j = 0;

    while (s[i]) {
        if (!isspace(s[i])) {
            if (i != j) {
                s[j] = s[i];
            }
            j += 1;
        }
        i += 1;
    }

    if (i == j)
        return 0;
    s[j] = 0;
    return 1;
}

int HexCharsToBinary(char* s)
{
    unsigned char* p = (unsigned char*) s;
    unsigned char* b = (unsigned char*) s;
    unsigned char c[2];

    while (p[0]) {
        c[0] = tb_hex_d[p[0]]; /* p[0] == 0 included */
        if (c[0] >= 16)
            return -1;

        c[1] = tb_hex_d[p[1]]; /* p[0] == 0 included */
        if (c[1] >= 16)
            return -1;

        *b++ = c[0] << 4 | c[1];

        p += 2;
    }

    return (int) (b - (unsigned char*) s);
}

int Base64CharsToBinary(char* s)
{
    unsigned char* p = (unsigned char*) s;
    unsigned char* b = (unsigned char*) s;
    unsigned char c[4];

    while (p[0]) {
        c[0] = tb_base64_d[p[0]]; /* p[0] == 0 included */
        if (c[0] >= 64)
            return -1;

        c[1] = tb_base64_d[p[1]]; /* p[1] == 0 included */
        if (c[1] >= 64)
            return -1;

        c[2] = tb_base64_d[p[2]]; /* p[2] == 0 included */
        if (c[2] >= 64) {
            if (p[2] != '=' || p[3] != '=' || p[4] != '\0')
                return -1;

            *b++ = c[0] << 2 | c[1] >> 4;
            break;
        }

        c[3] = tb_base64_d[p[3]]; /* p[3] == 0 included */
        if (c[3] >= 64) {
            if (p[3] != '=' || p[4] != '\0')
                return -1;

            *b++ = c[0] << 2 | c[1] >> 4;
            *b++ = c[1] << 4 | c[2] >> 2;
            break;
        }

        *b++ = c[0] << 2 | c[1] >> 4;
        *b++ = c[1] << 4 | c[2] >> 2;
        *b++ = c[2] << 6 | c[3];

        p += 4;
    }

    return (int) (b - (unsigned char*) s);
}

int CArrayCharsToBinary(char* s)
{
    unsigned char* p = (unsigned char*) s;
    unsigned char* b = (unsigned char*) s;
    unsigned char c[2];

    /* 0x11,0x22, */
    while (p[0]) {
        if (p[0] != '0' || p[1] != 'x')
            return -1;

        c[0] = tb_hex_d[p[2]]; /* p[2] == 0 included */
        if (c[0] >= 16)
            return -1;

        c[1] = tb_hex_d[p[3]]; /* p[3] == 0 included */
        if (c[1] >= 16)
            return -1;

        *b++ = c[0] << 4 | c[1];

        if (p[4] == ',') {
            p += 5;
            continue;
        }
        if (p[4] == '\0')
            break;

        return -1; /* p[4] != '\0' */
    }

    return (int) (b - (unsigned char*) s);
}

int CStringCharsToBinary(char* s)
{
    unsigned char* p = (unsigned char*) s;
    unsigned char* b = (unsigned char*) s;
    unsigned char c[2];

    /* \x11\x22 */
    while (p[0]) {
        if (p[0] != '\\' || p[1] != 'x')
            return -1;

        c[0] = tb_hex_d[p[2]]; /* p[2] == 0 included */
        if (c[0] >= 16)
            return -1;

        c[1] = tb_hex_d[p[3]]; /* p[3] == 0 included */
        if (c[1] >= 16)
            return -1;

        *b++ = c[0] << 4 | c[1];

        p += 4;
    }

    return (int) (b - (unsigned char*) s);
}

char* BinaryToHexChars(const unsigned char* b, unsigned l)
{
    char* s = malloc(l * 2 + 1);
    unsigned i;

    for (i = 0; i < l; ++i) {
        s[i * 2 + 0] = tb_hex_e[b[i] >> 4];
        s[i * 2 + 1] = tb_hex_e[b[i] & 0x0F];
    }

    s[l * 2] = 0;
    return s;
}

char* BinaryToBase64Chars(const unsigned char* b, unsigned l)
{
    char* s = malloc((l + 2) / 3 * 4 + 1);
    char* _s = s;
    const unsigned char* _b = b;

    while (l >= 3) {
        *_s++ = tb_base64_e[(_b[0] >> 2)];
        *_s++ = tb_base64_e[(_b[0] << 4 | _b[1] >> 4) & 0x3F];
        *_s++ = tb_base64_e[(_b[1] << 2 | _b[2] >> 6) & 0x3F];
        *_s++ = tb_base64_e[(_b[2] & 0x3F)];

        _b += 3;
        l -= 3;
    }

    if (l) {
        *_s++ = tb_base64_e[(_b[0] >> 2)];
        if (l > 1) {
            *_s++ = tb_base64_e[(_b[0] << 4 | _b[1] >> 4) & 0x3F];
            *_s++ = tb_base64_e[(_b[1] << 2) & 0x3F];
        } else {
            *_s++ = tb_base64_e[(_b[0] << 4) & 0x3F];
            *_s++ = '=';
       }
        *_s++ = '=';
    }
    *_s = 0;

    return s;
}

char* BinaryToCArrayChars(const unsigned char* b, unsigned l)
{
    char* s = malloc(5 * l + 1); /* 0x00, */
    unsigned i;

    for (i = 0; i < l; ++i) {
        s[i * 5 + 0] = '0';
        s[i * 5 + 1] = 'x';
        s[i * 5 + 2] = tb_hex_e[b[i] >> 4];
        s[i * 5 + 3] = tb_hex_e[b[i] & 0x0F];
        s[i * 5 + 4] = ',';
    }

    s[l * 5] = 0;
    return s;
}

char* BinaryToCStringChars(const unsigned char* b, unsigned l)
{
    char* s = malloc(4 * l + 1); /* \x00 */
    unsigned i;

    for (i = 0; i < l; ++i) {
        s[i * 4 + 0] = '\\';
        s[i * 4 + 1] = 'x';
        s[i * 4 + 2] = tb_hex_e[b[i] >> 4];
        s[i * 4 + 3] = tb_hex_e[b[i] & 0x0F];
    }

    s[l * 4] = 0;
    return s;
}