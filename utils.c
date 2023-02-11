#include "utils.h"

TCHAR* trimFilePath(TCHAR* path, UINT maxl)
{
    UINT l = lstrlen(path);

    if (l > maxl) {
        path[maxl - 3] = (TCHAR) '.';
        path[maxl - 2] = (TCHAR) '.';
        path[maxl - 1] = (TCHAR) '.';
        path[maxl - 0] = (TCHAR) '\0';
    }
    return path;
}

UCHAR* ReadFileOnce(CONST TCHAR* path, UINT* n)
{
    HANDLE h = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    LARGE_INTEGER sz;
    UCHAR* b = NULL;

    if (h == INVALID_HANDLE_VALUE)
        return NULL;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart > *n)
        goto done;

    b = malloc(sz.LowPart);
    if (!b)
        goto done;

    ReadFile(h, b, sz.LowPart, n, NULL);

    if (*n != sz.LowPart) {
        free(b);
        b = NULL;
    }
done:
    CloseHandle(h);
    return b;
}

BOOL WriteFileOnce(CONST TCHAR* path, UCHAR* b, UINT l)
{
    HANDLE h = CreateFile(path, GENERIC_WRITE, 0, NULL,
                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD nw;

    if (h == INVALID_HANDLE_VALUE)
        return FALSE;
    WriteFile(h, b, l, &nw, NULL);

    CloseHandle(h);
    return nw == l;
}

BOOL IsFile(CONST TCHAR* path)
{
    DWORD r = GetFileAttributesA(path);
    /* path exists && not a directory */
    return INVALID_FILE_ATTRIBUTES != r && !(FILE_ATTRIBUTE_DIRECTORY & r);
}
