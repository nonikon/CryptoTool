#ifndef _UTILS_H_
#define _UTILS_H_

#include <windows.h>
#include <tchar.h>

TCHAR* trimFilePath(TCHAR* path, UINT maxl);
UCHAR* ReadFileOnce(CONST TCHAR* path, UINT* n);
BOOL WriteFileOnce(CONST TCHAR* path, UCHAR* b, UINT l);
BOOL IsFile(CONST TCHAR* path);

#endif