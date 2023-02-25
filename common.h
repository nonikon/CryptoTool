#ifndef _COMMON_H_
#define _COMMON_H_

#include <windows.h>
#include <tchar.h>

#define GETBTCHCK(hWnd)     (SendMessage(hWnd, BM_GETCHECK, 0, 0) == BST_CHECKED)
#define SETBTCHCK(hWnd, on) SendMessage(hWnd, BM_SETCHECK, on ? BST_CHECKED : BST_UNCHECKED, 0)

#define GETCBOPT(hWnd)      (INT) SendMessage(hWnd, CB_GETCURSEL, 0, 0)
#define SETCBOPT(hWnd, opt) SendMessage(hWnd, CB_SETCURSEL, opt, 0)

#define INFO(...)           FormatMessageBox(hMainWindow, MB_OK, _T("INFO"), ##__VA_ARGS__)
#define WARN(...)           FormatMessageBox(hMainWindow, MB_OK, _T("WARN"), ##__VA_ARGS__)
#define CONFIRM(...)        FormatMessageBox(hMainWindow, MB_OKCANCEL, _T("WARN"), ##__VA_ARGS__)

#define TRIMPATH(path)      TrimFilePath(path, 32)

VOID SetChildWindowsFont(HWND hWnd, HFONT hFont);
VOID FormatTextTo(HWND hWnd, CONST TCHAR* fmt, ...);
INT FormatMessageBox(HWND hWnd, UINT type, CONST TCHAR* title, CONST TCHAR* fmt, ...);
TCHAR* GetTextOnce(HWND hWnd);
TCHAR* TrimFilePath(TCHAR* path, UINT maxl);
UCHAR* ReadFileOnce(CONST TCHAR* path, UINT* n);
BOOL WriteFileOnce(CONST TCHAR* path, UCHAR* b, UINT l);
BOOL IsFile(CONST TCHAR* path);

#endif