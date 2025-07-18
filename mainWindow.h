#ifndef _MAIN_WINDOW_H_
#define _MAIN_WINDOW_H_

#include <stdio.h>
#include <windows.h>
#include <commctrl.h>
#include <tchar.h>

#include "common.h"
#include "resource.h"

#define VERSION_STRING      _T("V2.2-DEV")

#define CONFIG_FILENAME     _T("CryptoTool.ini")
#define MAX_INFILE_SIZE     (128 * 1024)
#define FILE_RBUF_SIZE      (16 * 1024)

#define WND_TITLE           _T("CryptoTool ") VERSION_STRING
#define WND_FONTNAME        _T("Calibri Light")
#define WND_FONTSIZE        (18)
#define WND_ALIGN           (4)
#define WND_LINEH           (WND_FONTSIZE + 6)
#define WND_COMBOXW         (96)
#define WND_BUTTONW         (80)

extern HINSTANCE hMainInstance;
extern HWND hMainWindow;

HWND CreateSymmWindow(HWND hWnd);
HWND CreateDigestWindow(HWND hWnd);
HWND CreateRandomWindow(HWND hWnd);
HWND CreateConvertWindow(HWND hWnd);

BOOL OnSymmWindowClose();
BOOL OnDigestWindowClose();
BOOL OnRandomWindowClose();
BOOL OnConvertWindowClose();

VOID OnSymmConfigItem(CONST TCHAR* name, CONST TCHAR* value);
VOID OnDigestConfigItem(CONST TCHAR* name, CONST TCHAR* value);
VOID OnRandomConfigItem(CONST TCHAR* name, CONST TCHAR* value);
VOID OnConvertConfigItem(CONST TCHAR* name, CONST TCHAR* value);

VOID OnSymmConfigSave(FILE* fp);
VOID OnDigestConfigSave(FILE* fp);
VOID OnRandomConfigSave(FILE* fp);
VOID OnConvertConfigSave(FILE* fp);

#endif