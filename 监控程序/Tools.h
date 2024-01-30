#pragma once

#include <windows.h>
#include <stdarg.h>
#include <tchar.h>
#include <stdio.h>

class Tools
{
public:
	//提权
	static BOOL AdjustPrivileges(HANDLE hProcess, LPCTSTR lpPrivilegeName);
	//调试输出
	static VOID OutputDebugStringFormat(const TCHAR* format, ...);
	//调试输出
	static VOID OutputDebugStringFormatA(const CHAR* format, ...);
};

