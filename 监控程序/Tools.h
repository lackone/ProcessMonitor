#pragma once

#include <windows.h>
#include <stdarg.h>
#include <tchar.h>
#include <stdio.h>

class Tools
{
public:
	//��Ȩ
	static BOOL AdjustPrivileges(HANDLE hProcess, LPCTSTR lpPrivilegeName);
	//�������
	static VOID OutputDebugStringFormat(const TCHAR* format, ...);
	//�������
	static VOID OutputDebugStringFormatA(const CHAR* format, ...);
};

