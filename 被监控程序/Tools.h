#pragma once

#include <windows.h>
#include <stdio.h>

class Tools
{
public:
	//将TCHAR转换成为CHAR
	VOID TCHARToChar(IN LPCTSTR tstr, OUT LPSTR* str);
};

