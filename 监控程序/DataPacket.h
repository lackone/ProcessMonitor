#pragma once

#include <windows.h>
#include "yyjson.h"

class DataPacket
{
public:
	CHAR method[64]; //方法
	CHAR params[1024]; //参数，该数据使用YYJSON来序列化
public:
	DataPacket();
	SIZE_T GetTotalSize();
	SIZE_T GetMethodSize();
	SIZE_T GetParamsSize();
	//设置方法
	VOID SetMethod(IN LPCSTR method);
	//设置参数
	VOID SetParams(IN LPCSTR params);
	//设置MsgBoxA参数
	VOID SetMsgBoxA(_In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);
	//设置CreateFileA参数
	VOID SetCreateFileA(_In_ LPCSTR lpFileName, _In_ DWORD dwDesiredAccess, _In_ DWORD dwShareMode, _In_ DWORD dwCreationDisposition, _In_ DWORD dwFlagsAndAttributes);
	//往MapView写数据
	VOID MapViewWriteData(IN LPVOID view);
	//往MapView读数据
	VOID MapViewReadData(IN LPVOID view);
};

