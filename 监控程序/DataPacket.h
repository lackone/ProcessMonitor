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
	VOID SetMsgBoxAParams(IN LPCSTR lpText, IN LPCSTR lpCaption);
	//解析MsgBoxA参数
	VOID ParseMsgBoxAParams(OUT LPCSTR* lpText, OUT LPCSTR* lpCaption);
	//设置CreateFileA参数
	VOID SetCreateFileAParams(IN LPCSTR lpFileName, IN LPCSTR lpContent);
	//解析CreateFileA参数
	VOID ParseCreateFileAParams(OUT LPCSTR* lpFileName, OUT LPCSTR* lpContent);
	//设置OpenProcess参数
	VOID SetOpenProcessAParams(IN LPCSTR lpApplicationName, IN LPCSTR lpCommandLine);
	//解析OpenProcess参数
	VOID ParseOpenProcessAParams(OUT LPCSTR* lpApplicationName, OUT LPCSTR* lpCommandLine);
	//往MapView写数据
	VOID MapViewWriteData(IN LPVOID view);
	//往MapView读数据
	VOID MapViewReadData(IN LPVOID view);
};

