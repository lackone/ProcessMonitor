#pragma once

#include <windows.h>
#include "yyjson.h"

class DataPacket
{
public:
	CHAR method[64]; //����
	CHAR params[1024]; //������������ʹ��YYJSON�����л�
public:
	DataPacket();
	SIZE_T GetTotalSize();
	SIZE_T GetMethodSize();
	SIZE_T GetParamsSize();
	//���÷���
	VOID SetMethod(IN LPCSTR method);
	//���ò���
	VOID SetParams(IN LPCSTR params);
	//����MsgBoxA����
	VOID SetMsgBoxAParams(IN LPCSTR lpText, IN LPCSTR lpCaption);
	//����MsgBoxA����
	VOID ParseMsgBoxAParams(OUT LPCSTR* lpText, OUT LPCSTR* lpCaption);
	//����CreateFileA����
	VOID SetCreateFileAParams(IN LPCSTR lpFileName, IN LPCSTR lpContent);
	//����CreateFileA����
	VOID ParseCreateFileAParams(OUT LPCSTR* lpFileName, OUT LPCSTR* lpContent);
	//����OpenProcess����
	VOID SetOpenProcessAParams(IN LPCSTR lpApplicationName, IN LPCSTR lpCommandLine);
	//����OpenProcess����
	VOID ParseOpenProcessAParams(OUT LPCSTR* lpApplicationName, OUT LPCSTR* lpCommandLine);
	//��MapViewд����
	VOID MapViewWriteData(IN LPVOID view);
	//��MapView������
	VOID MapViewReadData(IN LPVOID view);
};

