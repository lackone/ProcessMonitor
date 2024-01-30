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
	VOID SetMsgBoxA(_In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);
	//����CreateFileA����
	VOID SetCreateFileA(_In_ LPCSTR lpFileName, _In_ DWORD dwDesiredAccess, _In_ DWORD dwShareMode, _In_ DWORD dwCreationDisposition, _In_ DWORD dwFlagsAndAttributes);
	//��MapViewд����
	VOID MapViewWriteData(IN LPVOID view);
	//��MapView������
	VOID MapViewReadData(IN LPVOID view);
};

