#include "DataPacket.h"

DataPacket::DataPacket()
{
	memset(method, 0, GetMethodSize());
	memset(params, 0, GetParamsSize());
}

SIZE_T DataPacket::GetMethodSize()
{
	return _countof(method) * sizeof(CHAR);
}

SIZE_T DataPacket::GetParamsSize()
{
	return _countof(params) * sizeof(CHAR);
}

SIZE_T DataPacket::GetTotalSize()
{
	return GetMethodSize() + GetParamsSize();
}

VOID DataPacket::SetMethod(IN LPCSTR method)
{
	memset(this->method, 0, GetMethodSize());
	memcpy(this->method, method, strlen(method) + 1);
}

VOID DataPacket::SetParams(IN LPCSTR params)
{
	memset(this->params, 0, GetParamsSize());
	memcpy(this->params, params, strlen(params) + 1);
}

/**
 * MessageBoxA的参数HWND也无法传递
 */
VOID DataPacket::SetMsgBoxA(
	_In_opt_ LPCSTR lpText,
	_In_opt_ LPCSTR lpCaption,
	_In_ UINT uType
)
{
	yyjson_mut_doc* doc = yyjson_mut_doc_new(NULL);
	yyjson_mut_val* root = yyjson_mut_obj(doc);
	yyjson_mut_doc_set_root(doc, root);


	yyjson_mut_obj_add_str(doc, root, "lpText", lpText);
	yyjson_mut_obj_add_str(doc, root, "lpCaption", lpCaption);
	yyjson_mut_obj_add_uint(doc, root, "uType", uType);

	LPCSTR json = yyjson_mut_write(doc, 0, NULL);
	if (json) {
		SetParams(json);
		free((void*)json);
	}

	yyjson_mut_doc_free(doc);
}

/**
 * CreateFileA另外两个参数，一个指针lpSecurityAttributes，一个hTemplateFile，通过进程间通信传过去数据也是无效的。
 */
VOID DataPacket::SetCreateFileA(
	_In_ LPCSTR lpFileName,
	_In_ DWORD dwDesiredAccess,
	_In_ DWORD dwShareMode,
	_In_ DWORD dwCreationDisposition,
	_In_ DWORD dwFlagsAndAttributes
)
{
	yyjson_mut_doc* doc = yyjson_mut_doc_new(NULL);
	yyjson_mut_val* root = yyjson_mut_obj(doc);
	yyjson_mut_doc_set_root(doc, root);

	yyjson_mut_obj_add_str(doc, root, "lpText", lpFileName);
	yyjson_mut_obj_add_uint(doc, root, "dwDesiredAccess", dwDesiredAccess);
	yyjson_mut_obj_add_uint(doc, root, "dwShareMode", dwShareMode);
	yyjson_mut_obj_add_uint(doc, root, "dwCreationDisposition", dwCreationDisposition);
	yyjson_mut_obj_add_uint(doc, root, "dwFlagsAndAttributes", dwFlagsAndAttributes);

	LPCSTR json = yyjson_mut_write(doc, 0, NULL);
	if (json) {
		SetParams(json);
		free((void*)json);
	}

	yyjson_mut_doc_free(doc);
}

/**
 * 往MapView写数据
 */
VOID DataPacket::MapViewWriteData(IN LPVOID view)
{
	memcpy(view, method, GetMethodSize());
	memcpy((LPBYTE)view + GetMethodSize(), params, GetParamsSize());
}

/**
 * 往MapView读数据
 */
VOID DataPacket::MapViewReadData(IN LPVOID view)
{
	memcpy(method, view, GetMethodSize());
	memcpy(params, (LPBYTE)view + GetMethodSize(), GetParamsSize());
}