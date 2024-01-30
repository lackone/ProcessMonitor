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
 * MessageBoxA的参数
 */
VOID DataPacket::SetMsgBoxAParams(IN LPCSTR lpText, IN LPCSTR lpCaption)
{
	yyjson_mut_doc* doc = yyjson_mut_doc_new(NULL);
	yyjson_mut_val* root = yyjson_mut_obj(doc);
	yyjson_mut_doc_set_root(doc, root);


	yyjson_mut_obj_add_str(doc, root, "lpText", lpText);
	yyjson_mut_obj_add_str(doc, root, "lpCaption", lpCaption);

	LPCSTR json = yyjson_mut_write(doc, 0, NULL);
	if (json) {
		SetParams(json);
		free((void*)json);
	}

	yyjson_mut_doc_free(doc);
}

/**
 * 解析MessageBoxA的参数
 */
VOID DataPacket::ParseMsgBoxAParams(OUT LPCSTR* lpText, OUT LPCSTR* lpCaption)
{
	yyjson_doc* doc = yyjson_read(params, strlen(params), 0);
	yyjson_val* root = yyjson_doc_get_root(doc);

	yyjson_val* text = yyjson_obj_get(root, "lpText");
	LPCSTR textTmp = yyjson_get_str(text);
	size_t len = strlen(textTmp) + 1;
	LPCSTR textBuf = (LPCSTR)malloc(len);
	memset((void*)textBuf, 0, len);
	strcpy_s((char*)textBuf, len, textTmp);
	*lpText = textBuf;

	yyjson_val* caption = yyjson_obj_get(root, "lpCaption");
	LPCSTR captionTmp = yyjson_get_str(caption);
	len = strlen(captionTmp) + 1;
	LPCSTR captionBuf = (LPCSTR)malloc(len);
	memset((void*)captionBuf, 0, len);
	strcpy_s((char*)captionBuf, len, captionTmp);
	*lpCaption = captionBuf;

	yyjson_doc_free(doc);
}

/**
 * CreateFileA的参数
 */
VOID DataPacket::SetCreateFileAParams(IN LPCSTR lpFileName, IN LPCSTR lpContent)
{
	yyjson_mut_doc* doc = yyjson_mut_doc_new(NULL);
	yyjson_mut_val* root = yyjson_mut_obj(doc);
	yyjson_mut_doc_set_root(doc, root);

	yyjson_mut_obj_add_str(doc, root, "lpFileName", lpFileName);
	yyjson_mut_obj_add_str(doc, root, "lpContent", lpContent);

	LPCSTR json = yyjson_mut_write(doc, 0, NULL);
	if (json) {
		SetParams(json);
		free((void*)json);
	}

	yyjson_mut_doc_free(doc);
}

/**
 * 解析CreateFileA的参数
 */
VOID DataPacket::ParseCreateFileAParams(OUT LPCSTR* lpFileName, OUT LPCSTR* lpContent)
{
	yyjson_doc* doc = yyjson_read(params, strlen(params), 0);
	yyjson_val* root = yyjson_doc_get_root(doc);

	yyjson_val* fileName = yyjson_obj_get(root, "lpFileName");
	LPCSTR fileNameTmp = yyjson_get_str(fileName);
	size_t len = strlen(fileNameTmp) + 1;
	LPCSTR fileNameBuf = (LPCSTR)malloc(len);
	memset((void*)fileNameBuf, 0, len);
	strcpy_s((char*)fileNameBuf, len, fileNameTmp);
	*lpFileName = fileNameBuf;

	yyjson_val* content = yyjson_obj_get(root, "lpContent");
	LPCSTR contentTmp = yyjson_get_str(content);
	len = strlen(contentTmp) + 1;
	LPCSTR contentBuf = (LPCSTR)malloc(len);
	memset((void*)contentBuf, 0, len);
	strcpy_s((char*)contentBuf, len, contentTmp);
	*lpContent = contentBuf;

	yyjson_doc_free(doc);
}

/**
 * OpenProcess的参数
 */
VOID DataPacket::SetOpenProcessAParams(IN LPCSTR lpApplicationName, IN LPCSTR lpCommandLine)
{
	yyjson_mut_doc* doc = yyjson_mut_doc_new(NULL);
	yyjson_mut_val* root = yyjson_mut_obj(doc);
	yyjson_mut_doc_set_root(doc, root);

	yyjson_mut_obj_add_str(doc, root, "lpApplicationName", lpApplicationName);
	yyjson_mut_obj_add_str(doc, root, "lpCommandLine", lpCommandLine);

	LPCSTR json = yyjson_mut_write(doc, 0, NULL);
	if (json) {
		SetParams(json);
		free((void*)json);
	}

	yyjson_mut_doc_free(doc);
}

/**
 * 解析OpenProcess的参数
 */
VOID DataPacket::ParseOpenProcessAParams(OUT LPCSTR* lpApplicationName, OUT LPCSTR* lpCommandLine)
{
	yyjson_doc* doc = yyjson_read(params, strlen(params), 0);
	yyjson_val* root = yyjson_doc_get_root(doc);

	yyjson_val* applicationName = yyjson_obj_get(root, "lpApplicationName");
	LPCSTR applicationNameTmp = yyjson_get_str(applicationName);
	size_t len = strlen(applicationNameTmp) + 1;
	LPCSTR applicationNameBuf = (LPCSTR)malloc(len);
	memset((void*)applicationNameBuf, 0, len);
	strcpy_s((char*)applicationNameBuf, len, applicationNameTmp);
	*lpApplicationName = applicationNameBuf;

	yyjson_val* commandLine = yyjson_obj_get(root, "lpCommandLine");
	LPCSTR commandLineTmp = yyjson_get_str(commandLine);
	len = strlen(commandLineTmp) + 1;
	LPCSTR commandLineBuf = (LPCSTR)malloc(len);
	memset((void*)commandLineBuf, 0, len);
	strcpy_s((char*)commandLineBuf, len, commandLineTmp);
	*lpCommandLine = commandLineBuf;

	yyjson_doc_free(doc);
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