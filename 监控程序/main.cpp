#include <windows.h>
#include <Psapi.h>
#include <stdio.h>
#include "resource.h"
#include "PETools.h"
#include "Tools.h"
#include "DataPacket.h"

//����һЩ����ָ������
typedef int (WINAPI* MBA)(HWND, LPCSTR, LPCSTR, UINT);
typedef HANDLE(WINAPI* CFA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE(WINAPI* CFW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI* CPA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef HANDLE(WINAPI* OP)(DWORD, BOOL, DWORD);

//���ھ��
HWND pidEdit;
HWND msgBoxMonitorBtn;
HWND createFileMonitorBtn;
HWND openProcessMonitorBtn;
HWND msgBoxCallTitle;
HWND msgBoxCallContent;
HWND createFileCallPath;
HWND createFileCallContent;
HWND openProcessCallPath;
//�����жϼ���Ƿ���
BOOL isMsgBoxMonitor = FALSE;
BOOL isCreateFileMonitor = FALSE;
BOOL isOpenProcessMonitor = FALSE;
//�����־�ļ�
HANDLE monitorLog;
TCHAR monitorLogPath[MAX_PATH]{ 0 };
HANDLE monitorLogEvent;
//����
Tools tools;
PETools pe;
DataPacket dp;
//�����ڴ�
HANDLE hMapObject;
HANDLE hMapView;
//�¼�����mapView�ɶ�����д
HANDLE hMapViewRead;
HANDLE hMapViewWrite;
//���ڱ���InlineHook����
CHAR szBuffer[MAX_PATH]{ 0 };
DWORD dwDesiredAccess;
BOOL bInheritHandle;
DWORD dwProcessId;
LPVOID oldData;
//OpenProcess�����Ļ�ַ�������ַ���ǲ���ʱ��Ҫ�����޸�
DWORD openProcessAddress = 0x75BEFC00;
DWORD oldJmp;

//CreateFileWָ��
CFW cfw;

/**
 * ע�⣬��Ҫ�滻�ĺ�����Ӧ������д�ĺ�����������һ��
 */
int WINAPI MyMsgBoxA(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType)
{
	//ע�����ﲻ��ֱ�ӵ���MessageBoxA����Ϊ�Ѿ��������滻�ˣ�ֱ�ӵ�����ѭ��
	MBA mba = (MBA)GetProcAddress(LoadLibrary(TEXT("user32.dll")), "MessageBoxA");

	int ret = mba(hWnd, lpText, lpCaption, uType);

	CHAR buf[MAX_PATH]{ 0 };
	sprintf_s(buf, MAX_PATH, "MessageBoxA ��ȡ���Ĳ��� %d %s %s %d ���ý�� %d\n", (DWORD)hWnd, lpText, lpCaption, uType);

	tools.OutputDebugStringFormatA("%s\n", buf);

	monitorLogEvent = OpenEvent(EVENT_ALL_ACCESS, FALSE, TEXT("MonitorLogEvent"));

	WaitForSingleObject(monitorLogEvent, INFINITE);
	//д�����ļ�
	cfw = (CFW)GetProcAddress(LoadLibrary(TEXT("Kernel32.dll")), "CreateFileW");
	HANDLE log = cfw(monitorLogPath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	SetFilePointer(log, 0, NULL, FILE_END);
	if (!WriteFile(log, buf, strlen(buf) + 1, NULL, NULL))
	{
		tools.OutputDebugStringFormat(TEXT("д����־ʧ�� %d\n"), GetLastError());
	}
	CloseHandle(log);
	SetEvent(monitorLogEvent);

	return ret;
}

/**
 * ע�⣬��Ҫ�滻�ĺ�����Ӧ������д�ĺ�����������һ��
 */
HANDLE WINAPI MyCreateFileA(
	_In_ LPCSTR lpFileName,
	_In_ DWORD dwDesiredAccess,
	_In_ DWORD dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_ DWORD dwCreationDisposition,
	_In_ DWORD dwFlagsAndAttributes,
	_In_opt_ HANDLE hTemplateFile
)
{
	CFA cfa = (CFA)GetProcAddress(LoadLibrary(TEXT("Kernel32.dll")), "CreateFileA");

	HANDLE h = cfa(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

	CHAR buf[MAX_PATH]{ 0 };
	sprintf_s(buf, MAX_PATH, "CreateFileA ��ȡ���Ĳ��� %s %d %d %x %d %d %d ���ý�� %d\n", lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, h);

	tools.OutputDebugStringFormatA("%s\n", buf);

	monitorLogEvent = OpenEvent(EVENT_ALL_ACCESS, FALSE, TEXT("MonitorLogEvent"));

	WaitForSingleObject(monitorLogEvent, INFINITE);
	cfw = (CFW)GetProcAddress(LoadLibrary(TEXT("Kernel32.dll")), "CreateFileW");
	HANDLE log = cfw(monitorLogPath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	SetFilePointer(log, 0, NULL, FILE_END);
	//д�����ļ�
	if (!WriteFile(log, buf, strlen(buf) + 1, NULL, NULL))
	{
		tools.OutputDebugStringFormat(TEXT("д����־ʧ�� %d\n"), GetLastError());
	}
	CloseHandle(log);
	SetEvent(monitorLogEvent);

	return h;
}

/**
 * �������ѵ�OpenProcess
 */
extern "C" __declspec(naked) void myOpenProcess()
{
	//����Ĵ���
	__asm
	{
		pushad
		pushfd
	}

	//pushad�ᱣ��8��4�ֽڵļĴ���32
	//pushfd�ᱣ��4���ֽڵ�EFLAGS
	//�������������ջ֮ǰ���д�����滻����ֻ��ͨ��ESP���Ҳ���
	//���û��pushad��pushfd������һΪ ESP+4��������Ϊ ESP+8
	//����һΪ ESP + 0x28��32 + 4 + 4��
	//������Ϊ ESP + 0x2c (32 + 4 + 8��
	//����������������ջ֮����д�����滻�����������ҿ�����EBP���Ҳ���
	//����һΪ EBP + 0x8
	//������Ϊ EBP + 0xc

	//��ȡ����
	__asm
	{
		mov EAX, dword ptr[EBP + 0x8]
		mov dwDesiredAccess, EAX
		mov EAX, dword ptr[EBP + 0xc]
		mov bInheritHandle, EAX
		mov EAX, dword ptr[EBP + 0x10]
		mov dwProcessId, EAX
	}

	sprintf_s(szBuffer, MAX_PATH, "OpenProcess ��ȡ���Ĳ��� %d %d %d\n", dwDesiredAccess, bInheritHandle, dwProcessId);

	tools.OutputDebugStringFormatA("%s", szBuffer);

	monitorLogEvent = OpenEvent(EVENT_ALL_ACCESS, FALSE, TEXT("MonitorLogEvent"));
	WaitForSingleObject(monitorLogEvent, INFINITE);
	//д�����ļ�
	cfw = (CFW)GetProcAddress(LoadLibrary(TEXT("Kernel32.dll")), "CreateFileW");
	monitorLog = cfw(monitorLogPath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (monitorLog == INVALID_HANDLE_VALUE)
	{
		tools.OutputDebugStringFormat(TEXT("��ȡ��־���ʧ�� %d\n"), GetLastError());
	}
	SetFilePointer(monitorLog, 0, NULL, FILE_END);
	if (!WriteFile(monitorLog, szBuffer, strlen(szBuffer) + 1, NULL, NULL))
	{
		tools.OutputDebugStringFormat(TEXT("д����־ʧ�� %d\n"), GetLastError());
	}
	CloseHandle(monitorLog);
	SetEvent(monitorLogEvent);

	//�ָ��Ĵ���
	__asm
	{
		popfd
		popad
	}

	//ִ��֮ǰ�滻�Ĵ���
	__asm
	{
		mov eax, dword ptr[ebp + 10h]
		xor ecx, ecx
	}

	//����ԭ���ĵط�
	__asm
	{
		jmp oldJmp
	}
}

/**
 * ע�����
 */
DWORD WINAPI InjectEntry(LPVOID pImageBuffer)
{
	//�޸�IAT��
	pe.RepairIAT(pImageBuffer);

	//��ȡ��ע����̵Ļ�ַ
	HMODULE injectModule = GetModuleHandle(NULL);
	HANDLE injectProcess = GetCurrentProcess();

	tools.OutputDebugStringFormat(TEXT("pImageBuffer 0x%x\n"), pImageBuffer);
	tools.OutputDebugStringFormat(TEXT("injectModule 0x%x\n"), injectModule);

	//��ȡ�����ڴ�
	HANDLE mapObj = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, dp.GetTotalSize(), TEXT("SharedMemory"));
	if (!mapObj)
	{
		tools.OutputDebugStringFormat(TEXT("���������ڴ�ʧ�� %d"), GetLastError());
	}

	tools.OutputDebugStringFormat(TEXT("mapObj 0x%x\n"), mapObj);

	//ӳ�乲���ڴ浽ע�����
	LPVOID mapView = MapViewOfFile(mapObj, FILE_MAP_WRITE, 0, 0, 0);
	if (!mapView)
	{
		tools.OutputDebugStringFormat(TEXT("�ڴ�ӳ��ʧ�� %d"), GetLastError());
	}

	tools.OutputDebugStringFormat(TEXT("mapView 0x%x\n"), mapView);

	//�¼�����mapView�ɶ�����д
	HANDLE read = OpenEvent(EVENT_ALL_ACCESS, FALSE, TEXT("MapViewRead"));
	HANDLE write = OpenEvent(EVENT_ALL_ACCESS, FALSE, TEXT("MapViewWrite"));

	tools.OutputDebugStringFormat(TEXT("read 0x%x\n"), read);
	tools.OutputDebugStringFormat(TEXT("write 0x%x\n"), write);

	DataPacket dpt;
	while (TRUE)
	{
		//�ȴ��¼�����ֹ���ݶ�ȡ����
		WaitForSingleObject(read, INFINITE);
		ResetEvent(read);

		dpt.MapViewReadData(mapView);

		tools.OutputDebugStringFormatA("%s\n", dpt.method);

		if (strcmp(dpt.method, "InstallIATHook_MessageBoxA") == 0)
		{
			//��ȡԭ������ַ
			FARPROC msgBoxA = GetProcAddress(LoadLibrary(TEXT("user32.dll")), "MessageBoxA");

			//��װHOOK
			pe.InstallIATHook((LPVOID)injectModule, (DWORD)msgBoxA, (DWORD)MyMsgBoxA);
		}
		if (strcmp(dpt.method, "UnInstallIATHook_MessageBoxA") == 0)
		{
			//��ȡԭ������ַ
			FARPROC msgBoxA = GetProcAddress(LoadLibrary(TEXT("user32.dll")), "MessageBoxA");

			//ж��HOOK
			pe.UnInstallIATHook((LPVOID)injectModule, (DWORD)msgBoxA, (DWORD)MyMsgBoxA);
		}
		if (strcmp(dpt.method, "InstallIATHook_CreateFileA") == 0)
		{
			//��ȡԭ������ַ
			FARPROC createFileA = GetProcAddress(LoadLibrary(TEXT("Kernel32.dll")), "CreateFileA");

			//��װHOOK
			pe.InstallIATHook((LPVOID)injectModule, (DWORD)createFileA, (DWORD)MyCreateFileA);
		}
		if (strcmp(dpt.method, "UnInstallIATHook_CreateFileA") == 0)
		{
			//��ȡԭ������ַ
			FARPROC createFileA = GetProcAddress(LoadLibrary(TEXT("Kernel32.dll")), "CreateFileA");

			//ж��HOOK
			pe.UnInstallIATHook((LPVOID)injectModule, (DWORD)createFileA, (DWORD)MyCreateFileA);
		}
		if (strcmp(dpt.method, "InstallInlineHook_OpenProcess") == 0)
		{
			//��ȡԭ������ַ
			//FARPROC openProcess = GetProcAddress(LoadLibrary(TEXT("Kernel32.dll")), "OpenProcess");
			//�����ȡ�ĵ�ַ������OpenProcess�����ĵ�ַ����Ϊ��VS�У�������תһ��������JMPһ�²Ż��������ĺ�����ַ��������������д����

			oldJmp = (DWORD)openProcessAddress + 8 + 5;

			pe.InstallInlineHook(injectProcess, (DWORD)openProcessAddress, (DWORD)myOpenProcess, 8, 5, &oldData);
		}
		if (strcmp(dpt.method, "UnInstallInlineHook_OpenProcess") == 0)
		{
			//��ȡԭ������ַ
			//FARPROC openProcess = GetProcAddress(LoadLibrary(TEXT("Kernel32.dll")), "OpenProcess");
			//�����ȡ�ĵ�ַ������OpenProcess�����ĵ�ַ����Ϊ��VS�У�������תһ��������JMPһ�²Ż��������ĺ�����ַ��������������д����

			pe.UnInstallInlineHook(injectProcess, (DWORD)openProcessAddress, 8, 5, oldData);
		}
		if (strcmp(dpt.method, "MsgBoxCall") == 0)
		{
			MBA mba = (MBA)GetProcAddress(LoadLibrary(TEXT("user32.dll")), "MessageBoxA");

			LPCSTR text = NULL;
			LPCSTR title = NULL;

			dpt.ParseMsgBoxAParams(&text, &title);

			tools.OutputDebugStringFormatA("MsgBoxCall %s %s\n", text, title);

			mba(NULL, text, title, MB_OK);

			free((void*)text);
			free((void*)title);
		}
		if (strcmp(dpt.method, "CreateFileCall") == 0)
		{
			CFA cfa = (CFA)GetProcAddress(LoadLibrary(TEXT("Kernel32.dll")), "CreateFileA");

			LPCSTR fileName = NULL;
			LPCSTR content = NULL;

			dpt.ParseCreateFileAParams(&fileName, &content);

			tools.OutputDebugStringFormatA("CreateFileCall %s %s\n", fileName, content);

			HANDLE hFile = cfa(fileName, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			SetFilePointer(hFile, 0, NULL, FILE_END);
			WriteFile(hFile, content, strlen(content) + 1, NULL, NULL);
			CloseHandle(hFile);

			free((void*)fileName);
			free((void*)content);
		}
		if (strcmp(dpt.method, "OpenProcessCall") == 0)
		{
			CPA cpa = (CPA)GetProcAddress(LoadLibrary(TEXT("Kernel32.dll")), "CreateProcessA");

			LPCSTR applicationName = NULL;
			LPCSTR commandLine = NULL;

			dpt.ParseOpenProcessAParams(&applicationName, &commandLine);

			tools.OutputDebugStringFormatA("OpenProcessCall %s %s\n", applicationName, commandLine);

			STARTUPINFOA si{ 0 };
			si.cb = sizeof(si);
			PROCESS_INFORMATION pi{ 0 };

			if (cpa(NULL, (LPSTR)commandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
			{
				OP op = (OP)GetProcAddress(LoadLibrary(TEXT("Kernel32.dll")), "OpenProcess");

				HANDLE hProcess = op(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);

				CloseHandle(hProcess);
			}
			else {
				tools.OutputDebugStringFormatA("OpenProcessCall error %d\n", GetLastError());
			}

			free((void*)applicationName);
			free((void*)commandLine);
		}

		SetEvent(write);

		Sleep(500);
	}
}

/**
 * ע��ģ��EXE
 */
DWORD WINAPI InjectEXE(LPVOID lpThreadParameter)
{
	//��ȡ��ǰ���̾��
	HMODULE hModule = GetModuleHandle(NULL);
	HANDLE hProcess = GetCurrentProcess();

	MODULEINFO moduleInfo;
	GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(moduleInfo));

	//��ȡ��ǰ���̵�ImageBase��SizeOfImage
	DWORD imageBase = (DWORD)moduleInfo.lpBaseOfDll;
	DWORD sizeOfImage = (DWORD)moduleInfo.SizeOfImage;

	//�����ڴ�
	LPVOID imageBuf = malloc(sizeOfImage);
	if (imageBuf == NULL)
	{
		tools.OutputDebugStringFormat(TEXT("�����ڴ�ʧ�� %d"), GetLastError());
		return 1;
	}
	memset(imageBuf, 0, sizeOfImage);

	//����ǰ���̵Ĵ��룬���������´����Ļ�������
	ReadProcessMemory(hProcess, (LPVOID)imageBase, imageBuf, sizeOfImage, NULL);

	//��ȡҪע����̵�hProcess
	TCHAR injectPidStr[MAX_PATH]{ 0 };
	GetWindowText(pidEdit, injectPidStr, MAX_PATH);
	DWORD injectPid = _ttoi(injectPidStr);

	//��Ҫע��Ľ���
	HANDLE injectProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, injectPid);
	if (injectProcess == NULL)
	{
		tools.OutputDebugStringFormat(TEXT("�򿪽���ʧ�� %d"), GetLastError());
		return 1;
	}

	//��ע������������ڴ�
	LPVOID address = VirtualAllocEx(injectProcess, NULL, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (address == NULL)
	{
		tools.OutputDebugStringFormat(TEXT("�����ڴ�ʧ�� %d"), GetLastError());
		return 1;
	}

	//�޸��ض�λ��
	if ((DWORD)address != imageBase)
	{
		DWORD offset = (DWORD)address - imageBase;
		pe.ReviseRelocation(imageBuf, offset);
	}

	//������д�뵽ע�������
	if (!WriteProcessMemory(injectProcess, address, imageBuf, sizeOfImage, NULL))
	{
		tools.OutputDebugStringFormat(TEXT("д������ʧ�� %d"), GetLastError());
		return 1;
	}

	//����Զ���߳�
	//���㺯���ڽ���A�еĵ�ַ = �����ڵ�ǰ���̵ĵ�ַ - ��ǰ���̵Ļ�ַ(ImageBase) + ����A������Ļ�ַ
	DWORD fn = (DWORD)InjectEntry - (DWORD)imageBase + (DWORD)address;

	HANDLE ht = CreateRemoteThread(injectProcess, NULL, 0, (LPTHREAD_START_ROUTINE)fn, address, 0, NULL);
	if (ht == NULL)
	{
		tools.OutputDebugStringFormat(TEXT("����Զ���߳�ʧ�� %d"), GetLastError());
		return 1;
	}

	CloseHandle(ht);

	MessageBox(NULL, TEXT("ע��ɹ�"), TEXT("�ɹ�"), MB_OK);

	return 0;
}

/**
 * MessageBoxA���
 */
DWORD WINAPI MsgBoxMonitor(LPVOID lpThreadParameter)
{
	if (isMsgBoxMonitor)
	{
		isMsgBoxMonitor = FALSE;
		SetWindowText(msgBoxMonitorBtn, TEXT("�������"));
	}
	else {
		isMsgBoxMonitor = TRUE;
		SetWindowText(msgBoxMonitorBtn, TEXT("�رռ��"));
	}

	if (isMsgBoxMonitor)
	{
		WaitForSingleObject(hMapViewWrite, INFINITE);
		ResetEvent(hMapViewWrite);

		dp.SetMethod("InstallIATHook_MessageBoxA");
		dp.MapViewWriteData(hMapView);

		SetEvent(hMapViewRead);
	}
	else {
		WaitForSingleObject(hMapViewWrite, INFINITE);
		ResetEvent(hMapViewWrite);

		dp.SetMethod("UnInstallIATHook_MessageBoxA");
		dp.MapViewWriteData(hMapView);

		SetEvent(hMapViewRead);
	}

	return 0;
}

/**
 * CreateFileA���
 */
DWORD WINAPI CreateFileMonitor(LPVOID lpThreadParameter)
{
	if (isCreateFileMonitor)
	{
		isCreateFileMonitor = FALSE;
		SetWindowText(createFileMonitorBtn, TEXT("�������"));
	}
	else {
		isCreateFileMonitor = TRUE;
		SetWindowText(createFileMonitorBtn, TEXT("�رռ��"));
	}

	if (isCreateFileMonitor)
	{
		WaitForSingleObject(hMapViewWrite, INFINITE);
		ResetEvent(hMapViewWrite);

		dp.SetMethod("InstallIATHook_CreateFileA");
		dp.MapViewWriteData(hMapView);

		SetEvent(hMapViewRead);
	}
	else {
		WaitForSingleObject(hMapViewWrite, INFINITE);
		ResetEvent(hMapViewWrite);

		dp.SetMethod("UnInstallIATHook_CreateFileA");
		dp.MapViewWriteData(hMapView);

		SetEvent(hMapViewRead);
	}

	return 0;
}

/**
 * OpenProcess���
 */
DWORD WINAPI OpenProcessMonitor(LPVOID lpThreadParameter)
{
	if (isOpenProcessMonitor)
	{
		isOpenProcessMonitor = FALSE;
		SetWindowText(openProcessMonitorBtn, TEXT("�������"));
	}
	else {
		isOpenProcessMonitor = TRUE;
		SetWindowText(openProcessMonitorBtn, TEXT("�رռ��"));
	}

	if (isOpenProcessMonitor)
	{
		WaitForSingleObject(hMapViewWrite, INFINITE);
		ResetEvent(hMapViewWrite);

		dp.SetMethod("InstallInlineHook_OpenProcess");
		dp.MapViewWriteData(hMapView);

		SetEvent(hMapViewRead);
	}
	else {
		WaitForSingleObject(hMapViewWrite, INFINITE);
		ResetEvent(hMapViewWrite);

		dp.SetMethod("UnInstallInlineHook_OpenProcess");
		dp.MapViewWriteData(hMapView);

		SetEvent(hMapViewRead);
	}

	return 0;
}

/**
 * Զ�̵���
 */
DWORD WINAPI MsgBoxCall(LPVOID lpThreadParameter)
{
	WaitForSingleObject(hMapViewWrite, INFINITE);
	ResetEvent(hMapViewWrite);

	TCHAR title[MAX_PATH]{ 0 };
	GetWindowText(msgBoxCallTitle, title, MAX_PATH);
	TCHAR content[MAX_PATH]{ 0 };
	GetWindowText(msgBoxCallContent, content, MAX_PATH);

	LPSTR titleStr = NULL;
	LPSTR contentStr = NULL;

	tools.TCHARToChar(title, &titleStr);
	tools.TCHARToChar(content, &contentStr);

	dp.SetMethod("MsgBoxCall");
	dp.SetMsgBoxAParams(contentStr, titleStr);
	dp.MapViewWriteData(hMapView);

	SetEvent(hMapViewRead);

	free(titleStr);
	free(contentStr);

	return 0;
}

/**
 * Զ�̵���
 */
DWORD WINAPI CreateFileCall(LPVOID lpThreadParameter)
{
	WaitForSingleObject(hMapViewWrite, INFINITE);
	ResetEvent(hMapViewWrite);

	TCHAR path[MAX_PATH]{ 0 };
	GetWindowText(createFileCallPath, path, MAX_PATH);
	TCHAR content[MAX_PATH]{ 0 };
	GetWindowText(createFileCallContent, content, MAX_PATH);

	LPSTR pathStr = NULL;
	LPSTR contentStr = NULL;

	tools.TCHARToChar(path, &pathStr);
	tools.TCHARToChar(content, &contentStr);

	dp.SetMethod("CreateFileCall");
	dp.SetCreateFileAParams(pathStr, contentStr);
	dp.MapViewWriteData(hMapView);

	SetEvent(hMapViewRead);

	free(pathStr);
	free(contentStr);

	return 0;
}

/**
 * Զ�̵���
 */
DWORD WINAPI OpenProcessCall(LPVOID lpThreadParameter)
{
	WaitForSingleObject(hMapViewWrite, INFINITE);
	ResetEvent(hMapViewWrite);

	TCHAR path[MAX_PATH]{ 0 };
	GetWindowText(openProcessCallPath, path, MAX_PATH);

	LPSTR pathStr = NULL;

	tools.TCHARToChar(path, &pathStr);

	dp.SetMethod("OpenProcessCall");
	dp.SetOpenProcessAParams("", pathStr);
	dp.MapViewWriteData(hMapView);

	SetEvent(hMapViewRead);

	free(pathStr);

	return 0;
}

INT_PTR CALLBACK dlgProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
	{
		pidEdit = GetDlgItem(hwnd, IDC_EDIT_INJECT_PID);
		msgBoxMonitorBtn = GetDlgItem(hwnd, IDC_BUTTON_MSGBOX_MONITOR);
		createFileMonitorBtn = GetDlgItem(hwnd, IDC_BUTTON_CREATEFILE_MONITOR);
		openProcessMonitorBtn = GetDlgItem(hwnd, IDC_BUTTON_OPENPROCESS_MONITOR);

		msgBoxCallTitle = GetDlgItem(hwnd, IDC_EDIT_MSGBOX_CALL_TITLE);
		msgBoxCallContent = GetDlgItem(hwnd, IDC_EDIT_MSGBOX_CALL_CONTENT);
		createFileCallPath = GetDlgItem(hwnd, IDC_EDIT_CREATEFILE_PATH);
		createFileCallContent = GetDlgItem(hwnd, IDC_EDIT_CREATEFILE_CONTENT);
		openProcessCallPath = GetDlgItem(hwnd, IDC_EDIT_OPENPROCESS_PAHT);

		//�������Log
		TCHAR exePath[MAX_PATH]{ 0 };
		GetModuleFileName(NULL, exePath, MAX_PATH);

		size_t ix = _tcsrchr(exePath, TEXT('\\')) - exePath;
		_tcsncpy_s(monitorLogPath, MAX_PATH, exePath, ix + 1);
		_tcscat_s(monitorLogPath, MAX_PATH, TEXT("monitor.log"));

		HANDLE monitorLogFile = CreateFile(monitorLogPath, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		if (monitorLogFile == INVALID_HANDLE_VALUE) {
			tools.OutputDebugStringFormat(TEXT("���������־ʧ�� %d"), GetLastError());
		}

		CloseHandle(monitorLogFile);

		//���������ڴ棬��ʵ�ֽ��̼��ͨ��
		hMapObject = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, dp.GetTotalSize(), TEXT("SharedMemory"));
		if (!hMapObject)
		{
			tools.OutputDebugStringFormat(TEXT("���������ڴ�ʧ�� %d"), GetLastError());
		}
		//��FileMapping����ӳ�䵽�Լ��Ľ���
		hMapView = MapViewOfFile(hMapObject, FILE_MAP_WRITE, 0, 0, 0);
		if (!hMapView)
		{
			tools.OutputDebugStringFormat(TEXT("�ڴ�ӳ��ʧ�� %d"), GetLastError());
		}

		//�����¼�����
		hMapViewRead = CreateEvent(NULL, TRUE, FALSE, TEXT("MapViewRead"));
		hMapViewWrite = CreateEvent(NULL, TRUE, TRUE, TEXT("MapViewWrite"));

		monitorLogEvent = CreateEvent(NULL, TRUE, TRUE, TEXT("MonitorLogEvent"));
	}
	return TRUE;
	case WM_CLOSE:
	{
		UnmapViewOfFile(hMapView);
		CloseHandle(hMapObject);

		CloseHandle(hMapViewRead);
		CloseHandle(hMapViewWrite);

		EndDialog(hwnd, 0);
	}
	return TRUE;
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_MSGBOX_MONITOR:
		{
			//ʹ��IATHook
			HANDLE ht = CreateThread(NULL, 0, MsgBoxMonitor, NULL, 0, NULL);
			CloseHandle(ht);
		}
		break;
		case IDC_BUTTON_CREATEFILE_MONITOR:
		{
			//ʹ��IATHook
			HANDLE ht = CreateThread(NULL, 0, CreateFileMonitor, NULL, 0, NULL);
			CloseHandle(ht);
		}
		break;
		case IDC_BUTTON_OPENPROCESS_MONITOR:
		{
			//ʹ��InlineHook
			HANDLE ht = CreateThread(NULL, 0, OpenProcessMonitor, NULL, 0, NULL);
			CloseHandle(ht);
		}
		break;
		case IDC_BUTTON_INJECT_EXE:
		{
			//ע��EXE
			HANDLE ht = CreateThread(NULL, 0, InjectEXE, NULL, 0, NULL);
			CloseHandle(ht);
		}
		break;
		case IDC_BUTTON_MSGBOX_CALL:
		{
			//MessageBoxAԶ�̵���
			HANDLE ht = CreateThread(NULL, 0, MsgBoxCall, NULL, 0, NULL);
			CloseHandle(ht);
		}
		break;
		case IDC_BUTTON_CREATEFILE_CALL:
		{
			//CreateFileAԶ�̵���
			HANDLE ht = CreateThread(NULL, 0, CreateFileCall, NULL, 0, NULL);
			CloseHandle(ht);
		}
		break;
		case IDC_BUTTON_OPENPROCESS_CALL:
		{
			//OpenProcessԶ�̵���
			HANDLE ht = CreateThread(NULL, 0, OpenProcessCall, NULL, 0, NULL);
			CloseHandle(ht);
		}
		break;
		}
		return TRUE;
	}
	return FALSE;
}

int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd)
{
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, dlgProc);
	return 0;
}