#include <windows.h>
#include <Psapi.h>
#include <stdio.h>
#include "resource.h"
#include "PETools.h"
#include "Tools.h"
#include "DataPacket.h"

//定义一些函数指针类型
typedef int (WINAPI* MBA)(HWND, LPCSTR, LPCSTR, UINT);
typedef HANDLE(WINAPI* CFA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE(WINAPI* CFW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

//窗口句柄
HWND pidEdit;
HWND msgBoxMonitorBtn;
HWND createFileMonitorBtn;
HWND openProcessMonitorBtn;
//用于判断监控是否开启
BOOL isMsgBoxMonitor = FALSE;
BOOL isCreateFileMonitor = FALSE;
BOOL isOpenProcessMonitor = FALSE;
//监控日志文件
HANDLE monitorLog;
TCHAR monitorLogPath[MAX_PATH]{ 0 };
HANDLE monitorLogEvent;
//工具
Tools tools;
PETools pe;
DataPacket dp;
//共享内存
HANDLE hMapObject;
HANDLE hMapView;
//事件对象，mapView可读，可写
HANDLE hMapViewRead;
HANDLE hMapViewWrite;
//用于保存InlineHook数据
CHAR szBuffer[MAX_PATH]{ 0 };
DWORD dwDesiredAccess;
BOOL bInheritHandle;
DWORD dwProcessId;
LPVOID oldData;
//OpenProcess函数的基址
DWORD openProcessAddress = 0x75BEFC00;
DWORD oldJmp;

//CreateFileW指针
CFW cfw;

/**
 * 注意，你要替换的函数，应该与你写的函数参数保持一致
 */
int WINAPI MyMsgBoxA(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType)
{
	//注意这里不能直接调用MessageBoxA，因为已经被我们替换了，直接调会死循环
	MBA mba = (MBA)GetProcAddress(LoadLibrary(TEXT("user32.dll")), "MessageBoxA");

	int ret = mba(hWnd, lpText, lpCaption, uType);

	CHAR buf[MAX_PATH]{ 0 };
	sprintf_s(buf, MAX_PATH, "MessageBoxA 获取到的参数 %d %s %s %d 调用结果 %d\n", (DWORD)hWnd, lpText, lpCaption, uType);

	tools.OutputDebugStringFormatA("%s\n", buf);

	monitorLogEvent = OpenEvent(EVENT_ALL_ACCESS, FALSE, TEXT("MonitorLogEvent"));

	WaitForSingleObject(monitorLogEvent, INFINITE);
	//写入监控文件
	cfw = (CFW)GetProcAddress(LoadLibrary(TEXT("Kernel32.dll")), "CreateFileW");
	HANDLE log = cfw(monitorLogPath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	SetFilePointer(log, 0, NULL, FILE_END);
	if (!WriteFile(log, buf, strlen(buf) + 1, NULL, NULL))
	{
		tools.OutputDebugStringFormat(TEXT("写入日志失败 %d\n"), GetLastError());
	}
	CloseHandle(log);
	SetEvent(monitorLogEvent);

	return ret;
}

/**
 * 注意，你要替换的函数，应该与你写的函数参数保持一致
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
	sprintf_s(buf, MAX_PATH, "CreateFileA 获取到的参数 %s %d %d %x %d %d %d 调用结果 %d\n", lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, h);

	tools.OutputDebugStringFormatA("%s\n", buf);

	monitorLogEvent = OpenEvent(EVENT_ALL_ACCESS, FALSE, TEXT("MonitorLogEvent"));

	WaitForSingleObject(monitorLogEvent, INFINITE);
	cfw = (CFW)GetProcAddress(LoadLibrary(TEXT("Kernel32.dll")), "CreateFileW");
	HANDLE log = cfw(monitorLogPath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	//写入监控文件
	if (!WriteFile(log, buf, strlen(buf) + 1, NULL, NULL))
	{
		tools.OutputDebugStringFormat(TEXT("写入日志失败 %d\n"), GetLastError());
	}
	CloseHandle(log);
	SetEvent(monitorLogEvent);

	return h;
}

/**
 * 我们自已的OpenProcess
 */
extern "C" __declspec(naked) void myOpenProcess()
{
	//保存寄存器
	__asm
	{
		pushad
		pushfd
	}

	//pushad会保存8个4字节的寄存器32
	//pushfd会保存4个字节的EFLAGS
	//如果你是在提升栈之前进行代码的替换，那只能通过ESP来找参数
	//如果没有pushad和pushfd，参数一为 ESP+4，参数二为 ESP+8
	//参数一为 ESP + 0x28（32 + 4 + 4）
	//参数二为 ESP + 0x2c (32 + 4 + 8）
	//由于我是在提升堆栈之后进行代码的替换，所以这里我可以用EBP来找参数
	//参数一为 EBP + 0x8
	//参数二为 EBP + 0xc

	__asm
	{
		mov EAX, dword ptr[EBP + 0x8]
		mov dwDesiredAccess, EAX
		mov EAX, dword ptr[EBP + 0xc]
		mov bInheritHandle, EAX
		mov EAX, dword ptr[EBP + 0x10]
		mov dwProcessId, EAX
	}

	sprintf_s(szBuffer, MAX_PATH, "OpenProcess 获取到的参数 %d %d %d\n", dwDesiredAccess, bInheritHandle, dwProcessId);

	tools.OutputDebugStringFormatA("%s", szBuffer);

	monitorLogEvent = OpenEvent(EVENT_ALL_ACCESS, FALSE, TEXT("MonitorLogEvent"));
	WaitForSingleObject(monitorLogEvent, INFINITE);
	//写入监控文件
	cfw = (CFW)GetProcAddress(LoadLibrary(TEXT("Kernel32.dll")), "CreateFileW");
	monitorLog = cfw(monitorLogPath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (monitorLog == INVALID_HANDLE_VALUE)
	{
		tools.OutputDebugStringFormat(TEXT("获取日志句柄失败 %d\n"), GetLastError());
	}
	SetFilePointer(monitorLog, 0, NULL, FILE_END);
	if (!WriteFile(monitorLog, szBuffer, strlen(szBuffer) + 1, NULL, NULL))
	{
		tools.OutputDebugStringFormat(TEXT("写入日志失败 %d\n"), GetLastError());
	}
	CloseHandle(monitorLog);
	SetEvent(monitorLogEvent);

	//恢复寄存器
	__asm
	{
		popfd
		popad
	}

	//执行之前替换的代码
	__asm
	{
		mov eax, dword ptr[ebp + 10h]
		xor ecx, ecx
	}

	//跳回原来的地方
	__asm
	{
		jmp oldJmp
	}
}

/**
 * 注入入口
 */
DWORD WINAPI InjectEntry(LPVOID pImageBuffer)
{
	//修复IAT表
	pe.RepairIAT(pImageBuffer);

	//获取被注入进程的基址
	HMODULE injectModule = GetModuleHandle(NULL);
	HANDLE injectProcess = GetCurrentProcess();

	tools.OutputDebugStringFormat(TEXT("pImageBuffer 0x%x\n"), pImageBuffer);
	tools.OutputDebugStringFormat(TEXT("injectModule 0x%x\n"), injectModule);

	//获取共享内存
	HANDLE mapObj = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, dp.GetTotalSize(), TEXT("SharedMemory"));
	if (!mapObj)
	{
		tools.OutputDebugStringFormat(TEXT("创建共享内存失败 %d"), GetLastError());
	}

	tools.OutputDebugStringFormat(TEXT("mapObj 0x%x\n"), mapObj);

	//映射共享内存到注入进程
	LPVOID mapView = MapViewOfFile(mapObj, FILE_MAP_WRITE, 0, 0, 0);
	if (!mapView)
	{
		tools.OutputDebugStringFormat(TEXT("内存映射失败 %d"), GetLastError());
	}

	tools.OutputDebugStringFormat(TEXT("mapView 0x%x\n"), mapView);

	//事件对象，mapView可读，可写
	HANDLE read = OpenEvent(EVENT_ALL_ACCESS, FALSE, TEXT("MapViewRead"));
	HANDLE write = OpenEvent(EVENT_ALL_ACCESS, FALSE, TEXT("MapViewWrite"));

	tools.OutputDebugStringFormat(TEXT("read 0x%x\n"), read);
	tools.OutputDebugStringFormat(TEXT("write 0x%x\n"), write);

	DataPacket dpt;
	while (TRUE)
	{
		WaitForSingleObject(read, INFINITE);
		ResetEvent(read);

		dpt.MapViewReadData(mapView);

		tools.OutputDebugStringFormatA("%s\n", dpt.method);

		if (strcmp(dpt.method, "InstallIATHook_MessageBoxA") == 0)
		{
			//获取原函数地址
			FARPROC msgBoxA = GetProcAddress(LoadLibrary(TEXT("user32.dll")), "MessageBoxA");

			//安装HOOK
			pe.InstallIATHook((LPVOID)injectModule, (DWORD)msgBoxA, (DWORD)MyMsgBoxA);
		}
		if (strcmp(dpt.method, "UnInstallIATHook_MessageBoxA") == 0)
		{
			//获取原函数地址
			FARPROC msgBoxA = GetProcAddress(LoadLibrary(TEXT("user32.dll")), "MessageBoxA");

			//卸载HOOK
			pe.UnInstallIATHook((LPVOID)injectModule, (DWORD)msgBoxA, (DWORD)MyMsgBoxA);
		}
		if (strcmp(dpt.method, "InstallIATHook_CreateFileA") == 0)
		{
			//获取原函数地址
			FARPROC createFileA = GetProcAddress(LoadLibrary(TEXT("Kernel32.dll")), "CreateFileA");

			//安装HOOK
			pe.InstallIATHook((LPVOID)injectModule, (DWORD)createFileA, (DWORD)MyCreateFileA);
		}
		if (strcmp(dpt.method, "UnInstallIATHook_CreateFileA") == 0)
		{
			//获取原函数地址
			FARPROC createFileA = GetProcAddress(LoadLibrary(TEXT("Kernel32.dll")), "CreateFileA");

			//卸载HOOK
			pe.UnInstallIATHook((LPVOID)injectModule, (DWORD)createFileA, (DWORD)MyCreateFileA);
		}
		if (strcmp(dpt.method, "InstallInlineHook_OpenProcess") == 0)
		{
			//获取原函数地址
			//FARPROC openProcess = GetProcAddress(LoadLibrary(TEXT("Kernel32.dll")), "OpenProcess");

			oldJmp = (DWORD)openProcessAddress + 8 + 5;

			pe.InstallInlineHook(injectProcess, (DWORD)openProcessAddress, (DWORD)myOpenProcess, 8, 5, &oldData);
		}
		if (strcmp(dpt.method, "UnInstallInlineHook_OpenProcess") == 0)
		{
			//获取原函数地址
			//FARPROC openProcess = GetProcAddress(LoadLibrary(TEXT("Kernel32.dll")), "OpenProcess");

			pe.UnInstallInlineHook(injectProcess, (DWORD)openProcessAddress, 8, 5, oldData);
		}

		SetEvent(write);

		Sleep(500);
	}
}

/**
 * 注入模块EXE
 */
DWORD WINAPI InjectEXE(LPVOID lpThreadParameter)
{
	//获取当前进程句柄
	HMODULE hModule = GetModuleHandle(NULL);
	HANDLE hProcess = GetCurrentProcess();

	MODULEINFO moduleInfo;
	GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(moduleInfo));

	//获取当前进程的ImageBase和SizeOfImage
	DWORD imageBase = (DWORD)moduleInfo.lpBaseOfDll;
	DWORD sizeOfImage = (DWORD)moduleInfo.SizeOfImage;

	//申请内存
	LPVOID imageBuf = malloc(sizeOfImage);
	if (imageBuf == NULL)
	{
		tools.OutputDebugStringFormat(TEXT("申请内存失败 %d"), GetLastError());
		return 1;
	}
	memset(imageBuf, 0, sizeOfImage);

	//将当前进程的代码，读到我们新创建的缓冲区里
	ReadProcessMemory(hProcess, (LPVOID)imageBase, imageBuf, sizeOfImage, NULL);

	//获取要注入进程的hProcess
	TCHAR injectPidStr[MAX_PATH]{ 0 };
	GetWindowText(pidEdit, injectPidStr, MAX_PATH);
	DWORD injectPid = _ttoi(injectPidStr);

	//打开要注入的进程
	HANDLE injectProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, injectPid);
	if (injectProcess == NULL)
	{
		tools.OutputDebugStringFormat(TEXT("打开进程失败 %d"), GetLastError());
		return 1;
	}

	//在注入进程中申请内存
	LPVOID address = VirtualAllocEx(injectProcess, NULL, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (address == NULL)
	{
		tools.OutputDebugStringFormat(TEXT("申请内存失败 %d"), GetLastError());
		return 1;
	}

	//修复重定位表
	if ((DWORD)address != imageBase)
	{
		DWORD offset = (DWORD)address - imageBase;
		pe.ReviseRelocation(imageBuf, offset);
	}

	//把数据写入到注入进程中
	if (!WriteProcessMemory(injectProcess, address, imageBuf, sizeOfImage, NULL))
	{
		tools.OutputDebugStringFormat(TEXT("写入数据失败 %d"), GetLastError());
		return 1;
	}

	//创建远程线程
	//计算函数在进程A中的地址 = 函数在当前进程的地址 - 当前进程的基址(ImageBase) + 进程A中申请的基址
	DWORD fn = (DWORD)InjectEntry - (DWORD)imageBase + (DWORD)address;

	HANDLE ht = CreateRemoteThread(injectProcess, NULL, 0, (LPTHREAD_START_ROUTINE)fn, address, 0, NULL);
	if (ht == NULL)
	{
		tools.OutputDebugStringFormat(TEXT("创建远程线程失败 %d"), GetLastError());
		return 1;
	}

	CloseHandle(ht);

	MessageBox(NULL, TEXT("注入成功"), TEXT("成功"), MB_OK);

	return 0;
}

/**
 * MessageBoxA监控
 */
DWORD WINAPI MsgBoxMonitor(LPVOID lpThreadParameter)
{
	if (isMsgBoxMonitor)
	{
		isMsgBoxMonitor = FALSE;
		SetWindowText(msgBoxMonitorBtn, TEXT("开启监控"));
	}
	else {
		isMsgBoxMonitor = TRUE;
		SetWindowText(msgBoxMonitorBtn, TEXT("关闭监控"));
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
 * CreateFileA监控
 */
DWORD WINAPI CreateFileMonitor(LPVOID lpThreadParameter)
{
	if (isCreateFileMonitor)
	{
		isCreateFileMonitor = FALSE;
		SetWindowText(createFileMonitorBtn, TEXT("开启监控"));
	}
	else {
		isCreateFileMonitor = TRUE;
		SetWindowText(createFileMonitorBtn, TEXT("关闭监控"));
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
 * OpenProcess监控
 */
DWORD WINAPI OpenProcessMonitor(LPVOID lpThreadParameter)
{
	if (isOpenProcessMonitor)
	{
		isOpenProcessMonitor = FALSE;
		SetWindowText(openProcessMonitorBtn, TEXT("开启监控"));
	}
	else {
		isOpenProcessMonitor = TRUE;
		SetWindowText(openProcessMonitorBtn, TEXT("关闭监控"));
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

		//创建监控Log
		TCHAR exePath[MAX_PATH]{ 0 };
		GetModuleFileName(NULL, exePath, MAX_PATH);

		size_t ix = _tcsrchr(exePath, TEXT('\\')) - exePath;
		_tcsncpy_s(monitorLogPath, MAX_PATH, exePath, ix + 1);
		_tcscat_s(monitorLogPath, MAX_PATH, TEXT("monitor.log"));

		HANDLE monitorLogFile = CreateFile(monitorLogPath, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		if (monitorLogFile == INVALID_HANDLE_VALUE) {
			tools.OutputDebugStringFormat(TEXT("创建监控日志失败 %d"), GetLastError());
		}

		CloseHandle(monitorLogFile);

		//创建共享内存，来实现进程间的通信
		hMapObject = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, dp.GetTotalSize(), TEXT("SharedMemory"));
		if (!hMapObject)
		{
			tools.OutputDebugStringFormat(TEXT("创建共享内存失败 %d"), GetLastError());
		}
		//将FileMapping对象映射到自己的进程
		hMapView = MapViewOfFile(hMapObject, FILE_MAP_WRITE, 0, 0, 0);
		if (!hMapView)
		{
			tools.OutputDebugStringFormat(TEXT("内存映射失败 %d"), GetLastError());
		}

		//创建事件对象
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
			//使用IATHook
			HANDLE ht = CreateThread(NULL, 0, MsgBoxMonitor, NULL, 0, NULL);
			CloseHandle(ht);
		}
		break;
		case IDC_BUTTON_CREATEFILE_MONITOR:
		{
			//使用IATHook
			HANDLE ht = CreateThread(NULL, 0, CreateFileMonitor, NULL, 0, NULL);
			CloseHandle(ht);
		}
		break;
		case IDC_BUTTON_OPENPROCESS_MONITOR:
		{
			//使用InlineHook
			HANDLE ht = CreateThread(NULL, 0, OpenProcessMonitor, NULL, 0, NULL);
			CloseHandle(ht);
		}
		break;
		case IDC_BUTTON_INJECT_EXE:
		{
			//注入EXE
			HANDLE ht = CreateThread(NULL, 0, InjectEXE, NULL, 0, NULL);
			CloseHandle(ht);
		}
		break;
		case IDC_BUTTON_MSGBOX_CALL:
		{

		}
		break;
		case IDC_BUTTON_CREATEFILE_CALL:
		{

		}
		break;
		case IDC_BUTTON_OPENPROCESS_CALL:
		{

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