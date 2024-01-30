#pragma once

#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>

class PETools
{
public:
	//RepairIAT
	VOID RepairIAT(IN LPVOID pImageBuffer);
	//ReviseRelocation
	VOID ReviseRelocation(IN LPVOID pImageBuffer, IN DWORD offset);
	//InstallIATHook
	VOID InstallIATHook(IN LPVOID pImageBuffer, IN DWORD oldFunc, IN DWORD newFunc);
	//UnInstallIATHook
	VOID UnInstallIATHook(IN LPVOID pImageBuffer, IN DWORD oldFunc, IN DWORD newFunc);
	//InstallInlineHook
	VOID InstallInlineHook(IN HANDLE hProcess, IN DWORD oldFunc, IN DWORD newFunc, IN DWORD offset, IN DWORD size, OUT LPVOID* oldData);
	//UnInstallInlineHook
	VOID UnInstallInlineHook(IN HANDLE hProcess, IN DWORD oldFunc, IN DWORD offset, IN DWORD size, IN LPVOID oldData);
};

