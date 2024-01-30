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
	//��װIATHook
	VOID InstallIATHook(IN LPVOID pImageBuffer, IN DWORD oldFunc, IN DWORD newFunc);
	//ж��IATHook
	VOID UnInstallIATHook(IN LPVOID pImageBuffer, IN DWORD oldFunc, IN DWORD newFunc);
	//��װInlineHook
	VOID InstallInlineHook(IN HANDLE hProcess, IN DWORD oldFunc, IN DWORD newFunc, IN DWORD offset, IN DWORD size, OUT LPVOID* oldData);
	//ж��InlineHook
	VOID UnInstallInlineHook(IN HANDLE hProcess, IN DWORD oldFunc, IN DWORD offset, IN DWORD size, IN LPVOID oldData);
};

