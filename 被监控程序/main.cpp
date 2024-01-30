#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include "resource.h"
#include "Tools.h"

//窗口控件句柄
HWND msgBoxTitle;
HWND msgBoxContent;
HWND filePath;
HWND fileContent;
HWND processPath;

INT_PTR CALLBACK dlgProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		msgBoxTitle = GetDlgItem(hwnd, IDC_EDIT_MSGBOX_TITLE);
		msgBoxContent = GetDlgItem(hwnd, IDC_EDIT_MSGBOX_CONTENT);
		filePath = GetDlgItem(hwnd, IDC_EDIT_FILE_PATH);
		fileContent = GetDlgItem(hwnd, IDC_EDIT_FILE_CONTENT);
		processPath = GetDlgItem(hwnd, IDC_EDIT_PROCESS_PATH);

		EnableWindow(GetDlgItem(hwnd, IDC_BUTTON_SEL_PROCESS_PATH), FALSE);
		return TRUE;
	case WM_CLOSE:
		EndDialog(hwnd, 0);
		return TRUE;
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_MSGBOX_TEST:
		{
			TCHAR title[MAX_PATH]{ 0 };
			GetWindowText(msgBoxTitle, title, MAX_PATH);
			TCHAR content[MAX_PATH]{ 0 };
			GetWindowText(msgBoxContent, content, MAX_PATH);

			Tools tool;
			LPSTR titleStr = NULL;
			LPSTR contentStr = NULL;
			tool.TCHARToChar(title, &titleStr);
			tool.TCHARToChar(content, &contentStr);

			//测试消息弹窗
			MessageBoxA(hwnd, contentStr, titleStr, MB_OK);

			free(titleStr);
			free(contentStr);

			return TRUE;
		}
		break;
		case IDC_BUTTON_SEL_FILE_PATH:
		{
			OPENFILENAME ofn = { 0 };
			TCHAR szFile[MAX_PATH] = { 0 };
			ZeroMemory(&ofn, sizeof(ofn));
			ofn.lStructSize = sizeof(ofn);
			ofn.hwndOwner = NULL;
			ofn.lpstrFilter = TEXT("All Files (*.*)\0*.*\0");
			ofn.lpstrFile = szFile;
			ofn.nMaxFile = sizeof(szFile) / sizeof(*szFile);
			ofn.lpstrTitle = TEXT("Save As");
			ofn.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;

			if (GetSaveFileName(&ofn)) {
				SetWindowText(filePath, szFile);
			}

			return TRUE;
		}
		break;
		case IDC_BUTTON_FILE_CREATE_TEST:
		{
			TCHAR szFile[MAX_PATH] = { 0 };
			GetWindowText(filePath, szFile, MAX_PATH);

			TCHAR content[MAX_PATH]{ 0 };
			GetWindowText(fileContent, content, MAX_PATH);

			if (_tcslen(szFile) <= 0)
			{
				MessageBox(NULL, TEXT("请选保存文件路径"), TEXT("错误"), MB_OK);
				return TRUE;
			}

			Tools tool;

			// 使用CreateFile函数创建文件
			LPSTR szFileStr = NULL;
			tool.TCHARToChar(szFile, &szFileStr);

			HANDLE hFile = CreateFileA(szFileStr, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

			if (hFile == INVALID_HANDLE_VALUE) {
				MessageBox(NULL, TEXT("文件创建失败!"), TEXT("错误"), MB_OK | MB_ICONERROR);
				return 1;
			}

			// 将文件指针移动到文件末尾
			SetFilePointer(hFile, 0, NULL, FILE_END);

			// 文件创建成功，可以进行文件操作
			LPSTR contentStr = NULL;
			tool.TCHARToChar(content, &contentStr);

			WriteFile(hFile, contentStr, strlen(contentStr), NULL, NULL);

			free(szFileStr);
			free(contentStr);

			// 关闭文件句柄
			CloseHandle(hFile);

			return TRUE;
		}
		break;
		case IDC_BUTTON_SEL_PROCESS_PATH:
		{
			//这里不能使用，OpenProcess监控的话，会造成死循环
			//请手动复制路径到进程文本框
			return TRUE;

			OPENFILENAME ofn = { 0 };
			TCHAR szFile[MAX_PATH] = { 0 };
			ZeroMemory(&ofn, sizeof(ofn));

			ofn.lStructSize = sizeof(ofn);
			ofn.hwndOwner = hwnd;
			ofn.lpstrFile = szFile;
			ofn.nMaxFile = MAX_PATH;
			ofn.lpstrFilter = TEXT("EXE Files\0*.exe\0");
			ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

			if (GetOpenFileName(&ofn))
			{
				SetWindowText(processPath, szFile);
			}

			return TRUE;
		}
		break;
		case IDC_BUTTON_OPEN_PROCESS_TEST:
		{
			TCHAR szFile[MAX_PATH] = { 0 };
			GetWindowText(processPath, szFile, MAX_PATH);

			if (_tcslen(szFile) <= 0)
			{
				MessageBox(NULL, TEXT("请选择要打开的进程"), TEXT("错误"), MB_OK);
				return TRUE;
			}

			STARTUPINFO si{ 0 };
			si.cb = sizeof(si);

			PROCESS_INFORMATION pi{ 0 };

			if (CreateProcess(NULL, szFile, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
			{
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);

				CloseHandle(hProcess);
			}

			// 等待进程结束
			//WaitForSingleObject(pi.hProcess, INFINITE);

			// 关闭进程和线程句柄
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);

			return TRUE;
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