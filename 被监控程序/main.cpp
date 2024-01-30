#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include "resource.h"
#include "Tools.h"

//���ڿؼ����
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

			//������Ϣ����
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
				MessageBox(NULL, TEXT("��ѡ�����ļ�·��"), TEXT("����"), MB_OK);
				return TRUE;
			}

			Tools tool;

			// ʹ��CreateFile���������ļ�
			LPSTR szFileStr = NULL;
			tool.TCHARToChar(szFile, &szFileStr);

			HANDLE hFile = CreateFileA(szFileStr, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

			if (hFile == INVALID_HANDLE_VALUE) {
				MessageBox(NULL, TEXT("�ļ�����ʧ��!"), TEXT("����"), MB_OK | MB_ICONERROR);
				return 1;
			}

			// ���ļ�ָ���ƶ����ļ�ĩβ
			SetFilePointer(hFile, 0, NULL, FILE_END);

			// �ļ������ɹ������Խ����ļ�����
			LPSTR contentStr = NULL;
			tool.TCHARToChar(content, &contentStr);

			WriteFile(hFile, contentStr, strlen(contentStr), NULL, NULL);

			free(szFileStr);
			free(contentStr);

			// �ر��ļ����
			CloseHandle(hFile);

			return TRUE;
		}
		break;
		case IDC_BUTTON_SEL_PROCESS_PATH:
		{
			//���ﲻ��ʹ�ã�OpenProcess��صĻ����������ѭ��
			//���ֶ�����·���������ı���
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
				MessageBox(NULL, TEXT("��ѡ��Ҫ�򿪵Ľ���"), TEXT("����"), MB_OK);
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

			// �ȴ����̽���
			//WaitForSingleObject(pi.hProcess, INFINITE);

			// �رս��̺��߳̾��
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