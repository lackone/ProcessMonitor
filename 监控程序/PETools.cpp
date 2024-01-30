#include "PETools.h"

/**
 * �����ض�λ��
 */
VOID PETools::ReviseRelocation(IN LPVOID pImageBuffer, IN DWORD offset)
{
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nt;
	PIMAGE_FILE_HEADER pe;
	PIMAGE_OPTIONAL_HEADER opt;
	PIMAGE_SECTION_HEADER section;
	PIMAGE_SECTION_HEADER last_section;
	IMAGE_DATA_DIRECTORY* dir;


	dos = PIMAGE_DOS_HEADER(pImageBuffer);
	nt = PIMAGE_NT_HEADERS((LPBYTE)dos + dos->e_lfanew);
	pe = PIMAGE_FILE_HEADER((LPBYTE)nt + 4);
	opt = PIMAGE_OPTIONAL_HEADER((LPBYTE)pe + IMAGE_SIZEOF_FILE_HEADER);
	section = PIMAGE_SECTION_HEADER((LPBYTE)opt + pe->SizeOfOptionalHeader);
	last_section = section + pe->NumberOfSections - 1;
	dir = opt->DataDirectory;

	DWORD relRva = dir[5].VirtualAddress;

	PIMAGE_BASE_RELOCATION relDir = (PIMAGE_BASE_RELOCATION)((LPBYTE)pImageBuffer + relRva);

	while (relDir->SizeOfBlock && relDir->VirtualAddress)
	{
		int nums = (relDir->SizeOfBlock - 8) / 2;

		LPWORD start = LPWORD((LPBYTE)relDir + 8);

		for (int i = 0; i < nums; i++)
		{
			WORD type = ((*start) & 0xF000) >> 12;

			if (type == 3)
			{
				//VirtualAddress+��12λ������������RVA
				DWORD rva = relDir->VirtualAddress + ((*start) & 0x0FFF);

				LPDWORD addr = LPDWORD((LPBYTE)pImageBuffer + rva);

				*addr = *addr + offset;
			}

			start++;
		}

		relDir = (PIMAGE_BASE_RELOCATION)((LPBYTE)relDir + relDir->SizeOfBlock);
	}
}

/**
 * �޸�IAT��
 */
VOID PETools::RepairIAT(IN LPVOID pImageBuffer)
{
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS32 nt;
	PIMAGE_FILE_HEADER pe;
	PIMAGE_OPTIONAL_HEADER32 opt;

	dos = (PIMAGE_DOS_HEADER)pImageBuffer;
	nt = (PIMAGE_NT_HEADERS32)((LPBYTE)dos + dos->e_lfanew);
	pe = (PIMAGE_FILE_HEADER)((LPBYTE)nt + 4);
	opt = (PIMAGE_OPTIONAL_HEADER32)((LPBYTE)pe + IMAGE_SIZEOF_FILE_HEADER);

	IMAGE_DATA_DIRECTORY* dir = opt->DataDirectory;

	DWORD importRva = dir[1].VirtualAddress;

	PIMAGE_IMPORT_DESCRIPTOR importDir = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pImageBuffer + importRva);

	FARPROC fn = NULL;

	while (importDir->Name)
	{
		DWORD nameRva = importDir->Name;

		//ע�����ﲻҪʹ��LoadLibrary���ᵼ��ģ�����ʧ��
		HMODULE hModule = LoadLibraryA((LPCSTR)((LPBYTE)pImageBuffer + nameRva));

		//����FirstThunk
		DWORD FirstThunkRva = importDir->FirstThunk;
		DWORD OriginalFirstThunkRva = importDir->OriginalFirstThunk;

		PIMAGE_THUNK_DATA32 FirstThunk = PIMAGE_THUNK_DATA32((LPBYTE)pImageBuffer + FirstThunkRva);
		PIMAGE_THUNK_DATA32 OriginalFirstThunk = PIMAGE_THUNK_DATA32((LPBYTE)pImageBuffer + OriginalFirstThunkRva);

		while (OriginalFirstThunk->u1.Ordinal)
		{
			//�ж����λ�ǲ���1������ǣ����ȥ���λ��ֵ�����Ǻ����ĵ������
			if ((OriginalFirstThunk->u1.Ordinal & 0x80000000) == 0x80000000)
			{
				fn = GetProcAddress(hModule, (LPCSTR)(OriginalFirstThunk->u1.Ordinal & 0x7FFFFFFF));
			}
			else {
				PIMAGE_IMPORT_BY_NAME byname = PIMAGE_IMPORT_BY_NAME((LPBYTE)pImageBuffer + OriginalFirstThunk->u1.AddressOfData);

				fn = GetProcAddress(hModule, byname->Name);
			}

			FirstThunk->u1.Function = (DWORD)fn;

			OriginalFirstThunk++;
			FirstThunk++;
		}

		importDir = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)importDir + 20);
	}
}

/**
 * ��װIATHook
 */
VOID PETools::InstallIATHook(IN LPVOID pImageBuffer, IN DWORD oldFunc, IN DWORD newFunc)
{
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS32 nt;
	PIMAGE_FILE_HEADER pe;
	PIMAGE_OPTIONAL_HEADER32 opt;

	dos = (PIMAGE_DOS_HEADER)pImageBuffer;
	nt = (PIMAGE_NT_HEADERS32)((LPBYTE)dos + dos->e_lfanew);
	pe = (PIMAGE_FILE_HEADER)((LPBYTE)nt + 4);
	opt = (PIMAGE_OPTIONAL_HEADER32)((LPBYTE)pe + IMAGE_SIZEOF_FILE_HEADER);

	IMAGE_DATA_DIRECTORY* dir = opt->DataDirectory;

	DWORD importRva = dir[1].VirtualAddress;

	PIMAGE_IMPORT_DESCRIPTOR importDir = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pImageBuffer + importRva);

	while (importDir->Name)
	{
		//����FirstThunk
		DWORD FirstThunkRva = importDir->FirstThunk;

		PIMAGE_THUNK_DATA32 FirstThunk = PIMAGE_THUNK_DATA32((LPBYTE)pImageBuffer + FirstThunkRva);

		while (FirstThunk->u1.Function)
		{
			if (FirstThunk->u1.Function == oldFunc)
			{
				OutputDebugString(TEXT("��װIATHook�ɹ�"));

				// ����дȨ��
				DWORD oldProtected;
				VirtualProtect(FirstThunk, 4, PAGE_EXECUTE_READWRITE, &oldProtected);

				FirstThunk->u1.Function = newFunc;

				// �ر�д����
				VirtualProtect(FirstThunk, 4, oldProtected, &oldProtected);

				break;
			}

			FirstThunk++;
		}
		importDir = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)importDir + 20);
	}
}

/**
 * ж��IATHook
 */
VOID PETools::UnInstallIATHook(IN LPVOID pImageBuffer, IN DWORD oldFunc, IN DWORD newFunc)
{
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS32 nt;
	PIMAGE_FILE_HEADER pe;
	PIMAGE_OPTIONAL_HEADER32 opt;

	dos = (PIMAGE_DOS_HEADER)pImageBuffer;
	nt = (PIMAGE_NT_HEADERS32)((LPBYTE)dos + dos->e_lfanew);
	pe = (PIMAGE_FILE_HEADER)((LPBYTE)nt + 4);
	opt = (PIMAGE_OPTIONAL_HEADER32)((LPBYTE)pe + IMAGE_SIZEOF_FILE_HEADER);

	IMAGE_DATA_DIRECTORY* dir = opt->DataDirectory;

	DWORD importRva = dir[1].VirtualAddress;

	PIMAGE_IMPORT_DESCRIPTOR importDir = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pImageBuffer + importRva);

	while (importDir->Name)
	{
		//����FirstThunk
		DWORD FirstThunkRva = importDir->FirstThunk;

		PIMAGE_THUNK_DATA32 FirstThunk = PIMAGE_THUNK_DATA32((LPBYTE)pImageBuffer + FirstThunkRva);

		while (FirstThunk->u1.Function)
		{
			if (FirstThunk->u1.Function == newFunc)
			{
				OutputDebugString(TEXT("ж��IATHook�ɹ�"));

				// ����дȨ��
				DWORD oldProtected;
				VirtualProtect(FirstThunk, 4, PAGE_EXECUTE_READWRITE, &oldProtected);

				FirstThunk->u1.Function = oldFunc;

				// �ر�д����
				VirtualProtect(FirstThunk, 4, oldProtected, &oldProtected);

				break;
			}

			FirstThunk++;
		}
		importDir = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)importDir + 20);
	}
}

/**
 * ��װInlineHook
 */
VOID PETools::InstallInlineHook(IN HANDLE hProcess, IN DWORD oldFunc, IN DWORD newFunc, IN DWORD offset, IN DWORD size, OUT LPVOID* oldData)
{
	if (size < 5)
	{
		return;
	}

	//���㿪ʼ��ַ
	DWORD start = oldFunc + offset;

	//�����ڴ棬���ڱ����滻������
	LPBYTE oldBuf = (LPBYTE)malloc(size);
	memset(oldBuf, 0, size);
	ReadProcessMemory(hProcess, (LPCVOID)(start), oldBuf, size, NULL);

	//����������Ҫ���E9 �����Ӳ����ΪX
	//X = ����Ҫ��ת�ĵ�ַ - E9����ָ�����һ�е�ַ
	//E9����ָ�����һ�е�ַ = ��ǰ��ַ + 5
	//X = ����Ҫ��ת�ĵ�ַ - ��ǰ��ַ - 5
	DWORD address = newFunc - start - 5;

	// ����дȨ��
	DWORD oldProtected;
	VirtualProtect((LPVOID)start, size, PAGE_EXECUTE_READWRITE, &oldProtected);

	//�滻ԭ�ȵ�Ӳ����
	*(LPBYTE)start = 0xE9;
	*(LPDWORD)((LPBYTE)start + 1) = address;

	// �ر�д����
	VirtualProtect((LPVOID)start, size, oldProtected, &oldProtected);

	*oldData = oldBuf;

	OutputDebugString(TEXT("��װInlineHook�ɹ�"));
}

/**
 * ж��InlineHook
 */
VOID PETools::UnInstallInlineHook(IN HANDLE hProcess, IN DWORD oldFunc, IN DWORD offset, IN DWORD size, IN LPVOID oldData)
{
	//���㿪ʼ��ַ
	DWORD start = oldFunc + offset;

	// ����дȨ��
	DWORD oldProtected;
	VirtualProtect((LPVOID)start, size, PAGE_EXECUTE_READWRITE, &oldProtected);

	//�滻ԭ�ȵ�Ӳ����
	WriteProcessMemory(hProcess, (LPVOID)start, oldData, size, NULL);

	// �ر�д����
	VirtualProtect((LPVOID)start, size, oldProtected, &oldProtected);

	OutputDebugString(TEXT("ж��InlineHook�ɹ�"));
}