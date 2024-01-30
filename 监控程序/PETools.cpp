#include "PETools.h"

/**
 * 修正重定位表
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
				//VirtualAddress+后12位，才是真正的RVA
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
 * 修复IAT表
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

		//注意这里不要使用LoadLibrary，会导致模块加载失败
		HMODULE hModule = LoadLibraryA((LPCSTR)((LPBYTE)pImageBuffer + nameRva));

		//遍历FirstThunk
		DWORD FirstThunkRva = importDir->FirstThunk;
		DWORD OriginalFirstThunkRva = importDir->OriginalFirstThunk;

		PIMAGE_THUNK_DATA32 FirstThunk = PIMAGE_THUNK_DATA32((LPBYTE)pImageBuffer + FirstThunkRva);
		PIMAGE_THUNK_DATA32 OriginalFirstThunk = PIMAGE_THUNK_DATA32((LPBYTE)pImageBuffer + OriginalFirstThunkRva);

		while (OriginalFirstThunk->u1.Ordinal)
		{
			//判断最高位是不是1，如果是，则除去最高位的值，就是函数的导出序号
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
 * 安装IATHook
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
		//遍历FirstThunk
		DWORD FirstThunkRva = importDir->FirstThunk;

		PIMAGE_THUNK_DATA32 FirstThunk = PIMAGE_THUNK_DATA32((LPBYTE)pImageBuffer + FirstThunkRva);

		while (FirstThunk->u1.Function)
		{
			if (FirstThunk->u1.Function == oldFunc)
			{
				OutputDebugString(TEXT("安装IATHook成功"));

				// 开启写权限
				DWORD oldProtected;
				VirtualProtect(FirstThunk, 4, PAGE_EXECUTE_READWRITE, &oldProtected);

				FirstThunk->u1.Function = newFunc;

				// 关闭写保护
				VirtualProtect(FirstThunk, 4, oldProtected, &oldProtected);

				break;
			}

			FirstThunk++;
		}
		importDir = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)importDir + 20);
	}
}

/**
 * 卸载IATHook
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
		//遍历FirstThunk
		DWORD FirstThunkRva = importDir->FirstThunk;

		PIMAGE_THUNK_DATA32 FirstThunk = PIMAGE_THUNK_DATA32((LPBYTE)pImageBuffer + FirstThunkRva);

		while (FirstThunk->u1.Function)
		{
			if (FirstThunk->u1.Function == newFunc)
			{
				OutputDebugString(TEXT("卸载IATHook成功"));

				// 开启写权限
				DWORD oldProtected;
				VirtualProtect(FirstThunk, 4, PAGE_EXECUTE_READWRITE, &oldProtected);

				FirstThunk->u1.Function = oldFunc;

				// 关闭写保护
				VirtualProtect(FirstThunk, 4, oldProtected, &oldProtected);

				break;
			}

			FirstThunk++;
		}
		importDir = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)importDir + 20);
	}
}

/**
 * 安装InlineHook
 */
VOID PETools::InstallInlineHook(IN HANDLE hProcess, IN DWORD oldFunc, IN DWORD newFunc, IN DWORD offset, IN DWORD size, OUT LPVOID* oldData)
{
	if (size < 5)
	{
		return;
	}

	//计算开始地址
	DWORD start = oldFunc + offset;

	//申请内存，用于保存替换的数据
	LPBYTE oldBuf = (LPBYTE)malloc(size);
	memset(oldBuf, 0, size);
	ReadProcessMemory(hProcess, (LPCVOID)(start), oldBuf, size, NULL);

	//假设我们需要获得E9 后面的硬编码为X
	//X = 真正要跳转的地址 - E9这条指令的下一行地址
	//E9这条指令的下一行地址 = 当前地址 + 5
	//X = 真正要跳转的地址 - 当前地址 - 5
	DWORD address = newFunc - start - 5;

	// 开启写权限
	DWORD oldProtected;
	VirtualProtect((LPVOID)start, size, PAGE_EXECUTE_READWRITE, &oldProtected);

	//替换原先的硬编码
	*(LPBYTE)start = 0xE9;
	*(LPDWORD)((LPBYTE)start + 1) = address;

	// 关闭写保护
	VirtualProtect((LPVOID)start, size, oldProtected, &oldProtected);

	*oldData = oldBuf;

	OutputDebugString(TEXT("安装InlineHook成功"));
}

/**
 * 卸载InlineHook
 */
VOID PETools::UnInstallInlineHook(IN HANDLE hProcess, IN DWORD oldFunc, IN DWORD offset, IN DWORD size, IN LPVOID oldData)
{
	//计算开始地址
	DWORD start = oldFunc + offset;

	// 开启写权限
	DWORD oldProtected;
	VirtualProtect((LPVOID)start, size, PAGE_EXECUTE_READWRITE, &oldProtected);

	//替换原先的硬编码
	WriteProcessMemory(hProcess, (LPVOID)start, oldData, size, NULL);

	// 关闭写保护
	VirtualProtect((LPVOID)start, size, oldProtected, &oldProtected);

	OutputDebugString(TEXT("卸载InlineHook成功"));
}