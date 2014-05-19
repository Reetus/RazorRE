#include "stdafx.h"
#include "Hooks.h"

int HookFunc(char *dllName, char *funcName, void *newFunc, FARPROC *oldFunc) 
{
	unsigned char* thisModule = (unsigned char*)GetModuleHandleA(NULL);

	HMODULE dllModule = GetModuleHandleA(dllName);
	*oldFunc = GetProcAddress(dllModule, funcName);

	IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER*)thisModule;
	IMAGE_NT_HEADERS *inh = (IMAGE_NT_HEADERS*)((BYTE*)thisModule + idh->e_lfanew);

	IMAGE_IMPORT_DESCRIPTOR* iid = (IMAGE_IMPORT_DESCRIPTOR*)(thisModule + inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	for (IMAGE_IMPORT_DESCRIPTOR* i = iid; i->Name != 0; ++i)
	{
		char *moduleName = (char*)(thisModule + i->Name);

		if (_stricmp(moduleName, dllName) == 0) 
		{
			IMAGE_THUNK_DATA* itd = (IMAGE_THUNK_DATA*)(thisModule + i->FirstThunk);

			for (IMAGE_THUNK_DATA* j = itd; j->u1.Function != 0; ++j)
			{
				if ((FARPROC)j->u1.Function == *oldFunc) 
				{
					DWORD oldProtect = 0;
					VirtualProtect(&j->u1.Function, sizeof(DWORD), PAGE_READWRITE, &oldProtect);
					j->u1.Function = (DWORD)newFunc;
					VirtualProtect(&j->u1.Function, sizeof(DWORD), oldProtect, &oldProtect);
				}
			}
		}
	}

	return 0;
}
