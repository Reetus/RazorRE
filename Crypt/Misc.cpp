#include "stdafx.h"
#include "Misc.h"
#include "Log.h"

BOOL GetPESectionAddress(char *sectionName, DWORD *sectionAddress, DWORD *sectionSize)
{
	unsigned char* thisModule = (unsigned char*)GetModuleHandleA(NULL);

	IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER*)thisModule;
	IMAGE_NT_HEADERS *inh = (IMAGE_NT_HEADERS*)((BYTE*)thisModule + idh->e_lfanew);
	IMAGE_SECTION_HEADER *ish = (IMAGE_SECTION_HEADER*)((BYTE*)thisModule + idh->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	for (int i = 0; i < inh->FileHeader.NumberOfSections;i++)
	{
		if (_stricmp((char*)ish->Name, sectionName) == 0) 
		{
			*sectionAddress = ish->VirtualAddress;
			LogPrintf("%x %x\r\n", *sectionAddress, ish->VirtualAddress);
			*sectionSize = ish->Misc.VirtualSize;
			return true;
		}
		ish = (IMAGE_SECTION_HEADER*)((BYTE*)ish + sizeof(IMAGE_SECTION_HEADER));
	}
	return false;
}