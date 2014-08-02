// Loader.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"

enum LOADER_ERROR {
	SUCCESS = 0,
	NO_OPEN_EXE,
	NO_MAP_EXE,
	NO_READ_EXE_DATA,
	NO_RUN_EXE,
	NO_ALLOC_MEN,
	NO_WRITE,
	NO_VPROTECT,
	NO_READ,
	UNKNOWN_ERROR = 99
};

LOADER_ERROR __declspec(dllexport) __cdecl Load(char *client, char *dll, char *dllfunc, void *dlldata, int dlldatalen, int *pid) {
	char shortPath[MAX_PATH];
	char pathOnly[MAX_PATH];
	void *dllDataAlloc;
	void *dataAlloc;
	char codeBuffer[256];

	int shortPathLen = GetShortPathNameA(client, shortPath, sizeof(shortPath));
	if (shortPathLen == 0) {
		return NO_OPEN_EXE;
	}
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	memset(pathOnly, 0, MAX_PATH);

	for (int i = strlen(shortPath); i > 0; i--) {
		if (shortPath[i] == '\\' || shortPath[i] == '/') {
			int slashPosition = i+1;
			memcpy(pathOnly, shortPath, slashPosition);
			break;
		}
	}

	memset(&si, 0, sizeof(STARTUPINFOA));
	memset(&pi, 0, sizeof(PROCESS_INFORMATION));

	if (!CreateProcessA(shortPath, 0, 0, 0, 0, CREATE_SUSPENDED, 0, pathOnly, &si, &pi)) {
		int error = GetLastError();
		return NO_RUN_EXE;
	}

	*pid = pi.dwProcessId;

	// dlldata == null anyway
/*	dllDataAlloc = VirtualAllocEx(pi.hProcess, 0, dlldatalen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (dllDataAlloc != 0) {
		DWORD junk = 0;
		VirtualProtectEx(pi.hProcess, (LPVOID)0x700000, dlldatalen, PAGE_EXECUTE_READWRITE, &junk); // 0x700000????????
	}*/

	dataAlloc = VirtualAllocEx(pi.hProcess, 0, strlen(dll+1)+strlen(dllfunc+1)+256, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (dataAlloc == 0) {
		return NO_ALLOC_MEN;
	}

	int pos = 0;
	memset(codeBuffer, 0x90, sizeof(codeBuffer));
	memcpy(codeBuffer, dll, strlen(dll));
	pos+= strlen(dll);
	memset(codeBuffer+pos, 0, 1);
	pos++;
	memcpy(codeBuffer+pos, dllfunc, strlen(dllfunc));
	pos+= strlen(dllfunc);
	memset(codeBuffer+pos, 0, 1);
	pos++;
	int codeStart = pos;

	HMODULE hModule = LoadLibraryA("kernel32.dll");
	LPVOID loadLibrary = GetProcAddress(hModule, "LoadLibraryA");
	LPVOID getProcAddress = GetProcAddress(hModule, "GetProcAddress");
	LPVOID exitThread = GetProcAddress(hModule, "ExitThread");

	char code[] = { 0x68, 0x00, 0x00, 0x00, 0x00 /* PUSH dataAlloc */,
					0xB8, 0x00, 0x00, 0x00, 0x00 /* MOV eax, LoadLibraryA */,
					0xFF, 0xD0					 /* CALL eax */,
					0xBB, 0x00, 0x00, 0x00, 0x00 /* MOV ebx, dataAlloc+strlen(dll+1) */,
					0x53						 /* PUSH ebx */,
					0x50						 /* PUSH eax */,
					0xB9, 0x00, 0x00, 0x00, 0x00 /* MOV ecx, GetProcAddress */,
					0xFF, 0xD1					 /* CALL ecx */,
					0xFF, 0xD0					 /* CALL eax */,
					0x6A, 0x00					 /* PUSH 0 */,
					0xB8, 0x00, 0x00, 0x00, 0x00 /* MOV eax, ExitThread */,
					0xFF, 0xD0					 /* CALL eax */};

	code[1] = (char)((int)dataAlloc);
	code[2] = (char)((int)dataAlloc >> 8);
	code[3] = (char)((int)dataAlloc >> 16);
	code[4] = (char)((int)dataAlloc >> 24);

	code[6] = (char)(loadLibrary);
	code[7] = (char)((int)loadLibrary >> 8);
	code[8] = (char)((int)loadLibrary >> 16);
	code[9] = (char)((int)loadLibrary >> 24);

	int pos2 = (int)dataAlloc + (strlen(dll)+1);
	code[13] = (char)(pos2);
	code[14] = (char)(pos2 >> 8);
	code[15] = (char)(pos2 >> 16);
	code[16] = (char)(pos2 >> 24);

	code[20] = (char)(getProcAddress);
	code[21] = (char)((int)getProcAddress >> 8);
	code[22] = (char)((int)getProcAddress >> 16);
	code[23] = (char)((int)getProcAddress >> 24);

	code[31] = (char)(exitThread);
	code[32] = (char)((int)exitThread >> 8);
	code[33] = (char)((int)exitThread >> 16);
	code[34] = (char)((int)exitThread >> 24);

	memcpy(codeBuffer+codeStart, code, sizeof(code));
	SIZE_T out = 0;
	WriteProcessMemory(pi.hProcess, dataAlloc, codeBuffer, 256, &out);

	DWORD tid = 0;
	HANDLE handler = CreateRemoteThread(pi.hProcess, 0, 0, (LPTHREAD_START_ROUTINE)((int)dataAlloc+codeStart), 0, 0, &tid);
	if (handler == 0)
		return NO_WRITE;

	WaitForSingleObject(handler, INFINITE);

	ResumeThread(pi.hThread);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return SUCCESS;
}