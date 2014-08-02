// Crypt.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "Crypt.h"
#include "Compression.h"
#include "Misc.h"

// Globals
HMODULE thishModule;
HWND clienthWnd;
HWND razorhWnd;
DWORD clientProcessId;
HANDLE mutex = 0;
HANDLE fileMapping;
HANDLE consoleHandle;
struct uo_decompression decompress;
BOOL mustDecompress = FALSE;
BOOL mustCompress = FALSE;
char recvBuffer[16384];
int recvBufferPosition = 0;
SOCKET serverSocket;
struct DataBuffer *dataBuffer;
HWND uoAssistHwnd;
RECT titleRect;

VOID SendOutgoingBuffer()
{
	WaitForSingleObject(mutex, -1);

	if (dataBuffer->outSend.Length > 0) 
	{
		PUCHAR outbuff;
		PUCHAR buff = (dataBuffer->outSend.Buff0+dataBuffer->outSend.Start);

		DWORD len = GetPacketLength(buff, dataBuffer->outSend.Length);
		if (len > dataBuffer->outSend.Length || len <= 0)
		{
			return;
		}		

		//LogPacket("Client -> Server", buff, len);
		dataBuffer->totalOut+=len;

		dataBuffer->outSend.Start += len;
		dataBuffer->outSend.Length -= len;

		outbuff = new UCHAR[len];//(PUCHAR)malloc(len);

		memcpy(outbuff, buff, len);

		oldSend(serverSocket, (PCHAR)outbuff, len, 0);

		//free(outbuff);
		delete[] outbuff;
	}
	ReleaseMutex(mutex);
}

int version_sprintf(char *buffer, const char *fmt, char *val)
{
	strcpy(dataBuffer->clientVersion, val);
	Log(dataBuffer->clientVersion);
	return sprintf(buffer, fmt, val);
}

VOID DLLEXPORT OnAttach() {
	AllocConsole();
	consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	clientProcessId = GetCurrentProcessId();
	CreateCommunicationMutex();
	InstallApiHooks();

	unsigned char* thisModule = (unsigned char*)GetModuleHandleA(NULL);

	IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER*)thisModule;
	IMAGE_NT_HEADERS *inh = (IMAGE_NT_HEADERS*)((BYTE*)thisModule + idh->e_lfanew);
	IMAGE_SECTION_HEADER *ish = (IMAGE_SECTION_HEADER*)((BYTE*)thisModule + idh->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	for (int i = 0; i < inh->FileHeader.NumberOfSections;i++)
	{
		if (_stricmp((char*)ish->Name, ".rdata") == 0) 
		{
			int position = ish->VirtualAddress;
			int size = ish->Misc.VirtualSize;

			UCHAR uoVer[] = "UO Version %s";
			PUCHAR ptr = (PUCHAR)thisModule+position;
			int address;
			if (FindSignatureAddress(uoVer, ptr, strlen((PCHAR)uoVer), size, &address))
			{
				UCHAR findBytes[] = { 0x68, address, (address >> 8), (address >> 16), (address >> 24) };

				ish = (IMAGE_SECTION_HEADER*)((BYTE*)thisModule + idh->e_lfanew + sizeof(IMAGE_NT_HEADERS));
				ptr = (PUCHAR)thisModule+ish->VirtualAddress;

				if (FindSignatureAddress(findBytes, ptr, 5, ish->Misc.VirtualSize, &address)) 
				{
					int offset = (address-(int)ptr)+6;
					ptr = (PUCHAR)ptr+offset;

					if ((unsigned char)*ptr == (unsigned char)0xE8)
					{
						int offset = (int)((char*)&version_sprintf-(DWORD)ptr)-5;
						DWORD oldProtect;
						VirtualProtect(ptr, 4, PAGE_EXECUTE_READWRITE, &oldProtect);
						*(ptr++) = 0xE8;
						*(ptr++) = (char)offset;
						*(ptr++) = (char)(offset >> 8);
						*(ptr++) = (char)(offset >> 16);
						*(ptr++) = (char)(offset >> 24);

						VirtualProtect(ptr, 4, oldProtect, &oldProtect);
					}
				}
			}
			break;
		}
		ish = (IMAGE_SECTION_HEADER*)((BYTE*)ish + sizeof(IMAGE_SECTION_HEADER));
	}

	GetPacketTable();

}

/// Get packet size table, lifted from https://github.com/jaryn-kubik/UOInterface/blob/master/UOInterface/PacketHooks.cpp
BOOL GetPacketTable()
{
	DWORD sectionAddress, sectionSize;

	if (GetPESectionAddress(".data", &sectionAddress, &sectionSize))
	{
		PUCHAR thisModule = (PUCHAR)GetModuleHandleA(NULL);
		PUCHAR ptr = thisModule+sectionAddress;
		int offset;

		unsigned char sig[] =
		{
			0x01, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC, 0xCC, 0x05, 0x00, 0x00, 0x00, //packet 1, unknown, len 5
			0x02, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, //packet 2, unknown, len ...
			0x03, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC, 0xCC, 0x00, //0x80, 0x00, 0x00  //packet 3, unknown, len 0x8000 (dynamic)
		};

		if (FindSignatureAddressWildcard(sig, sizeof(sig), ptr, sectionSize, 0xCC, &offset))
		{
			struct ClientPacketInfo *pt = ((struct ClientPacketInfo*)offset)-1;

			for (UINT unknown = pt->unknown;pt->unknown == unknown;pt++)
			{
				dataBuffer->packetTable[pt->id] = pt->length;
				//LogPrintf("ID: 0x%x, Length = 0x%x\r\n", pt->id, pt->length);
			}

			return true;
		} 
		else
		{
			Log("Error: Cannot locate packet table.\r\n");
		}
	}
	return false;
}

HWND DLLEXPORT FindUOWindow() 
{
	if (IsWindow(clienthWnd))
	{
		return clienthWnd;
	} 
	return FindWindowA("Ultima Online", 0);
}

VOID DLLEXPORT WaitForWindow(DWORD dwProcessId) 
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, NULL, dwProcessId);
	do {
		Sleep(500);
	} while (FindUOWindow() == NULL);
	CloseHandle(hProcess);
}

VOID CreateCommunicationMutex() 
{
	CHAR mutexName[256];
	CHAR mappingName[256];
	mutex = 0;
	sprintf_s(mutexName, "UONetSharedCOMM_%x", clientProcessId);

	if ((mutex = CreateMutexA(0, 0, mutexName)) != NULL) 
	{
		sprintf_s(mappingName, "UONetSharedFM_%x", clientProcessId);
		if ((fileMapping = CreateFileMappingA(INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, sizeof(struct DataBuffer), mappingName)) != NULL)
		{
			dataBuffer = (struct DataBuffer *)MapViewOfFile(fileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
			if (dataBuffer == NULL)
				Log("MapView failed\r\n");
		}
		else
		{
			Log("CreateFileMapping failed\r\n");
		}
	} else
	{
		Log("Mutex failed\r\n");
	}

}

#pragma region Window Message Hooks/Functions
VOID ProcessWindowMessage(int code, WPARAM wParam, LPARAM lParam) 
{
	switch (code) 
	{
	case 0x400:
		razorhWnd = (HWND)lParam;
		break;
	case 0x401:
		{
			//LogPrintf("ProcessWindowMessage: code = %x, wParam = %d, lParam = %d\r\n", code, wParam, lParam);
			switch (wParam) 
			{
			case UONET_SEND:
				{
					WaitForSingleObject(mutex, -1);
					SendOutgoingBuffer();
					ReleaseMutex(mutex);
					break;
				}
			case UONET_SETGAMESIZE:
				{
					// TODO
					int x = (short)(lParam);
					int y = (short)(lParam>>16);
					LogPrintf("SetGameSize: %dx%d\r\n", x, y);
					dataBuffer->gameSizeX = x;
					dataBuffer->gameSizeY = y;
					break;
				}
			case UONET_LOGMESSAGE:
				{
					WaitForSingleObject(mutex, -1);
					DWORD length = dataBuffer->logMessage.Length;
					PCHAR tmpBuffer = new CHAR[length+1];
					strcpy_s(tmpBuffer, length+1, (PCHAR)(dataBuffer->logMessage.Buff0+dataBuffer->logMessage.Start));
					Log(tmpBuffer);
					dataBuffer->logMessage.Start += length;
					dataBuffer->logMessage.Length -= length;
					delete[] tmpBuffer;
					ReleaseMutex(mutex);
					break;
				}
			}
			break;
		}
	case 0x402:
		{
			LogPrintf("Title Bar Update: %s\r\n", dataBuffer->titleBar);
			break;
		}
	}
}

LRESULT CALLBACK CallWndHook(int code,WPARAM wParam,LPARAM lParam)
{
	CWPSTRUCT *cwps = (CWPSTRUCT*)lParam;
	if (cwps->message = WM_NCPAINT) {
		if (strlen(dataBuffer->titleBar) > 0)
		{
//			UpdateTitleBar(FindUOWindow());
		}
	}

	if (cwps->message == 0x400)
	{
		ProcessWindowMessage(cwps->message, wParam, cwps->lParam);
	}

	return CallNextHookEx(0, code, wParam, lParam);
}

LRESULT CALLBACK GetMessageHook(int code,WPARAM wParam,LPARAM lParam)
{
	MSG *msg = (MSG*)lParam;
	if (msg->message == 0x400 || msg->message == 0x401 || msg->message == 0x402)
	{
		ProcessWindowMessage(msg->message, msg->wParam, msg->lParam);
	}
	return CallNextHookEx(0, code, wParam, lParam);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) 
{
	if (uMsg >= WM_USER && WM_USER <= WM_USER+314) {
		return SendMessageA(razorhWnd, uMsg, wParam, lParam);
	}
	return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}
#pragma endregion

#pragma region Encryption Removal
VOID LoginCryptPatch(PUCHAR buffer, HANDLE hProcess, long baseAddress)
{
	unsigned char newClientSig[] = { 0x75, 0x12, 0x8B, 0x54, 0x24, 0x0C };
	int offset = 0;
	SIZE_T written = 0;

	if (FindSignatureOffset(newClientSig, 6, buffer, 4194304, &offset))
	{
		unsigned char patch[] = { 0xEB };
		WriteProcessMemory(hProcess, (LPVOID)(baseAddress+offset), patch, 1, &written);
	}
}

VOID TwoFishCryptPatch(PUCHAR buffer, HANDLE hProcess, long baseAddress)
{
	unsigned char oldClientSig[] = { 0x8B, 0xD9, 0x8B, 0xC8, 0x48, 0x85, 0xC9, 0x0F, 0x84 };
	unsigned char newClientSig[] = { 0x74, 0x0F, 0x83, 0xB9, 0xB4, 0x00, 0x00, 0x00, 0x00 };
	int offset;

	if (FindSignatureOffset(oldClientSig, 9, buffer, 4194304, &offset))
	{
		unsigned char patch[] = { 0x85 };
		SIZE_T written = 0;
		WriteProcessMemory(hProcess, (LPVOID)(baseAddress+offset), patch, 1, &written);
		return;
	}

	if (FindSignatureOffset(newClientSig, 9, buffer, 4194304, &offset))
	{
		unsigned char patch[] = { 0xEB };
		SIZE_T written = 0;
		WriteProcessMemory(hProcess, (LPVOID)(baseAddress+offset), patch, 1, &written);
		return;
	}
}

VOID DecryptPatch(PUCHAR buffer, HANDLE hProcess, long baseAddress)
{
	unsigned char oldClientSig[] = { 0x8B, 0x86, 0x04, 0x01, 0x0A, 0x00, 0x85, 0xC0, 0x74, 0x52 };
	unsigned char newClientSig[] = { 0x74, 0x37, 0x83, 0xBE, 0xB4, 0x00, 0x00, 0x00, 0x00 };
	int offset;

	if (FindSignatureOffset(oldClientSig, 10, buffer, 4194304, &offset))
	{
		unsigned char patch[] = { 0x3B };
		SIZE_T written = 0;
		WriteProcessMemory(hProcess, (LPVOID)(baseAddress+offset), patch, 1, &written);
		return;
	}

	if (FindSignatureOffset(newClientSig, 9, buffer, 4194304, &offset))
	{
		unsigned char patch[] = { 0xEB };
		SIZE_T written = 0;
		WriteProcessMemory(hProcess, (LPVOID)(baseAddress+offset), patch, 1, &written);
		return;
	}

}

VOID PatchEncryption(int pid)
{
	HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	LONG baseAddress = 0x0400000;
	PUCHAR buffer = new UCHAR[4194304];
	SIZE_T read = 0;
	ReadProcessMemory(proc, (LPCVOID)baseAddress, buffer, 4194304, &read);

	LoginCryptPatch(buffer, proc, baseAddress);
	TwoFishCryptPatch(buffer, proc, baseAddress);
	DecryptPatch(buffer, proc, baseAddress);

	delete[] buffer;
	CloseHandle(proc);

}
#pragma endregion Encryption Removal

INIT_ERROR DLLEXPORT InstallLibrary(HWND razorhwnd, int clientprocid, int flags) 
{
	razorhWnd = razorhwnd;
	clientProcessId = clientprocid;

	HWND hwnd;
	DWORD procid;
	DWORD threadId;
	hwnd = FindWindowA("Ultima Online", 0);

	do 
	{
		threadId = GetWindowThreadProcessId(hwnd, &procid);
		if (procid == clientprocid) {
			clienthWnd = hwnd;
			break;
		}
		FindWindowExA(0, hwnd, "Ultima Online", 0);
	} while (hwnd != 0);

	WaitForWindow(clientprocid);

	CreateCommunicationMutex();

	PatchEncryption(clientprocid);

	HHOOK hhk = SetWindowsHookExA(WH_CALLWNDPROCRET, CallWndHook, thishModule, threadId);
	if (hhk == NULL) {
		int error = GetLastError();
		printf("%d", error);
	}

	hhk = SetWindowsHookExA(WH_GETMESSAGE, GetMessageHook, thishModule, threadId);
	if (hhk == NULL) {
		int error = GetLastError();
		printf("%d", error);
	}

	WNDCLASSA wndClass;

	wndClass.style = 0;
	wndClass.cbClsExtra = 0;
	wndClass.cbWndExtra = 0;
	wndClass.hCursor = LoadCursor(0, IDC_ARROW);
	wndClass.hIcon = LoadIcon(0, IDI_WINLOGO);
	wndClass.hbrBackground = 0;
	wndClass.lpszMenuName = 0;
	wndClass.lpszClassName = "UOASSIST-TP-MSG-WND";
	wndClass.hInstance = thishModule;
	wndClass.lpfnWndProc = WindowProc;
	ATOM regClass = RegisterClassA(&wndClass);

	uoAssistHwnd = CreateWindowExA(0, "UOASSIST-TP-MSG-WND", "UOASSIST-TP-MSG-WND", 0x0CF0000, 0, 0, 50, 50, 0, 0, thishModule, 0);

	ShowWindow(uoAssistHwnd, 0);

	PostMessageA(clienthWnd, 0x400, flags, (LPARAM)razorhwnd);
	return SUCCESS;
}

LPVOID DLLEXPORT GetSharedAddress() 
{
	return dataBuffer;
}

VOID DLLEXPORT SetServer(UINT serverIp, USHORT serverPort) 
{
	if (dataBuffer != NULL)
	{
		dataBuffer->serverIp = serverIp;
		dataBuffer->serverPort = serverPort;
	}
}

HANDLE DLLEXPORT GetCommMutex()
{
	return mutex;
}

VOID DLLEXPORT SetDataPath(char *dataPath) 
{
	if (dataBuffer != NULL)
	{
		WaitForSingleObject(mutex, -1);
		strncpy_s(dataBuffer->clientDataPath, MAX_PATH, dataPath, 256);
		ReleaseMutex(mutex);
	}
}

VOID DLLEXPORT SetAllowDisconn(BOOL allowDisconn)
{
	if (dataBuffer != NULL && mutex != NULL) 
	{
		WaitForSingleObject(mutex, -1);
		dataBuffer->allowDisconn = allowDisconn;
		ReleaseMutex(mutex);
	}
}

BOOL DLLEXPORT AllowBit(UINT bit)
{
	return TRUE;
}

VOID DLLEXPORT BringToFront(HWND hwnd)
{
	SetWindowPos(hwnd, 0, 0, 0, 0, 0, 3);
	ShowWindow(hwnd, 5);
	SetForegroundWindow(hwnd);
	SetFocus(hwnd);
}

int DLLEXPORT HandleNegotiate(ULONG features)
{
	dataBuffer->features = features;
	return 1;
}

int DLLEXPORT InitializeLibrary(LPCSTR version)
{
	//	AllocConsole();
	//	consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);

	return 1;
}

VOID DLLEXPORT Shutdown(BOOL closeClient)
{
	if (IsWindow(uoAssistHwnd))
	{
		UnregisterClassA("UOASSIST-TP-MSG-WND", thishModule);
		SendMessageA(uoAssistHwnd, 0x10, 0, 0);
	}

	if (IsWindow(clienthWnd))
	{
		PostMessageA(clienthWnd, 0x12, 0, 0);
	}
}

DWORD DLLEXPORT TotalIn()
{
	return dataBuffer->totalIn;
}

DWORD DLLEXPORT TotalOut()
{
	return dataBuffer->totalOut;
}

#pragma region Translate Functions, untested
VOID DLLEXPORT TranslateSetup(TRANSLATESETUP *ptr)
{
	if (ptr != NULL)
		(*ptr)();
}

VOID DLLEXPORT TranslateLogin(TRANSLATELOGIN *ptr, char *name, char *shard)
{
	if (ptr != NULL)
		(*ptr)(name, shard);
}

VOID DLLEXPORT TranslateDo(TRANSLATEDO *ptr, char *intext, char *outtext, int *len)
{
	if (ptr != NULL)
		(*ptr)(intext, outtext, len);
}
#pragma endregion

VOID DLLEXPORT SetDeathMsg(LPCSTR msg)
{
	WaitForSingleObject(mutex, -1);
	strcpy_s(dataBuffer->deathMsg, 16, msg);
	ReleaseMutex(mutex);
}

VOID DLLEXPORT CalibratePosition(int x, int y, int z)
{
	LogPrintfR("CalibratePosition: X: %d Y: %d Z: %d\r\n", x, y, z);
	dataBuffer->X = x;
	dataBuffer->Y = y;
	dataBuffer->Z = z;
	PostMessageA(clienthWnd, 0x401, 0x10, 0x00);
}

VOID DLLEXPORT GetPosition(int *x, int *y, int *z)
{
	//TODO: read it from the client if NULL??

	if (x != NULL)
		*x = dataBuffer->X;

	if (y != NULL)
		*y = dataBuffer->Y;

	if (z != NULL)
		*z = dataBuffer->Z;

	LogPrintfR("GetPosition(): X: %d, Y: %d, Z: %d\r\n", dataBuffer->X, dataBuffer->Y, dataBuffer->Z);
}

int DLLEXPORT GetUOProcId()
{
//	LogPrintfR("GetUOProcId()\r\n");
	return clientProcessId;
}

DLLEXPORT char* GetUOVersion()
{
//	LogPrintfR("GetUOVersion()\r\n");
	char ver[] = "7.0.34.23";
	//return dataBuffer->clientVersion;
	return ver;
}

DLLEXPORT BOOL IsCalibrated()
{
	BOOL ret = false;
	if (dataBuffer->X > 0 && dataBuffer->Y > 0)
		ret = true;
	//TODO: check y and z
	//LogPrintfR("IsCalibrated(): %d, X: %d, Y: %d, Z: %d\r\n", ret, dataBuffer->X, dataBuffer->Y, dataBuffer->Z);
	return ret;
}

#pragma region TODO: DoFeatures
VOID DLLEXPORT DoFeatures(DWORD features)
{
	LogPrintfR("DoFeatures()\r\n");
	//TODO
}
#pragma endregion

DWORD DLLEXPORT GetPacketLength(PUCHAR buffer, int bufferlength)
{
	SHORT len = dataBuffer->packetTable[(unsigned char)buffer[0]];
	if (len == (SHORT)0x8000)
		len = (((BYTE)buffer[1] << 8) | ((BYTE)buffer[2]));

	//LogPrintf("Packet Id %x, len = %x\r\n", buffer[0], len);

	return len;
}

BOOL DLLEXPORT IsDynLength(char packetid)
{
	short len = dataBuffer->packetTable[(unsigned char)packetid];
	if (len == (short)0x8000)
		return true;
	return false;
}