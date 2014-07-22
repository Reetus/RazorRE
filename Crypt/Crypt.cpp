// Crypt.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "Crypt.h"
#include "Compression.h"

HWND clienthWnd;
HWND razorhWnd;
int clientProcessId;
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

void SendOutgoingBuffer()
{
	WaitForSingleObject(mutex, -1);
	char tmp[128];
	if (dataBuffer->outSend.Length > 0) 
	{
		char *outbuff;
		char *buff = (dataBuffer->outSend.Buff0+dataBuffer->outSend.Start);

		int len = GetPacketLength(buff, dataBuffer->outSend.Length);
		if (len > dataBuffer->outSend.Length || len <= 0)
		{
			return;
		}		

		//LogPacket("Client -> Server", buff, len);
		dataBuffer->totalOut+=len;

		dataBuffer->outSend.Start += len;
		dataBuffer->outSend.Length -= len;

		outbuff = (char*)malloc(len);

		memcpy(outbuff, buff, len);

		oldSend(serverSocket, outbuff, len, 0);

		free(outbuff);
	}
	ReleaseMutex(mutex);
}

int WINAPI newSelect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timeval *timeout)
{
	if (readfds->fd_array[0] != NULL) {
		serverSocket = readfds->fd_array[0];
		SendOutgoingBuffer();
		fd_set mySet;
		FD_ZERO(&mySet);
		FD_SET(serverSocket, &mySet);
		timeval myTimeout;
		myTimeout.tv_usec = 1000;

		int val = oldSelect(1, &mySet, 0, 0, &myTimeout);
		if (val > 0)
		{
			char recvBuffer[16384];
			char decomBuffer[16384];
			int decomSize = 0;
			int size = oldRecv(serverSocket, recvBuffer, 16384, 0);
			if (mustDecompress) {
				decomSize = (int)uo_decompress(&decompress, (unsigned char *)decomBuffer, 16384, (unsigned char *)recvBuffer, size);
			} else {
				memcpy(decomBuffer, recvBuffer, size);
				decomSize = size;
			}

			dataBuffer->totalIn+=size;

			WaitForSingleObject(mutex, -1);
			memcpy((dataBuffer->inRecv.Buff0+(dataBuffer->inRecv.Start + dataBuffer->inRecv.Length)), decomBuffer, decomSize);
			dataBuffer->inRecv.Length+=decomSize;

			if ((BYTE)decomBuffer[0] == (BYTE)0xB9)
				mustCompress = true;

			ReleaseMutex(mutex);

			PostMessageA(razorhWnd, 0x401, UONET_RECV, 0);
		}
	}
	int ret = oldSelect(nfds, readfds, writefds, exceptfds, timeout);

	if (FD_ISSET(serverSocket, readfds))
	{
		ret -= 1;
		FD_CLR(serverSocket, readfds);
	}

	//	WaitForSingleObject(mutex, -1);
	if (dataBuffer->outRecv.Length > 0)
	{
		FD_SET(serverSocket, readfds);
		ret = ret + 1;
	}
	//	ReleaseMutex(mutex);


	return ret;
}

int WINAPI newClosesocket(SOCKET s)
{
	int ret = oldClosesocket(s);
	WaitForSingleObject(mutex, -1);

	mustDecompress = false;
	serverSocket = 0;
	ReleaseMutex(mutex);

	//	PostMessageA(razorhWnd, 0x401, UONET_NOTREADY, 0);
	//	PostMessageA(razorhWnd, 0x401, UONET_DISCONNECT, 0);

	return ret;
}

int WINAPI newConnect(SOCKET s, const struct sockaddr *name, int namelen)
{
	PostMessageA(razorhWnd, 0x401, UONET_CONNECT, 0);
	serverSocket = s;
	if (dataBuffer != NULL) 
	{
		sockaddr_in newsockaddr;
		newsockaddr.sin_family = AF_INET;
		newsockaddr.sin_addr.s_addr = dataBuffer->serverIp;
		newsockaddr.sin_port = htons(dataBuffer->serverPort);
		unsigned char *ptr = (unsigned char*)&dataBuffer->serverIp;
		LogPrintf("newConnect: %d.%d.%d.%d,2593\r\n", ptr[0], ptr[1], ptr[2], ptr[3], dataBuffer->serverPort);
		return oldConnect(s, (SOCKADDR *)&newsockaddr, sizeof(newsockaddr));
	}
	return oldConnect(s, name, namelen);
}

int WINAPI newRecv(SOCKET s, char *buf, int buflen, int flags)
{
	int written = 0;

	if (dataBuffer->outRecv.Length > 0) 
	{
		char buffer[16384];
		char tmp[128];
		int comlen = 0;

		char *buff = dataBuffer->outRecv.Buff0+dataBuffer->outRecv.Start;
		int len = GetPacketLength(buff, dataBuffer->outRecv.Length);
		if (len <= 0)
		{			
			return 0;
		}

		if (((unsigned char*)buff)[0] == (unsigned char)0xB9)
		{
			mustCompress = true;

			//TODO: Find out when this is really sent
			PostMessageA(razorhWnd, 0x401, UONET_READY, 0);
		}

		if (mustCompress) {
			comlen = uo_compress((unsigned char*)buffer, 16384, (unsigned char*)buff, len);
		} else
		{
			memcpy(buffer, buff, len);
			comlen = len;
		}

		memcpy(buf, buffer, comlen);
		written += comlen;

		WaitForSingleObject(mutex, -1);
		dataBuffer->outRecv.Start += len;
		dataBuffer->outRecv.Length -= len;
		//		LogPacket("Server -> Client", (char*)buffer, comlen);
		ReleaseMutex(mutex);
	}

	return written;
}


int WINAPI newSend(SOCKET s, const char *buf, int len, int flags)
{
	char mybuff[16384];
	int mybuff_size;
	int mysize = 0;

	char tmp[128];
	int ret = len;

	if (len > 3 && (int)buf > 0x40000000 /* Kludge, what are the send()'s with stack addresses? */) {
		WaitForSingleObject(mutex, -1);

		memcpy(mybuff, buf, len);
		mysize = len;

		char *ptr = (dataBuffer->inSend.Buff0 + (dataBuffer->inSend.Start+dataBuffer->inSend.Length));

		memcpy(ptr, mybuff, mysize);
		dataBuffer->inSend.Length+=mysize;

		if ((char)mybuff[0] == (char)0x91) {
			uo_decompression_init(&decompress);
			mustDecompress = true;
		}

		ReleaseMutex(mutex);
		PostMessageA(razorhWnd, 0x401, UONET_SEND, 0);
	} else {
		ret = oldSend(s, buf, len, flags);
	}
	return ret;
}

int version_sprintf(char *buffer, const char *fmt, char *val)
{
	strcpy(dataBuffer->clientVersion, val);
	Log(dataBuffer->clientVersion);
	return sprintf(buffer, fmt, val);
}

extern "C" void __declspec(dllexport) __cdecl OnAttach() {
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

			char uoVer[] = "UO Version %s";
			char *ptr = (char*)thisModule+position;
			int address;
			if (FindSignatureAddress(uoVer, ptr, strlen(uoVer), size, &address))
			{
				char findBytes[] = { 0x68, address, (address >> 8), (address >> 16), (address >> 24) };

				ish = (IMAGE_SECTION_HEADER*)((BYTE*)thisModule + idh->e_lfanew + sizeof(IMAGE_NT_HEADERS));
				ptr = (char*)thisModule+ish->VirtualAddress;

				if (FindSignatureAddress(findBytes, ptr, 5, ish->Misc.VirtualSize, &address)) 
				{
					int offset = (address-(int)ptr)+6;
					ptr = (char*)ptr+offset;

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

	idh = (IMAGE_DOS_HEADER*)thisModule;
	inh = (IMAGE_NT_HEADERS*)((BYTE*)thisModule + idh->e_lfanew);
	ish = (IMAGE_SECTION_HEADER*)((BYTE*)thisModule + idh->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	for (int i = 0; i < inh->FileHeader.NumberOfSections;i++)
	{
		if (_stricmp((char*)ish->Name, ".data") == 0) 
		{
			int position = ish->VirtualAddress;
			int size = ish->Misc.VirtualSize;
			char *ptr = (char*)thisModule+position;
			LogPrintf(".data position = %x\r\n", ptr);
			int offset = 0;

			// Get packet size table, lifted from https://github.com/jaryn-kubik/UOInterface/blob/master/UOInterface/PacketHooks.cpp
			unsigned char sig[] =
			{
				0x01, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC, 0xCC, 0x05, 0x00, 0x00, 0x00, //packet 1, unknown, len 5
				0x02, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, //packet 2, unknown, len ...
				0x03, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC, 0xCC, 0x00, //0x80, 0x00, 0x00  //packet 3, unknown, len 0x8000 (dynamic)
			};

			if (FindSignatureAddressWildcard(sig, sizeof(sig), ptr, size, 0xCC, &offset))
			{
				struct ClientPacketInfo *pt = ((struct ClientPacketInfo*)offset)-1;
				
				for (UINT unknown = pt->unknown;pt->unknown == unknown;pt++)
				{
					dataBuffer->packetTable[pt->id] = pt->length;
//					LogPrintf("ID: %x, Length = %x\r\n", pt->id, pt->length);
				}
			} 
			else
			{
				Log("Error: Cannot locate packet table.\r\n");
			}
			break;
		}
		ish = (IMAGE_SECTION_HEADER*)((BYTE*)ish + sizeof(IMAGE_SECTION_HEADER));
	}

}

extern "C" HWND __declspec(dllexport) FindUOWindow() 
{
	if (IsWindow(clienthWnd))
	{
		return clienthWnd;
	} 
	return FindWindowA("Ultima Online", 0);
}

extern "C" void __declspec(dllexport) WaitForWindow(DWORD dwProcessId) 
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, NULL, dwProcessId);
	do {
		Sleep(500);
	} while (FindUOWindow() == NULL);
	CloseHandle(hProcess);
}

void CreateCommunicationMutex() 
{
	char mutexname[256];
	char mappingname[256];
	mutex = 0;
	sprintf_s(mutexname, "UONetSharedCOMM_%x", clientProcessId);

	if ((mutex = CreateMutexA(0, 0, mutexname)) != NULL) 
	{
		sprintf_s(mappingname, "UONetSharedFM_%x", clientProcessId);
		if ((fileMapping = CreateFileMappingA(INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, sizeof(struct DataBuffer), mappingname)) != NULL)
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

void ProcessWindowMessage(int code, WPARAM wParam, LPARAM lParam) 
{
	switch (code) 
	{
	case 0x400:
		razorhWnd = (HWND)lParam;
		break;
	case 0x401:
		{
			LogPrintf("ProcessWindowMessage: code = %x, wParam = %d, lParam = %d\r\n", code, wParam, lParam);
			switch (wParam) 
			{
			case UONET_SEND:
				WaitForSingleObject(mutex, -1);
				SendOutgoingBuffer();
				ReleaseMutex(mutex);
				break;
			case UONET_SETGAMESIZE:
				// TODO
				int x = (short)(lParam);
				int y = (short)(lParam>>16);
				LogPrintf("SetGameSize: %dx%d\r\n", x, y);
				dataBuffer->gameSizeX = x;
				dataBuffer->gameSizeY = y;
				break;
			}
			break;
		}
	}
}

LRESULT CALLBACK CallWndHook(int code,WPARAM wParam,LPARAM lParam)
{
	CWPSTRUCT *cwps = (CWPSTRUCT*)lParam;
	if (cwps->message == 0x400)
	{
		ProcessWindowMessage(cwps->message, wParam, cwps->lParam);
	}

	return CallNextHookEx(0, code, wParam, lParam);
}

LRESULT CALLBACK GetMessageHook(int code,WPARAM wParam,LPARAM lParam)
{
	MSG *msg = (MSG*)lParam;
	if (msg->message == 0x400 || msg->message == 0x401)
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

void LoginCryptPatch(char *buffer, HANDLE hProcess, long baseAddress)
{
	char newClientSig[] = { 0x75, 0x12, 0x8B, 0x54, 0x24, 0x0C };
	int offset = 0;
	SIZE_T written = 0;

	if (FindSignatureOffset(newClientSig, 6, buffer, 4194304, &offset))
	{
		char patch[] = { 0xEB };
		WriteProcessMemory(hProcess, (LPVOID)(baseAddress+offset), patch, 1, &written);
	}
}

void TwoFishCryptPatch(char *buffer, HANDLE hProcess, long baseAddress)
{
	char oldClientSig[] = { 0x8B, 0xD9, 0x8B, 0xC8, 0x48, 0x85, 0xC9, 0x0F, 0x84 };
	char newClientSig[] = { 0x74, 0x0F, 0x83, 0xB9, 0xB4, 0x00, 0x00, 0x00, 0x00 };
	int offset;

	if (FindSignatureOffset(oldClientSig, 9, buffer, 4194304, &offset))
	{
		char patch[] = { 0x85 };
		SIZE_T written = 0;
		WriteProcessMemory(hProcess, (LPVOID)(baseAddress+offset), patch, 1, &written);
		return;
	}

	if (FindSignatureOffset(newClientSig, 9, buffer, 4194304, &offset))
	{
		char patch[] = { 0xEB };
		SIZE_T written = 0;
		WriteProcessMemory(hProcess, (LPVOID)(baseAddress+offset), patch, 1, &written);
		return;
	}
}

void DecryptPatch(char *buffer, HANDLE hProcess, long baseAddress)
{
	char oldClientSig[] = { 0x8B, 0x86, 0x04, 0x01, 0x0A, 0x00, 0x85, 0xC0, 0x74, 0x52 };
	char newClientSig[] = { 0x74, 0x37, 0x83, 0xBE, 0xB4, 0x00, 0x00, 0x00, 0x00 };
	int offset;

	if (FindSignatureOffset(oldClientSig, 10, buffer, 4194304, &offset))
	{
		char patch[] = { 0x3B };
		SIZE_T written = 0;
		WriteProcessMemory(hProcess, (LPVOID)(baseAddress+offset), patch, 1, &written);
		return;
	}

	if (FindSignatureOffset(newClientSig, 9, buffer, 4194304, &offset))
	{
		char patch[] = { 0xEB };
		SIZE_T written = 0;
		WriteProcessMemory(hProcess, (LPVOID)(baseAddress+offset), patch, 1, &written);
		return;
	}

}

void PatchEncryption(int pid)
{
	HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	long baseAddress = 0x0400000;
	char *buffer = (char*)malloc(4194304);
	SIZE_T read = 0;
	ReadProcessMemory(proc, (LPCVOID)baseAddress, buffer, 4194304, &read);

	LoginCryptPatch(buffer, proc, baseAddress);
	TwoFishCryptPatch(buffer, proc, baseAddress);
	DecryptPatch(buffer, proc, baseAddress);

	free(buffer);
	CloseHandle(proc);

}

extern "C" INIT_ERROR __declspec(dllexport) InstallLibrary(HWND razorhwnd, int clientprocid, int flags) 
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

extern "C" LPVOID __declspec(dllexport) GetSharedAddress() 
{
	return dataBuffer;
}

extern "C" void __declspec(dllexport) SetServer(UINT serverIp, USHORT serverPort) 
{
	if (dataBuffer != NULL)
	{
		dataBuffer->serverIp = serverIp;
		dataBuffer->serverPort = serverPort;
	}
}

extern "C" HANDLE __declspec(dllexport) GetCommMutex()
{
	return mutex;
}

extern "C" void __declspec(dllexport) SetDataPath(char *path) 
{
	if (dataBuffer != NULL)
	{
		WaitForSingleObject(mutex, -1);
		strncpy_s(dataBuffer->clientDataPath, 256, path, 256);
		ReleaseMutex(mutex);
	}
}

extern "C" void __declspec(dllexport) SetAllowDisconn(BOOL allow)
{
	if (dataBuffer != NULL && mutex != NULL) 
	{
		WaitForSingleObject(mutex, -1);
		dataBuffer->allowDisconn = allow;
		ReleaseMutex(mutex);
	}
}

extern "C" BOOL __declspec(dllexport) AllowBit(UINT bit)
{
	return TRUE;
}

extern "C" void __declspec(dllexport) BringToFront(HWND hwnd)
{
	SetWindowPos(hwnd, 0, 0, 0, 0, 0, 3);
	ShowWindow(hwnd, 5);
	SetForegroundWindow(hwnd);
	SetFocus(hwnd);
}

extern "C" int __declspec(dllexport) HandleNegotiate(unsigned long features)
{
	dataBuffer->features = features;
	return 1;
}

extern "C" int __declspec(dllexport) InitializeLibrary(char *version)
{
	//	AllocConsole();
	//	consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);

	return 1;
}

extern "C" void __declspec(dllexport) Shutdown(BOOL closeClient)
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

extern "C" int __declspec(dllexport) TotalIn()
{
	return dataBuffer->totalIn;
}

extern "C" int __declspec(dllexport) TotalOut()
{
	return dataBuffer->totalOut;
}

#pragma region Translate Functions, untested
extern "C" void __declspec(dllexport) TranslateSetup(TRANSLATESETUP *ptr)
{
	if (ptr != NULL)
		(*ptr)();
}

extern "C" void __declspec(dllexport) TranslateLogin(TRANSLATELOGIN *ptr, char *name, char *shard)
{
	if (ptr != NULL)
		(*ptr)(name, shard);
}

extern "C" void __declspec(dllexport) TranslateDo(TRANSLATEDO *ptr, char *intext, char *outtext, int *len)
{
	if (ptr != NULL)
		(*ptr)(intext, outtext, len);
}
#pragma endregion

extern "C" void __declspec(dllexport) SetDeathMsg(char *msg)
{
	WaitForSingleObject(mutex, -1);
	strcpy(dataBuffer->deathMsg, msg);
	ReleaseMutex(mutex);
}

extern "C" void __declspec(dllexport) CalibratePosition(int x, int y, int z)
{
	dataBuffer->X = x;
	dataBuffer->Y = y;
	dataBuffer->Z = z;
	PostMessageA(clienthWnd, 0x401, 0x10, 0x00);
}

extern "C" void __declspec(dllexport) GetPosition(int *x, int *y, int *z)
{
	//TODO: read it from the client if NULL??

	if (x != NULL)
		*x = dataBuffer->X;

	if (y != NULL)
		*y = dataBuffer->Y;

	if (z != NULL)
		*z = dataBuffer->Z;

}

extern "C" int __declspec(dllexport) GetUOProcId()
{
	return clientProcessId;
}

extern "C" __declspec(dllexport) char* GetUOVersion()
{
	char ver[] = "7.0.34.23";
	//return dataBuffer->clientVersion;
	return ver;
}

extern "C" __declspec(dllexport) BOOL IsCalibrated()
{
	if (dataBuffer->X > -1)
		return true;
	//TODO: check y and z
	return false;
}

#pragma region TODO: CaptureScreen, DoFeatures
extern "C" int __declspec(dllexport) CaptureScreen(BOOL isFullScreen, char* message)
{
	//TODO
	return NULL;
}

extern "C" void __declspec(dllexport) DoFeatures(int features)
{
	//TODO
}
#pragma endregion

extern "C" int __declspec(dllexport) GetPacketLength(char *buffer, int bufferlength)
{
	short len = dataBuffer->packetTable[(unsigned char)buffer[0]];
	if (len == (short)0x8000)
		len = (((BYTE)buffer[1] << 8) | ((BYTE)buffer[2]));

	//LogPrintf("Packet Id %x, len = %x\r\n", buffer[0], len);

	return len;
}

extern "C" BOOL __declspec(dllexport) IsDynLength(char packetid)
{
	short len = dataBuffer->packetTable[(unsigned char)packetid];
	if (len == (short)0x8000)
		return true;
	return false;
}

void InstallApiHooks()
{
	HookFunc("wsock32.dll", "connect", &newConnect, (FARPROC*)&oldConnect);
	HookFunc("wsock32.dll", "recv", &newRecv, (FARPROC*)&oldRecv);
	HookFunc("wsock32.dll", "send", &newSend, (FARPROC*)&oldSend);
	HookFunc("wsock32.dll", "closesocket", &newClosesocket, (FARPROC*)&oldClosesocket);
	HookFunc("wsock32.dll", "select", &newSelect, (FARPROC*)&oldSelect);
}
