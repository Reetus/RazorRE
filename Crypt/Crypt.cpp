// Crypt.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "Crypt.h"
#include "Compression.h"

HWND clienthWnd;
HWND razorhWnd;
int clientProcessId;
HANDLE mutex = 0;
void *dataAddress;
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

const size_t server_packet_lengths[0x100] = {
	0x0068, 0x0005, 0x0007, 0x0000, 0x0002, 0x0005, 0x0005, 0x0007, // 0x00
	0x000e, 0x0005, 0x0007, 0x0007, 0x0000, 0x0003, 0x0000, 0x003d, // 0x08
	0x00d7, 0x0000, 0x0000, 0x000a, 0x0006, 0x0009, 0x0001, 0x0000, // 0x10
	0x0000, 0x0000, 0x0000, 0x0025, 0x0000, 0x0005, 0x0004, 0x0008, // 0x18
	0x0013, 0x0008, 0x0003, 0x001a, 0x0009, 0x0015, 0x0005, 0x0002, // 0x20
	0x0005, 0x0001, 0x0005, 0x0002, 0x0002, 0x0011, 0x000f, 0x000a, // 0x28
	0x0005, 0x0001, 0x0002, 0x0002, 0x000a, 0x028d, 0x0000, 0x0008, // 0x30
	0x0007, 0x0009, 0x0000, 0x0000, 0x0000, 0x0002, 0x0025, 0x0000, // 0x38
	0x00c9, 0x0000, 0x0000, 0x0229, 0x02c9, 0x0005, 0x0000, 0x000b, // 0x40
	0x0049, 0x005d, 0x0005, 0x0009, 0x0000, 0x0000, 0x0006, 0x0002, // 0x48
	0x0000, 0x0000, 0x0000, 0x0002, 0x000c, 0x0001, 0x000b, 0x006e, // 0x50
	0x006a, 0x0000, 0x0000, 0x0004, 0x0002, 0x0049, 0x0000, 0x0031, // 0x58
	0x0005, 0x0009, 0x000f, 0x000d, 0x0001, 0x0004, 0x0000, 0x0015, // 0x60
	0x0000, 0x0000, 0x0003, 0x0009, 0x0013, 0x0003, 0x000e, 0x0000, // 0x68
	0x001c, 0x0000, 0x0005, 0x0002, 0x0000, 0x0023, 0x0010, 0x0011, // 0x70
	0x0000, 0x0009, 0x0000, 0x0002, 0x0000, 0x000d, 0x0002, 0x0000, // 0x78
	0x003e, 0x0000, 0x0002, 0x0027, 0x0045, 0x0002, 0x0000, 0x0000, // 0x80
	0x0042, 0x0000, 0x0000, 0x0000, 0x000b, 0x0000, 0x0000, 0x0000, // 0x88
	0x0013, 0x0041, 0x0000, 0x0063, 0x0000, 0x0009, 0x0000, 0x0002, // 0x90
	0x0000, 0x001e, 0x0000, 0x0102, 0x0135, 0x0033, 0x0000, 0x0000, // 0x98
	0x0003, 0x0009, 0x0009, 0x0009, 0x0095, 0x0000, 0x0000, 0x0004, // 0xA0
	0x0000, 0x0000, 0x0005, 0x0000, 0x0000, 0x0000, 0x0000, 0x000d, // 0xA8
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0040, 0x0009, 0x0000, // 0xB0
	0x0000, 0x0005, 0x0006, 0x0009, 0x0003, 0x0000, 0x0000, 0x0000, // 0xB8
	0x0024, 0x0000, 0x0000, 0x0000, 0x0006, 0x00cb, 0x0001, 0x0031, // 0xC0
	0x0002, 0x0006, 0x0006, 0x0007, 0x0000, 0x0001, 0x0000, 0x004e, // 0xC8
	0x0000, 0x0002, 0x0019, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, // 0xD0
	0x0000, 0x010C, 0xFFFF, 0xFFFF, 0x0009, 0x0000, 0xFFFF, 0xFFFF, // 0xD8
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 0xE0
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x0015, // 0xE8
	0x0000, 0x0009, 0xFFFF, 0x001a, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 0xF0
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 0xF8
};

const int client_packet_lengths[0x100] = /* From http://ruosi.org/packetguide/index.xml */
{
	/* 00 */  104,   5,   7,   0,  -1,   5,   5,   7,  15,   5,  -1,  -1,  -1,  -1,  -1,  -1,
	/* 10 */   -1,  -1,   0,  10,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,   5,  -1,  -1,
	/* 20 */   -1,  -1,   3,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
	/* 30 */   -1,  -1,  -1,  -1,  10,  -1,  -1,  -1,  -1,  -1,   0,   0,  -1,  -1,  -1,  -1,
	/* 40 */   -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
	/* 50 */   -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  73,  -1,  -1,
	/* 60 */   -1,  -1,  -1,  -1,  -1,  -1,   0,  -1,  -1,  -1,  -1,  -1,  19,  -1,  -1,  -1,
	/* 70 */   -1,   0,   5,   2,  -1,  35,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
	/* 80 */   62,  -1,  -1,  39,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
	/* 90 */   -1,  65,  -1,  -1,  -1,  -1,  -1,  -1,   0,  -1,   0, 258,  -1,  -1,  -1,  -1,
	/* A0 */    3,  -1,  -1,  -1,  -1,  -1,  -1,   4,  -1,  -1,  -1,   0,  -1,   0,  -1,  -1,
	/* B0 */   -1,   0,  -1,   0,  -1,  64,   9,  -1,   0,  -1,  -1,  -1,  -1,   0,   0,   0,
	/* C0 */   -1,  -1,   0,  -1,  -1,  -1,  -1,  -1,   2,   6,   6,  -1,  -1,  -1,  -1,  -1,
	/* D0 */   -1,   1,  -1,  -1,   0,  -1,   0,   0,  -1, 268,   0,  -1,  -1,  -1,  -1,  -1,
	/* E0 */    0,   0,  -1,  -1,   0,  -1,  -1,  -1,  13,  -1,  -1,   0,   0,   0,  -1,  21,
	/* F0 */    0,   9,  -1,  -1,   0,  -1,  -1,  -1, 106,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
};

void SendOutgoingBuffer()
{
	WaitForSingleObject(mutex, -1);
	char tmp[128];
	while (dataBuffer->outSend.Length > 0) 
	{
		char *outbuff;
		char *buff = (dataBuffer->outSend.Buff0+dataBuffer->outSend.Start);

		int len = GetClientPacketLength(buff, dataBuffer->outSend.Length);
		if (len > dataBuffer->outSend.Length || len <= 0)
		{
			break;
		}		

		dataBuffer->outSend.Start += len;
		dataBuffer->outSend.Length -= len;

		outbuff = (char*)malloc(len);

		memcpy(outbuff, buff, len);

		oldSend(serverSocket, outbuff, len, 0);
		//sprintf(tmp, "SendOutgoingBuffer(): Sending packet ID = %02X, Length = %d\r\n", (unsigned char)buff[0], len);
		//Log(tmp);	
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

			WaitForSingleObject(mutex, -1);
			memcpy((dataBuffer->inRecv.Buff0+(dataBuffer->inRecv.Start + dataBuffer->inRecv.Length)), decomBuffer, decomSize);
			dataBuffer->inRecv.Length+=decomSize;

			if ((BYTE)decomBuffer[0] == (BYTE)0xB9)
				mustCompress = true;

			//struct Buffer *outRecv = (struct Buffer *)((BYTE*)dataAddress+524296);
			//memcpy((BYTE*)(((BYTE*)&outRecv->Buff0)+(outRecv->Start + outRecv->Length)), decomBuffer, decomSize);
			//outRecv->Length+=decomSize;

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
		//Log("newSelect() return FD_SET from outRecv\r\n");
		FD_SET(serverSocket, readfds);
		ret = ret + 1;
	}
	//	ReleaseMutex(mutex);


	return ret;
}

int WINAPI newClosesocket(SOCKET s)
{
	//Log("newClosesocket called\r\n");
	int ret = oldClosesocket(s);
	WaitForSingleObject(mutex, -1);
	//memset(dataBuffer->inRecv.Buff0, 0, 524288);
	//memset(dataBuffer->outRecv.Buff0, 0, 524288);
	//memset(dataBuffer->inSend.Buff0, 0, 524288);
	//memset(dataBuffer->outSend.Buff0, 0, 524288);

	mustDecompress = false;
	serverSocket = 0;
	ReleaseMutex(mutex);
	return ret;
}

int WINAPI newConnect(SOCKET s, const struct sockaddr *name, int namelen)
{
	serverSocket = s;
	if (dataAddress != NULL) 
	{
		sockaddr_in newsockaddr;
		newsockaddr.sin_family = AF_INET;
		dataBuffer->serverIp = 0x0100007f;
		dataBuffer->serverPort = 0x0a21;
		newsockaddr.sin_addr.s_addr = dataBuffer->serverIp;
		newsockaddr.sin_port = htons(dataBuffer->serverPort);
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
		}

		//		LogPacket("newRecv()", (char*)ptr, len);

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
			//Log("Setting mustDecompress to true\r\n");
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

BOOL FindSignatureOffset(char *signature, int siglength, char *buffer, int buflen, int *offset)
{
	char *base = buffer;
	bool found = false;

	int size = buflen;
	for (int x = 0; x < size; x++)
	{
		char *ptr = base++;
		if (memcmp(ptr, signature, siglength) == 0)
		{
			found = true;
			*offset = (int)((char*)ptr-(char*)buffer);
			break;
		}
	}
	return found;
}


BOOL FindSignatureAddress(char *signature, char *buffer, int sigsize, int bufsize, int *address)
{
	BOOL found = false;


	for (int x = 0; x < (bufsize - sigsize);x++)
	{
		char *ptr = (char*)((BYTE*)buffer++);
		if (memcmp(ptr, signature, sigsize) == 0)
		{
			found = true;
			*address = (int)ptr;
			break;
		}
	}
	return found;
}

int version_sprintf(char *buffer, const char *fmt, char *val)
{
	strcpy(dataBuffer->clientVersion, val);
	//Log(dataBuffer->clientVersion);
	return sprintf(buffer, fmt, val);
}

extern "C" void __declspec(dllexport) __cdecl OnAttach() {
//	AllocConsole();
//	consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);
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
	WaitForSingleObject(mutex, -1);
	dataBuffer->serverIp = 0x0100007f;
	dataBuffer->serverPort = 0x0a21;
	ReleaseMutex(mutex);

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
		if ((fileMapping = CreateFileMappingA(INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 0x200776, mappingname)) != NULL)
		{
			dataBuffer = (struct DataBuffer *)MapViewOfFile(fileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
			if (dataBuffer == NULL)
				MessageBoxA(0, "MapView failed", 0, 0);
			dataAddress = dataBuffer;
		}
		else
		{
			MessageBoxA(0, "CreateFileMapping failed", 0, 0);
		}
	} else
	{
		MessageBoxA(0, "Mutex failed", 0, 0);
	}

}

void ProcessWindowMessage(int code, WPARAM wParam, LPARAM lParam) 
{
	WaitForSingleObject(mutex, -1);
	SendOutgoingBuffer();
	ReleaseMutex(mutex);

	if (code == 0x400)
		razorhWnd = (HWND)lParam;
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
	if (msg->message == 0x400)
	{
		ProcessWindowMessage(msg->message, wParam, msg->lParam);
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
	return dataAddress;
}

extern "C" void __declspec(dllexport) SetServer(UINT serverIp, USHORT serverPort) 
{
	//Log("SetServer called\r\n");
	if (dataAddress != NULL)
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
	if (dataAddress != NULL)
	{
		WaitForSingleObject(mutex, -1);
		strncpy_s(dataBuffer->clientDataPath, 256, path, 256);
		ReleaseMutex(mutex);
	}
}

extern "C" void __declspec(dllexport) SetAllowDisconn(BOOL allow)
{
	if (dataAddress != NULL && mutex != NULL) 
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

extern "C" int __declspec(dllexport) CaptureScreen(BOOL isFullScreen, char* message)
{
	//TODO
	return NULL;
}

extern "C" void __declspec(dllexport) DoFeatures(int features)
{
	//TODO
}

extern "C" int __declspec(dllexport) GetClientPacketLength(char *buffer, int bufferlength)
{
	if (client_packet_lengths[(unsigned char)buffer[0]] == 0 && bufferlength > 3) {
		return (((BYTE)buffer[1] << 8) | ((BYTE)buffer[2]));
	}

	return client_packet_lengths[(unsigned char)buffer[0]];
}


extern "C" int __declspec(dllexport) GetPacketLength(char *buffer, int bufferlength)
{
	if (server_packet_lengths[(unsigned char)buffer[0]] == 0 && bufferlength > 3) {
		return (((BYTE)buffer[1] << 8) | ((BYTE)buffer[2]));
	}

	return server_packet_lengths[(unsigned char)buffer[0]];
}

extern "C" BOOL __declspec(dllexport) IsDynLength(char packetid)
{
	if (server_packet_lengths[(unsigned char)packetid] == (unsigned char)0)
	{
		return true;
	}
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
