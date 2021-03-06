#include "stdafx.h"

SEND oldSend;
SELECT oldSelect;
CLOSESOCKET oldClosesocket;
CONNECT oldConnect;
RECV oldRecv;
BOOL preServerList = TRUE;

VOID InstallApiHooks()
{
	HookFunc("wsock32.dll", "connect", &newConnect, (FARPROC*)&oldConnect);
	HookFunc("wsock32.dll", "recv", &newRecv, (FARPROC*)&oldRecv);
	HookFunc("wsock32.dll", "send", &newSend, (FARPROC*)&oldSend);
	HookFunc("wsock32.dll", "closesocket", &newClosesocket, (FARPROC*)&oldClosesocket);
	HookFunc("wsock32.dll", "select", &newSelect, (FARPROC*)&oldSelect);
}

DWORD WINAPI newClosesocket(SOCKET s)
{
	int ret = oldClosesocket(s);

	if (s == serverSocket)
	{
		WaitForSingleObject(mutex, -1);

		mustDecompress = false;
		serverSocket = 0;
		ReleaseMutex(mutex);

		//	PostMessageA(razorhWnd, UONET_MESSAGE, UONET_NOTREADY, 0);
		PostMessageA(razorhWnd, UONET_MESSAGE, UONET_DISCONNECT, 0);
	}
	LogPrintf("newClosesocket(%d)\r\n", s);
	return ret;
}

DWORD WINAPI newConnect(SOCKET s, const struct sockaddr *name, int namelen)
{
	struct sockaddr_in *sin = (struct sockaddr_in*)name;

	if (preServerList)
	{
		sin->sin_addr.S_un.S_addr = dataBuffer->serverIp;
		sin->sin_port = htons(dataBuffer->serverPort);
	}

	LogPrintf("newConnect(%d): %s,%d, %d\r\n", s, inet_ntoa(sin->sin_addr), ntohs(sin->sin_port), preServerList);

	int ret = oldConnect(s, name, namelen);
	if (ret != SOCKET_ERROR)
	{
		WaitForSingleObject(mutex, -1);
		serverSocket = s;
		ReleaseMutex(mutex);

		PostMessageA(razorhWnd, 0x401, UONET_CONNECT, 0);
	}

	return ret;
}

DWORD WINAPI newRecv(SOCKET s, char *buf, int buflen, int flags)
{
	int written = 0;

	if (dataBuffer->outRecv.Length > 0) 
	{
		char buffer[16384];
		int comlen = 0;

		PUCHAR buff = dataBuffer->outRecv.Buff0+dataBuffer->outRecv.Start;
		int len = GetPacketLength(buff, dataBuffer->outRecv.Length);
		if (len <= 0)
		{			
			return 0;
		}

		if (((unsigned char*)buff)[0] == (unsigned char)0xB9)
		{
			mustCompress = true;
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

		if ((dataBuffer->outRecv.Start + dataBuffer->outRecv.Length) > (SHARED_BUFF_SIZE/2))
			BufferReset(&dataBuffer->outRecv);

		ReleaseMutex(mutex);
	}

	return written;
}

DWORD WINAPI newSelect(int nfds, PFD_SET readfds, PFD_SET writefds, PFD_SET exceptfds, const struct timeval *timeout)
{
	if (readfds->fd_array[0] != NULL) {
		serverSocket = readfds->fd_array[0];
		SendOutgoingBuffer();
		FD_SET mySet;
		FD_ZERO(&mySet);
		FD_SET(serverSocket, &mySet);
		timeval myTimeout;
		myTimeout.tv_usec = 1000;

		int val = oldSelect(1, &mySet, 0, 0, &myTimeout);
		if (val > 0)
		{
			CHAR recvBuffer[16384];
			UCHAR decomBuffer[16384];
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

			if ((dataBuffer->inRecv.Start + dataBuffer->inRecv.Length + decomSize) > (SHARED_BUFF_SIZE/2))
				BufferReset(&dataBuffer->inRecv);

			memcpy((dataBuffer->inRecv.Buff0+(dataBuffer->inRecv.Start + dataBuffer->inRecv.Length)), decomBuffer, decomSize);
			dataBuffer->inRecv.Length+=decomSize;

			if ((BYTE)decomBuffer[0] == (BYTE)0xB9)
				mustCompress = true;

			if ((BYTE)decomBuffer[0] == (BYTE)0x8C)
			{
				preServerList = false;
				Log("preServerList = false\r\n");
			}

			ReleaseMutex(mutex);

			PostMessageA(razorhWnd, UONET_MESSAGE, UONET_RECV, 0);
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

DWORD WINAPI newSend(SOCKET s, const char *buf, int len, int flags)
{
	char mybuff[16384];
	int mysize = 0;
	int ret = len;

	if (len >= 3 && (int)buf > 0x40000000 /* Kludge, what are the send()'s with stack addresses? */) {
		WaitForSingleObject(mutex, -1);

		memcpy(mybuff, buf, len);
		mysize = len;

		if (dataBuffer->inSend.Length > (SHARED_BUFF_SIZE/2))
			BufferReset(&dataBuffer->inSend);

		PUCHAR ptr = (dataBuffer->inSend.Buff0 + (dataBuffer->inSend.Start+dataBuffer->inSend.Length));

		memcpy(ptr, mybuff, mysize);
		dataBuffer->inSend.Length+=mysize;

		if ((CHAR)mybuff[0] == (CHAR)0x91) {
			uo_decompression_init(&decompress);
			mustDecompress = true;
		}

		ReleaseMutex(mutex);
		PostMessageA(razorhWnd, UONET_MESSAGE, UONET_SEND, 0);
	} else {
		ret = oldSend(s, buf, len, flags);
	}
	return ret;
}

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
