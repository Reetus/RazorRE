#include "stdafx.h"

SEND oldSend;
SELECT oldSelect;
CLOSESOCKET oldClosesocket;
CONNECT oldConnect;
RECV oldRecv;

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
	WaitForSingleObject(mutex, -1);

	mustDecompress = false;
	serverSocket = 0;
	ReleaseMutex(mutex);

	//	PostMessageA(razorhWnd, 0x401, UONET_NOTREADY, 0);
	//	PostMessageA(razorhWnd, 0x401, UONET_DISCONNECT, 0);

	return ret;
}

DWORD WINAPI newConnect(SOCKET s, const struct sockaddr *name, int namelen)
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

		// Check if getting close to buffer filling
		if ((dataBuffer->outRecv.Start + dataBuffer->outRecv.Length + 8192) > SHARED_BUFF_SIZE)
		{
			PUCHAR tmpBuffer = new UCHAR[dataBuffer->outRecv.Length];
			memcpy(tmpBuffer, dataBuffer->outRecv.Buff0+dataBuffer->outRecv.Start, dataBuffer->outRecv.Length);
			memcpy(dataBuffer->outRecv.Buff0, tmpBuffer, dataBuffer->outRecv.Length);
			dataBuffer->outRecv.Start = 0;
			delete[] tmpBuffer;
		}

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
			// Check for buffer overflow, rewrite from 0
			if ((dataBuffer->inRecv.Start + dataBuffer->inRecv.Length + decomSize) > SHARED_BUFF_SIZE)
			{
				PUCHAR tmpBuffer = new UCHAR[dataBuffer->inRecv.Length];
				memcpy(tmpBuffer, dataBuffer->inRecv.Buff0+dataBuffer->inRecv.Start, dataBuffer->inRecv.Length);
				memcpy(dataBuffer->inRecv.Buff0, tmpBuffer, dataBuffer->inRecv.Length);
				dataBuffer->inRecv.Start = 0;
				delete[] tmpBuffer;
			}

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

DWORD WINAPI newSend(SOCKET s, const char *buf, int len, int flags)
{
	char mybuff[16384];
	int mysize = 0;
	int ret = len;

	if (len >= 3 && (int)buf > 0x40000000 /* Kludge, what are the send()'s with stack addresses? */) {
		WaitForSingleObject(mutex, -1);

		memcpy(mybuff, buf, len);
		mysize = len;

		PUCHAR ptr = (dataBuffer->inSend.Buff0 + (dataBuffer->inSend.Start+dataBuffer->inSend.Length));

		memcpy(ptr, mybuff, mysize);
		dataBuffer->inSend.Length+=mysize;

		if ((CHAR)mybuff[0] == (CHAR)0x91) {
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
