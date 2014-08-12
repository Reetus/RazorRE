// Crypt.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "Crypt.h"
#include "Compression.h"
#include "Misc.h"
#include <dwmapi.h>

// Globals
HINSTANCE hInstance;
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
GETUOVERSION RealGetUOVersion = NULL;
SIZE *SizePtr = NULL;

VOID SendOutgoingBuffer()
{
	WaitForSingleObject(mutex, -1);

	if (dataBuffer->outSend.Length > 0) 
	{
		if (dataBuffer->outSend.Length > (SHARED_BUFF_SIZE/2))
			BufferReset(&dataBuffer->outSend);

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

		if ((CHAR)outbuff[0] == (CHAR)0xA0)
			preServerList = true;

		oldSend(serverSocket, (PCHAR)outbuff, len, 0);

		//free(outbuff);
		delete[] outbuff;
	}
	ReleaseMutex(mutex);
}

VOID DLLEXPORT OnAttach() {
	AllocConsole();
	consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	clientProcessId = GetCurrentProcessId();
	CreateCommunicationMutex();
	InstallApiHooks();

	unsigned char* thisModule = (unsigned char*)GetModuleHandleA(NULL);

	DWORD rdataAddress, rdataSize;
	if (GetPESectionAddress(".rdata", &rdataAddress, &rdataSize))
	{
		UCHAR uoVer[] = "UO Version %s";
		PUCHAR ptr= (PUCHAR)thisModule + rdataAddress;
		DWORD address;
		if (FindSignatureAddress(uoVer, ptr, strlen((PCHAR)uoVer), rdataSize, &address))
		{
			DWORD dataAddress, dataSize;
			if (GetPESectionAddress(".text", &dataAddress, &dataSize)) 
			{
				UCHAR findBytes[] = { 0x68, (UCHAR)address, (UCHAR)(address >> 8), (UCHAR)(address >> 16), (UCHAR)(address >> 24) };
				PUCHAR ptr = (PUCHAR)thisModule + dataAddress;

				if (FindSignatureAddress(findBytes, ptr, 5, dataSize, &address))
				{
					DWORD offset = (address - (DWORD)thisModule) - 10;
					PUCHAR ptr = thisModule+offset;
					if (*ptr == 0xE8) 
					{
						ptr++;
						RealGetUOVersion = (GETUOVERSION)(DWORD)((ptr+4) + *(DWORD*)(ptr));
					}
				}
			}
		}
	}

	/* Set game window size, copied verbatim from code contributed by Zippy, http://www.runuo.com/community/threads/crypt-dll-reverse-engineering.536176/#post-3987305 */
	DWORD dataAddress, dataSize;
	if (GetPESectionAddress(".data", &dataAddress, &dataSize))
	{
		UCHAR findBytes[] = { 0x80, 0x02, 0x00, 0x00, 0xE0, 0x01, 0x00, 0x00 };
		PUCHAR ptr = (PUCHAR)thisModule + dataAddress;
		DWORD address;

		if (FindSignatureAddress(findBytes, ptr, 8, dataSize, &address))
		{
			SizePtr = (SIZE*)address;

			if (GetPESectionAddress(".text", &dataAddress, &dataSize)) 
			{
				PUCHAR ptr = (PUCHAR)thisModule + dataAddress;
				UCHAR findBytes[] = { 0x8B, 0x44, 0x24, 0x04, 0xBA, 0x80, 0x02, 0x00, 0x00, 0x3B, 0xC2, 0xB9, 0xE0, 0x01, 0x00, 0x00 };

				if (FindSignatureAddress(findBytes, ptr, 8, dataSize, &address))
				{
					int i;
					DWORD origAddr = address;
					DWORD oldProt;

					VirtualProtect( (void*)origAddr, 128, PAGE_EXECUTE_READWRITE, &oldProt );
					for (i = 16; i < 128; i++)
					{
						if ( *((BYTE*)(address+i)) == 0xE9 ) // find the first jmp
						{
							memset( (void*)address, 0x90, i ); // nop

							// mov eax, dword [esp+4]
							*((BYTE*)(address+0)) = 0x8B; // mov
							*((BYTE*)(address+1)) = 0x44; //  eax
							*((BYTE*)(address+2)) = 0x24; //  [esp
							*((BYTE*)(address+3)) = 0x04; //      +4]
							address += 4;

							*((BYTE*)address) = 0x50; // push eax
							address++;
							// call OnSetUOWindowSize
							*((BYTE*)address) = 0xE8;
							*((DWORD*)(address+1)) = ((DWORD)OnSetUOWindowSize) - (address + 5);
							address += 5;
							break;
						}
					}
					VirtualProtect( (void*)origAddr, 128, oldProt, &oldProt );
				}
			}
		}
	}

	GetPacketTable();
}

/* Set game window size, copied verbatim from code contributed by Zippy, http://www.runuo.com/community/threads/crypt-dll-reverse-engineering.536176/#post-3987305 */
void __stdcall OnSetUOWindowSize( int width )
{
	if ( width != 800 && width != 600 ) // in case it actually the height for some reason
	{
		SizePtr->cx = 640;
		SizePtr->cy = 480;
	}
	else
	{
		*SizePtr = dataBuffer->gameSize;
	}
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
	if ( clienthWnd == NULL || !IsWindow( clienthWnd ) )
	{
		HWND hWnd = FindWindowA( "Ultima Online", NULL );
		return hWnd;
	}
	else
	{
		return clienthWnd;
	}
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

	dataBuffer->clientVersion[0] = NULL;
	dataBuffer->gameSize.cx = 800;
	dataBuffer->gameSize.cy = 600;
}

#pragma region Window Message Hooks/Functions
VOID ProcessWindowMessage(HWND hwnd, int code, WPARAM wParam, LPARAM lParam, MSG *msg) 
{
	//LogPrintf("ProcessWindowMessage: code = %x, wParam = %d, lParam = %d\r\n", code, wParam, lParam);
	switch (code) 
	{
	case UONET_RAZORINIT:

		clienthWnd = hwnd;
		razorhWnd = (HWND)lParam;
		strncpy(dataBuffer->clientVersion, RealGetUOVersion(), 16);
		LogPrintf("Client version: %s\r\n", dataBuffer->clientVersion);
		PostMessageA(razorhWnd, UONET_MESSAGE, UONET_READY, 0);

		break;

	case UONET_MESSAGE:
		switch (LOWORD(wParam)) 
		{
		case UONET_SEND:
			WaitForSingleObject(mutex, -1);
			SendOutgoingBuffer();
			ReleaseMutex(mutex);
			break;

		case UONET_SETGAMESIZE:
			dataBuffer->gameSize.cx = (short)(lParam);
			dataBuffer->gameSize.cy = (short)(lParam>>16);
			LogPrintf("SetGameSize: %dx%d\r\n", dataBuffer->gameSize.cx, dataBuffer->gameSize.cy);
			break;

		case UONET_LOGMESSAGE:
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
		break;

	case WM_KEYDOWN:
	case WM_SYSKEYDOWN:

		if (msg && !SendMessage(razorhWnd, UONET_MESSAGE, UONET_KEYDOWN, wParam))
			msg->message = msg->lParam = msg->wParam = 0;
		break;

	case WM_MOUSEWHEEL:

		PostMessage(razorhWnd, UONET_MESSAGE, UONET_MOUSE, MAKELONG(0, ((short)HIWORD(wParam)) < 0 ? -1 : 1));
		break;

	case WM_SETFOCUS:

		PostMessage(razorhWnd, UONET_MESSAGE, UONET_FOCUS, true);
		break;

	case WM_KILLFOCUS:

		PostMessage(razorhWnd, UONET_MESSAGE, UONET_FOCUS, false);
		break;

	case WM_ACTIVATE:

		PostMessage(razorhWnd, UONET_MESSAGE, UONET_ACTIVATE, wParam);
		break;

	case UONET_TITLEBAR:
	case WM_NCPAINT:
	case WM_NCACTIVATE:
	case WM_ERASEBKGND:
		{
			if (strlen(dataBuffer->titleBar) > 0)
			{
				DWMNCRENDERINGPOLICY policy = DWMNCRP_ENABLED;
				DwmSetWindowAttribute(hwnd, DWMWA_NCRENDERING_POLICY, &policy, sizeof(policy));
				HDC hdc = GetWindowDC(hwnd);
				HDC hdcMem = CreateCompatibleDC(hdc);

				RECT rect, rect2;
				GetWindowRect(hwnd, &rect2);
				RECT r = GetTitlebarRect(hwnd);
				HBITMAP hBitmap = CreateCompatibleBitmap(hdc, rect2.right, rect2.bottom);
				SelectObject(hdcMem, hBitmap);

				rect.top = rect.left = 0;
				rect.right = rect2.right - rect2.left;
				rect.bottom = (r.bottom - r.top);

				FillRect(hdcMem, &rect, GetSysColorBrush(COLOR_ACTIVECAPTION));
				DrawTitlebar(hdcMem, hwnd, rect, dataBuffer->titleBar);
				BitBlt(hdc, r.left, r.top, (r.right - r.left), (r.bottom - r.top), hdcMem, 0, 0, SRCCOPY);
				DeleteDC(hdcMem);
				ReleaseDC(hwnd, hdc);
			}
			break;
		}
	}
}

LRESULT CALLBACK CallWndHook(int code,WPARAM wParam,LPARAM lParam)
{
	if (code >= 0)
	{
		CWPRETSTRUCT *cwps = (CWPRETSTRUCT*)lParam;
		ProcessWindowMessage(cwps->hwnd, cwps->message, cwps->wParam, cwps->lParam, 0);
	}
	return CallNextHookEx(0, code, wParam, lParam);
}

LRESULT CALLBACK GetMessageHook(int code,WPARAM wParam,LPARAM lParam)
{
	if (code >= 0 && wParam != PM_NOREMOVE)
	{
		MSG *msg = (MSG*)lParam;
		ProcessWindowMessage(msg->hwnd, msg->message, msg->wParam, msg->lParam, msg);
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
	DWORD offset = 0;
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
	DWORD offset;

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
	DWORD offset;

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

	DWORD procid;
	DWORD threadId;

	HWND hWnd = FindUOWindow();
	if ( hWnd != NULL )
		threadId = GetWindowThreadProcessId( hWnd, &procid );

	clienthWnd = hWnd;

	WaitForWindow(procid);

	CreateCommunicationMutex();

	PatchEncryption(clientprocid);

	HHOOK hhk = SetWindowsHookExA(WH_CALLWNDPROCRET, CallWndHook, hInstance, threadId);
	if (hhk == NULL) {
		return NO_HOOK;
	}

	hhk = SetWindowsHookExA(WH_GETMESSAGE, GetMessageHook, hInstance, threadId);
	if (hhk == NULL) {
		return NO_HOOK;
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
	wndClass.hInstance = hInstance;
	wndClass.lpfnWndProc = WindowProc;
	ATOM regClass = RegisterClassA(&wndClass);

	uoAssistHwnd = CreateWindowExA(0, "UOASSIST-TP-MSG-WND", "UOASSIST-TP-MSG-WND", WS_OVERLAPPEDWINDOW, 0, 0, 50, 50, 0, 0, hInstance, 0);

	ShowWindow(uoAssistHwnd, 0);

	PostMessageA(clienthWnd, UONET_RAZORINIT, flags, (LPARAM)razorhwnd);
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
	return 1;
}

VOID DLLEXPORT Shutdown(BOOL closeClient)
{
	if (IsWindow(uoAssistHwnd))
	{
		UnregisterClassA("UOASSIST-TP-MSG-WND", hInstance);
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
	PostMessageA(clienthWnd, UONET_MESSAGE, 0x10, 0x00);
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

	//LogPrintfR("GetPosition(): X: %d, Y: %d, Z: %d\r\n", dataBuffer->X, dataBuffer->Y, dataBuffer->Z);
}

int DLLEXPORT GetUOProcId()
{
	//	LogPrintfR("GetUOProcId()\r\n");
	return clientProcessId;
}

DLLEXPORT char* GetUOVersion()
{
	if (dataBuffer)
	{
		LogPrintfR("GetUOVersion(): %s\r\n", dataBuffer->clientVersion);
		return dataBuffer->clientVersion;
	}

	return "7.0.0.0";
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