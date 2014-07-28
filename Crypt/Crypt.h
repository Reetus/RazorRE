#pragma once
#pragma pack(1)
#include "stdafx.h"

#define SHARED_BUFF_SIZE 524288

struct Buffer 
{
	DWORD Length;
	DWORD Start;
	UCHAR Buff0[SHARED_BUFF_SIZE];
};

struct ClientPacketInfo
{
	UINT id;
	UINT unknown;
	UINT length;
};

struct DataBuffer
{
	struct Buffer inRecv; // 524296 0x80008
	struct Buffer outRecv; //1048592 0x100010 
	struct Buffer inSend; //1572888 0x180018
	struct Buffer outSend; //2097184 0x200020
	CHAR titleBar[512];
	BOOL allowDisconn;
	CHAR clientDataPath[MAX_PATH];
	DWORD serverIp;
	USHORT serverPort;
	CHAR clientVersion[128];
	DWORD X;
	DWORD Y;
	DWORD Z;
	ULONG features;
	CHAR deathMsg[16];
	DWORD totalIn;
	DWORD totalOut;
	DWORD gameSizeX;
	DWORD gameSizeY;
	SHORT packetTable[0x100];
	struct Buffer logMessage;
};

enum UONetMessage
{
	UONET_SEND = 1,
	UONET_RECV = 2,
	UONET_READY = 3,
	UONET_NOTREADY = 4,
	UONET_CONNECT = 5,
	UONET_DISCONNECT = 6,
	KeyDown = 7,
	Mouse = 8,
	Activate = 9,
	Focus = 10,
	Close = 11,
	StatBar = 12,
	NotoHue = 13,
	DLL_Error = 14,
	DeathMsg = 15,
	OpenRPV = 18,
	UONET_SETGAMESIZE = 19,
	FindData = 20,
	SmartCPU = 21,
	Negotiate = 22,
	SetMapHWnd = 23,
	UONET_LOGMESSAGE = 24
};

enum INIT_ERROR 
{
	SUCCESS,
	NO_UOWND,
	NO_TID,
	NO_HOOK,
	NO_SHAREMEM,
	LIB_DISABLED,
	NO_PATCH,
	NO_MEMCOPY,
	INVALID_PARAMS,
	UNKNOWN
};

// DLL Exports
extern "C" VOID __declspec(dllexport) WaitForWindow(DWORD hProcess);
extern "C" INIT_ERROR __declspec(dllexport) InstallLibrary(HWND razorhwnd, int clientprocid, int flags);
extern "C" DWORD __declspec(dllexport) GetPacketLength(PUCHAR buffer, int bufferlength);
extern "C" DWORD __declspec(dllexport) GetClientPacketLength(char *buffer, int bufferlength);
extern "C" VOID __declspec(dllexport) SetServer(UINT serverIp, USHORT serverPort) ;
extern "C" HWND __declspec(dllexport) FindUOWindow();

// Misc Functions
VOID InstallApiHooks();
VOID CreateCommunicationMutex();
BOOL GetPacketTable();
VOID SendOutgoingBuffer();
LRESULT CALLBACK CallWndHook(int code,WPARAM wParam,LPARAM lParam);
LRESULT CALLBACK GetMessageHook(int code,WPARAM wParam,LPARAM lParam);
VOID UpdateTitleBar(HWND hwnd);

// Globals
extern HWND clienthWnd;
extern HWND razorhWnd;
extern DWORD clientProcessId;
extern HANDLE mutex;
extern HANDLE fileMapping;
extern HANDLE consoleHandle;
extern BOOL mustDecompress;
extern BOOL mustCompress;
extern SOCKET serverSocket;
extern struct DataBuffer *dataBuffer;
extern struct uo_decompression decompress;

// Typedefs
typedef int (WINAPI *TRANSLATESETUP)();
typedef int (WINAPI *TRANSLATELOGIN)(char*, char*);
typedef int (WINAPI *TRANSLATEDO)(char*, char*, int*);
