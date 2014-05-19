#include <stdio.h>
#include "Hooks.h"

#define SHARED_BUFF_SIZE = 524288;

struct Buffer 
{
	int Length;
	int Start;
	char Buff0[524288];
};

struct DataBuffer
{
	struct Buffer inRecv; // 524296 0x80008
	struct Buffer outRecv; //1048592 0x100010 
	struct Buffer inSend; //1572888 0x180018
	struct Buffer outSend; //2097184 0x200020
	char titleBar[128];
	BOOL allowDisconn;
	char clientDataPath[136];
	int serverIp;
	u_short serverPort;
	char clientVersion[128];
	int X;
	int Y;
	int Z;
	unsigned long features;
	char deathMsg[16];
	int totalIn;
	int totalOut;
};

enum UONetMessage
{
	UONET_SEND = 1,
	UONET_RECV = 2,
	Ready = 3,
	NotReady = 4,
	Connect = 5,
	Disconnect = 6,
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
	SetGameSize = 19,
	FindData = 20,
	SmartCPU = 21,
	Negotiate = 22,
	SetMapHWnd = 23,
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

HMODULE thishModule;

extern "C" void __declspec(dllexport) Log(char*data);
extern "C" void __declspec(dllexport) LogPacket(char *msg, char *packet, int packetlen);
void LogPrintf(char *fmt, ...);

extern "C" void __declspec(dllexport) WaitForWindow(DWORD hProcess);
extern "C" INIT_ERROR __declspec(dllexport) InstallLibrary(HWND razorhwnd, int clientprocid, int flags);
extern "C" int __declspec(dllexport) GetPacketLength(char *buffer, int bufferlength);
extern "C" int __declspec(dllexport) GetClientPacketLength(char *buffer, int bufferlength);
extern "C" void __declspec(dllexport) SetServer(UINT serverIp, USHORT serverPort) ;
void InstallApiHooks();
void CreateCommunicationMutex();
LRESULT CALLBACK CallWndHook(int code,WPARAM wParam,LPARAM lParam);
LRESULT CALLBACK GetMessageHook(int code,WPARAM wParam,LPARAM lParam);

int WINAPI newRecv(SOCKET s, char *buf, int len, int flags);
BOOL WINAPI ourRecv(SOCKET s, char *buf, int len, int flags);

SEND oldSend;
SELECT oldSelect;
CLOSESOCKET oldClosesocket;
CONNECT oldConnect;
RECV oldRecv;

typedef int (WINAPI *TRANSLATESETUP)();
typedef int (WINAPI *TRANSLATELOGIN)(char*, char*);
typedef int (WINAPI *TRANSLATEDO)(char*, char*, int*);