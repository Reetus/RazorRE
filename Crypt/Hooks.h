#pragma once
#include "stdafx.h"

int HookFunc(char *dllName, char *funcName, void *newFunc, FARPROC *oldFunc);
VOID InstallApiHooks();
DWORD WINAPI newClosesocket(SOCKET s);
DWORD WINAPI newConnect(SOCKET s, const struct sockaddr *name, int namelen);
DWORD WINAPI newRecv(SOCKET s, char *buf, int buflen, int flags);
DWORD WINAPI newSend(SOCKET s, const char *buf, int len, int flags);
DWORD WINAPI newSelect(int nfds, PFD_SET readfds, PFD_SET writefds, PFD_SET exceptfds, const struct timeval *timeout);

typedef int (WINAPI *CONNECT)(SOCKET s, const struct sockaddr *name, int namelen);
typedef int (WINAPI *RECV)(SOCKET s, char *buf, int len, int flags);
typedef int (WINAPI *SEND)(SOCKET s, const char *buf, int len, int flags);
typedef int (WINAPI *CLOSESOCKET)(SOCKET s);
typedef int (WINAPI *SELECT)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timeval *timeout);

extern SEND oldSend;
extern SELECT oldSelect;
extern CLOSESOCKET oldClosesocket;
extern CONNECT oldConnect;
extern RECV oldRecv;
