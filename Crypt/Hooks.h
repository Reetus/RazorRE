#pragma once
#include "stdafx.h"

int HookFunc(char *dllName, char *funcName, void *newFunc, FARPROC *oldFunc);

typedef int (WINAPI *CONNECT)(SOCKET s, const struct sockaddr *name, int namelen);
typedef int (WINAPI *RECV)(SOCKET s, char *buf, int len, int flags);
typedef int (WINAPI *SEND)(SOCKET s, const char *buf, int len, int flags);
typedef int (WINAPI *CLOSESOCKET)(SOCKET s);
typedef int (WINAPI *SELECT)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timeval *timeout);
