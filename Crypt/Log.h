#pragma once
extern "C" void __declspec(dllexport) Log(char*data);
extern "C" void __declspec(dllexport) LogPacket(char *msg, char *packet, int packetlen);
void LogPrintf(char *fmt, ...);
