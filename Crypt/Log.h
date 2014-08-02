#pragma once
void DLLEXPORT Log(char*data);
void DLLEXPORT LogPacket(char *msg, char *packet, int packetlen);
void LogPrintf(char *fmt, ...);
void LogPrintfR(char *fmt, ...);
