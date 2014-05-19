#include "stdafx.h"

extern HANDLE consoleHandle;

extern "C" void __declspec(dllexport) Log(char*data)
{
	WriteConsoleA(consoleHandle, data, strlen(data), NULL, NULL);
}

void LogPrintf(char *fmt, ...) 
{
	char buf[16384];
	va_list args;
	va_start(args, fmt);
	sprintf(buf, fmt, args);
	Log(buf);
}

extern "C" void __declspec(dllexport) LogPacket(char *msg, char *packet, int packetlen)
{
	char buffer[256];
	memset(buffer, 0, 256);

	int whole = packetlen / 16;
	int rem = packetlen % 16;
	int byteIndex = 0;
	int bufferpos = 0;

	sprintf(buffer, "\r\n%s, Length: %d\r\n", msg, packetlen);
	Log(buffer);

	Log( " 0  1  2  3  4  5  6  7   8  9  A  B  C  D  E  F\r\n" );
	Log( "-- -- -- -- -- -- -- --  -- -- -- -- -- -- -- --\r\n" );

	for (int i = 0; i < whole; ++i, byteIndex+=16)
	{

		bufferpos = 0;
		memset(buffer, 0, 256);

		for (int j = 0; j < 16; j++)
		{
			int c = *packet++;

			bufferpos+=sprintf(buffer+bufferpos, "%02X ", (unsigned char)c);

			if (j == 7)
				bufferpos+=sprintf(buffer+bufferpos, " ");
		}
		bufferpos+=sprintf(buffer+bufferpos, "\r\n");
		Log(buffer);
	}

	if ( rem != 0 )
	{
		bufferpos = 0;
		memset(buffer, 0, 256);

		for ( int j = 0; j < 16; ++j )
		{
			if ( j < rem )
			{
				int c = *packet++;
				bufferpos+=sprintf(buffer+bufferpos, "%02X ", (unsigned char)c);

				if (j == 7)
					bufferpos+=sprintf(buffer+bufferpos, " ");
			}	
		}
		bufferpos+=sprintf(buffer+bufferpos, "\r\n");
		Log(buffer);

	}
}
