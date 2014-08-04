#include "stdafx.h"
#include "Log.h"

BOOL FindSignatureOffset(PUCHAR signature, int siglength, PUCHAR buffer, int buflen, DWORD *offset)
{
	unsigned char *base = buffer;
	bool found = false;

	int size = buflen;
	for (int x = 0; x < size; x++)
	{
		unsigned char *ptr = base++;
		if (memcmp(ptr, signature, siglength) == 0)
		{
			found = true;
			*offset = (int)((char*)ptr-(char*)buffer);
			break;
		}
	}
	return found;
}

BOOL FindSignatureAddressWildcard(PUCHAR signature, int sigsize, PUCHAR buffer, int bufsize, UCHAR wildcard, int *offset)
{
	unsigned char *ptr;
	for (ptr = buffer; ptr < (buffer+bufsize);ptr++) 
	{
		for (int i = 0; i < (sigsize+1); i++)
		{
			if ((signature[i] != wildcard) && signature[i] != ptr[i])
				break;
			if (i == sigsize) {
				*offset = (int)ptr;
				return true;	
			}
		}
	}
	return false;
}

BOOL FindSignatureAddress(PUCHAR signature, PUCHAR buffer, int sigsize, int bufsize, DWORD *address)
{
	BOOL found = false;


	for (int x = 0; x < (bufsize - sigsize);x++)
	{
		char *ptr = (char*)((BYTE*)buffer++);
		if (memcmp(ptr, signature, sigsize) == 0)
		{
			found = true;
			*address = (int)ptr;
			break;
		}
	}
	return found;
}
