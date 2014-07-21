#include "stdafx.h"

BOOL FindSignatureOffset(char *signature, int siglength, char *buffer, int buflen, int *offset)
{
	char *base = buffer;
	bool found = false;

	int size = buflen;
	for (int x = 0; x < size; x++)
	{
		char *ptr = base++;
		if (memcmp(ptr, signature, siglength) == 0)
		{
			found = true;
			*offset = (int)((char*)ptr-(char*)buffer);
			break;
		}
	}
	return found;
}

//BOOL FindMoo(char *signature, int sigsize, char *buffer, int bufsize, int *offset)
//{
//	for (int x = 0; x < (bufsize - sigsize);x++)
//	{
//		char *ptr = (char*)((BYTE*)buffer++);
//		for (int i = 0; i < sigsize; i++)
//		{
//			if (signature[i] != 0xCC && (BYTE)signature[i] != (BYTE)ptr)
//				break;
//			if (i == sigsize - 1)
//				return true;
//		}
//	}
//	return false;
//}

BOOL FindSignatureAddress(char *signature, char *buffer, int sigsize, int bufsize, int *address)
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
