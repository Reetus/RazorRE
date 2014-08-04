#pragma once

BOOL FindSignatureOffset(PUCHAR signature, int siglength, PUCHAR buffer, int buflen, DWORD *offset);
BOOL FindSignatureAddress(PUCHAR signature, PUCHAR buffer, int sigsize, int bufsize, DWORD *address);
BOOL FindSignatureAddressWildcard(PUCHAR signature, int sigsize, PUCHAR buffer, int bufsize, UCHAR wildcard, int *offset);
