#pragma once

BOOL FindSignatureOffset(char *signature, int siglength, char *buffer, int buflen, int *offset);
BOOL FindSignatureAddress(char *signature, char *buffer, int sigsize, int bufsize, int *address);