#include "stdafx.h"
#include "Misc.h"
#include "Log.h"

HBITMAP DLLEXPORT CaptureScreen(BOOL isFullScreen, char* message)
{
	LogPrintfR("CaptureScreen()\r\n");
	RECT rect = {0};
	HDC hDc;
	int imageWidth, imageHeight;

	if (isFullScreen)
	{
		hDc = GetDC(NULL);
		imageWidth = GetDeviceCaps(hDc, HORZRES);
		imageHeight = GetDeviceCaps(hDc, VERTRES);
	} 
	else
	{
		hDc = GetWindowDC(clienthWnd);
		GetWindowRect(clienthWnd, &rect);
		imageWidth = rect.right - rect.left;
		imageHeight = rect.bottom - rect.top;
	}

	HDC hMemDc = CreateCompatibleDC(hDc);
	HBITMAP output = CreateCompatibleBitmap(hDc, imageWidth, imageHeight);
	SelectObject(hMemDc, output);

	BitBlt(hMemDc, 0, 0, imageWidth, imageHeight, hDc, 0, 0, SRCCOPY);

	if (strlen(message) > 0)
	{
		SelectObject(hMemDc, CreateFontA(-16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DRAFT_QUALITY, FIXED_PITCH, "Courier"));
		SetBkColor(hMemDc, RGB(0, 0, 0));
		SetTextColor(hMemDc, RGB(0xFF, 0xFF, 0xFF));
		SIZE size;
		GetTextExtentPoint32A(hMemDc, message, strlen(message), &size);
		rect.top = 0;
		rect.bottom = size.cy;
		rect.left = imageWidth - size.cx;
		rect.right = imageWidth;

		TextOutA(hMemDc, rect.left, rect.top, message, strlen(message));
	}

	ReleaseDC(clienthWnd, hDc);
	DeleteDC(hMemDc);

	return output;
}


BOOL GetPESectionAddress(char *sectionName, DWORD *sectionAddress, DWORD *sectionSize)
{
	unsigned char* thisModule = (unsigned char*)GetModuleHandleA(NULL);

	IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER*)thisModule;
	IMAGE_NT_HEADERS *inh = (IMAGE_NT_HEADERS*)((BYTE*)thisModule + idh->e_lfanew);
	IMAGE_SECTION_HEADER *ish = (IMAGE_SECTION_HEADER*)((BYTE*)thisModule + idh->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	for (int i = 0; i < inh->FileHeader.NumberOfSections;i++)
	{
		if (_stricmp((char*)ish->Name, sectionName) == 0) 
		{
			*sectionAddress = ish->VirtualAddress;
			LogPrintf("%x %x\r\n", *sectionAddress, ish->VirtualAddress);
			*sectionSize = ish->Misc.VirtualSize;
			return true;
		}
		ish = (IMAGE_SECTION_HEADER*)((BYTE*)ish + sizeof(IMAGE_SECTION_HEADER));
	}
	return false;
}