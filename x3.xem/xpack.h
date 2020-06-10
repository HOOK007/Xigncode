#pragma once

typedef struct _PACKED_FILE_CTX
{
	void *buf;
	uint size;
} PACKED_FILE_CTX, *PPACKED_FILE_CTX, *LPPACKED_FILE_CTX;

extern BOOL GetXFileInfo(__in LPCWSTR lpPackedFileName, __in LPCSTR lpFileName, __out LPPACKED_FILE_CTX lpCTX);
extern BOOL LomxLoadLibrary(__in MODULE_LOADER *pLomxLoader, __in LPCWSTR lpPackedFileName, __in LPCSTR lpFileName, __out HMODULE *phModule);