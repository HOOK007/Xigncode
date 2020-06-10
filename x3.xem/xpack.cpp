#include "stdafx.h"

#include "xst.h"
#include "xpack.h"

BOOL GetXFileInfo(__in LPCWSTR lpPackedFileName, __in LPCSTR lpFileName, __out LPPACKED_FILE_CTX lpCTX)
{
	XPACK_PROVIDER *pXpackProvider;
	uint size;
	void *buf;
	BOOL result;

	if (!lpCTX)
		return FALSE;

	result = FALSE;

	if (pXstImport->CreateProvider(LOADER_XMAG, &pXpackProvider, lpPackedFileName, 0) >= 0)
	{
		if (pXpackProvider->vfptr->GetSize(pXpackProvider, lpFileName, &size) >= 0)
		{
			buf = malloc(size);
			if (buf)
			{
				if (pXpackProvider->vfptr->GetPackedBuffer(pXpackProvider, lpFileName, buf, size) >= 0)
				{
					lpCTX->buf = buf;
					lpCTX->size = size;
					result = TRUE;
				}
				else
				{
					free(buf);
				}
			}
		}

		// dec
		pXpackProvider->vfptr->baseProvider.DecInstance(pXpackProvider);
	}

	return result;
}

BOOL LomxLoadLibrary(__in MODULE_LOADER *pLomxLoader, __in LPCWSTR lpPackedFileName, __in LPCSTR lpFileName, __out HMODULE *phModule)
{
	PACKED_FILE_CTX ctx;
	BOOL result;

	if (!phModule)
		return FALSE;

	if (!GetXFileInfo(lpPackedFileName, lpFileName, &ctx))
	{
		*phModule = NULL;
		return FALSE;
	}

	// LoadLibrary
	result = pLomxLoader->vfptr->XLoadLibrary(pLomxLoader, phModule, ctx.buf, ctx.size) >= 0;

	// Free buf
	free(ctx.buf);

	return result;
}