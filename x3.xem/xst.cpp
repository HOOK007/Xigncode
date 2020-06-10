#include "stdafx.h"

#include "xst.h"

HMODULE	hXst = NULL;
xst_exports *pXstImport	= nullptr;

// +0x29c
uint get_hash(uint *src, uint len)
{
	uint size = len >> 2;
	uint result = 0;

	for (uint i = 0; i < size; i++)
		result += src[i];

	return ~result;
}

// +0x2bc
uint HexToWideChar(wchar_t *dst, uint dsize, const unsigned char *src, uint ssize, bool large)
{
	const wchar_t *pszBaseText;
	uint dst_off, src_off;

	if (large)
		pszBaseText = L"0123456789ABCDEF";
	else
		pszBaseText = L"0123456789abcdef";

	dst_off = 0;

	for (src_off = 0; src_off < ssize; src_off++)
	{
		if (dst_off + 1 >= dsize)
			return 0xE0010003;

		dst[dst_off++] = pszBaseText[src[src_off] >> 4];
		dst[dst_off++] = pszBaseText[src[src_off] & 0xF];
	}
	dst[dst_off] = 0;

	return 0;
}