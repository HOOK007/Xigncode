#pragma once

typedef struct _PACKET_PROVIDER_VF
{
	ABSTRACT_XPROVIDER_VF baseProvider;
	uint(__stdcall * InitReader1)(XPL_READER **, const ubyte *buf, uint size);
	uint(__stdcall * InitWriter1)(XPL_WRITER **, void *buf, uint size);
	uint(__stdcall * InitReader2)(XPL_READER **, const ubyte *buf, uint size);
	uint(__stdcall * InitWriter2)(XPL_WRITER **, void *buf, uint size);
	uint(__stdcall * InitReader3)(XPL_READER **, const ubyte *buf, uint size);
} PACKET_PROVIDER_VF, *PPACKET_PROVIDER_VF, *LPPACKET_PROVIDER_VF;

typedef struct _PACKET_PROVIDER
{
	PACKET_PROVIDER_VF *vfptr;
	uint instances;			// gc
} PACKET_PROVIDER, *PPACKET_PROVIDER;

typedef PACKET_PROVIDER * (__stdcall * CreatePacketProviderT)();

extern HMODULE hXpl;
extern PACKET_PROVIDER *pPacketProvider;