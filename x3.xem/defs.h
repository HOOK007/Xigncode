#pragma once

#define XIGNAPI __stdcall

typedef unsigned char ubyte;
typedef unsigned short ushort;
typedef unsigned int uint;

enum _XclioFid
{
	XclioFidSysEnterA = 0x0,
	XclioFidSysEnterW = 0x1,
	XclioFidSysExit = 0x2,
	XclioFidInit = 0x3,
	XclioFidCleanup = 0x4,
	XclioFidProbe = 0x5,
	XclioFidProbeEx = 0x6,
	XclioFidCreateCodeBox = 0x7,
	XclioFidCloseCodeBox = 0x8,
	XclioFidProbeCodeBox = 0x9,
	XclioFidProbeCodeBoxEx = 0xA,
	XclioFidEncrypt = 0xB,
	XclioFidDecrypt = 0xC,
	XclioFidRsaCreate = 0xD,
	XclioFidRsaClose = 0xE,
	XclioFidRsaSetPublicKey = 0xF,
	XclioFidRsaSetPrivateKey = 0x10,
	XclioFidRsaPublicEncrypt = 0x11,
	XclioFidRsaPublicDecrypt = 0x12,
	XclioFidRsaPrivateEncrypt = 0x13,
	XclioFidRsaPrivateDecrypt = 0x14,
	XclioFidCheck = 0x15,
	XclioFidRegisterCallback = 0x16,
	XclioFidRsaGenerateKey = 0x17,
	XclioFidRsaFreeBuffer = 0x18,
	XclioFidSetup = 0x19,
	XclioFidSendCommandVa = 0x1A,
};

typedef BOOL(XIGNAPI * XigncodeCallbackT)(unsigned int, unsigned int, void *, void *);
typedef void(XIGNAPI * ProbeCallbackT)(void *, const char *, char *, unsigned int, void *);

typedef BOOL(XIGNAPI * XxxSysEnterWT)(const wchar_t *, const wchar_t *, unsigned int);
typedef BOOL(XIGNAPI * XxxSysExitT)();
typedef BOOL(XIGNAPI * XxxInitT)();
typedef BOOL(XIGNAPI * XxxCleanupT)();
typedef BOOL(XIGNAPI * XxxProbeExT)(const char *, unsigned int, ProbeCallbackT, void *);
typedef void(XIGNAPI * XxxRegisterCallbackT)(XigncodeCallbackT, void *);
typedef BOOL(XIGNAPI * XxxSendCommandVaT)(unsigned int, char *);

typedef unsigned int(XIGNAPI * XxxQueryFunctionT)(void **, _XclioFid);