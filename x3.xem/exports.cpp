#include "stdafx.h"

#include "exports.hpp"
#include "CXignCodeMain.hpp"
#include "log.h"

BOOL XIGNAPI SysEnterA(const char *License, const char *Path, unsigned int Flags)
{
	return CXignCodeMain::GetInstance()->SysEnterA(License, Path, Flags);
}

BOOL XIGNAPI SysEnterW(const wchar_t *License, const wchar_t *Path, unsigned int Flags)
{
	return CXignCodeMain::GetInstance()->SysEnterW(License, Path, Flags);
}

BOOL XIGNAPI SysExit()
{
	return CXignCodeMain::GetInstance()->SysExit();
}

BOOL XIGNAPI Init()
{
	return CXignCodeMain::GetInstance()->Init();
}

BOOL XIGNAPI Cleanup()
{
	return CXignCodeMain::GetInstance()->Cleanup();
}

BOOL XIGNAPI Probe(const unsigned char *request, unsigned char *response, unsigned int req_size)
{
	return CXignCodeMain::GetInstance()->Probe(request, response, req_size);
}

BOOL XIGNAPI ProbeEx(const unsigned char *request, unsigned int req_size, ProbeCallbackT callback, void *context)
{
	return CXignCodeMain::GetInstance()->ProbeEx(request, req_size, callback, context);
}

void * XIGNAPI CreateCodeBox()
{
	return CXignCodeMain::GetInstance()->CreateCodeBox();
}

BOOL XIGNAPI CloseCodeBox(void *CodeBox)
{
	return CXignCodeMain::GetInstance()->CloseCodeBox(CodeBox);
}

BOOL XIGNAPI ProbeCodeBox(void *codebox, const unsigned char *request, void *response, unsigned int res_size)
{
	return CXignCodeMain::GetInstance()->ProbeCodeBox(codebox, request, response, res_size);
}

BOOL XIGNAPI ProbeCodeBoxEx(void *codebox, const unsigned char *request, unsigned int req_size, unsigned int res_size, ProbeCallbackT callback, void *context)
{
	return CXignCodeMain::GetInstance()->ProbeCodeBoxEx(codebox, request, req_size, res_size, callback, context);
}

VOID XIGNAPI RegisterCallback(XigncodeCallbackT Callback, void *Context)
{
	CXignCodeMain::GetInstance()->RegisterCallback(Callback, Context);
}

BOOL XIGNAPI SendCommandVa(unsigned int cid, va_list ap)
{
	return CXignCodeMain::GetInstance()->SendCommandVa(cid, ap);
}

unsigned int XIGNAPI QueryFunction(void** Address, _XclioFid Fid)
{
	switch (Fid)
	{
		case XclioFidSysEnterA:
			*Address = SysEnterA;
			break;

		case XclioFidSysEnterW:
			*Address = SysEnterW;
			break;

		case XclioFidSysExit:
			*Address = SysExit;
			break;

		case XclioFidInit:
			*Address = Init;
			break;

		case XclioFidCleanup:
			*Address = Cleanup;
			break;

		case XclioFidProbe:
			*Address = Probe;
			break;

		case XclioFidProbeEx:
			*Address = ProbeEx;
			break;

		case XclioFidCreateCodeBox:
			*Address = CreateCodeBox;
			break;

		case XclioFidCloseCodeBox:
			*Address = CloseCodeBox;
			break;

		case XclioFidProbeCodeBox:
			*Address = ProbeCodeBox;
			break;

		case XclioFidProbeCodeBoxEx:
			*Address = ProbeCodeBoxEx;
			break;

		case XclioFidRegisterCallback:
			*Address = RegisterCallback;
			break;

		case XclioFidSendCommandVa:
			*Address = SendCommandVa;
			break;

		default:
			Log("QueryFunction - Address: %08X, Fid: %08X\n", Address, Fid);
			return 0xE0010002;
	}
	return 0;
}