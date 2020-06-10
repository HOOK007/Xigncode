#pragma once

#include "TSingleton.hpp"
#include <list>

struct CProbeEx : public TSingleton<CProbeEx>
{
	friend class TSingleton<CProbeEx>;

	struct PROBE_CONSTRUCT
	{
		void *pCodeBox;
		BYTE *pRequest;
		UINT uSize;
		ProbeCallbackT fnCallback;
		void *pContext;
	};

	HANDLE m_hThread;
	DWORD m_dwThreadId;
	HANDLE m_hTermEvent, m_hProcEvent;
	CRITICAL_SECTION m_csConstruct;
	std::list<PROBE_CONSTRUCT> m_lConstruct;

private:
	CProbeEx();

public:
	~CProbeEx();

	LONG AddConstruct(void *pCodeBox, const BYTE *pRequest, UINT uReqSize, UINT uResSize, ProbeCallbackT fnCallback, void *pContext);
	void Procedure(PROBE_CONSTRUCT *pConstruct);
	BOOL OnProcEvent();
	DWORD ProcThread();
};