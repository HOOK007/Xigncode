#include "stdafx.h"

#include "CProbeEx.hpp"
#include "CXignCodeMain.hpp"
#include "log.h"

DWORD WINAPI ThreadProc(__in LPVOID lpvParameter)
{
	return reinterpret_cast<CProbeEx*>(lpvParameter)->ProcThread();
}

CProbeEx::CProbeEx()
{
	this->m_hTermEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!this->m_hTermEvent)
	{
		throw GetLastError();
	}

	// CreateThread as suspended
	this->m_hThread = CreateThread(NULL, 0, ThreadProc, this, CREATE_SUSPENDED, &this->m_dwThreadId);
	if (this->m_hThread == NULL)
	{
		CloseHandle(this->m_hTermEvent);
		throw GetLastError();
	}

	InitializeCriticalSection(&this->m_csConstruct);

	this->m_hProcEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!this->m_hProcEvent)
	{
		throw GetLastError();
	}

	ResumeThread(this->m_hThread);
}

CProbeEx::~CProbeEx()
{
	Log("xclio:: probe term\n");

	if (this->m_hTermEvent != NULL)
	{
		CloseHandle(this->m_hTermEvent);
		this->m_hTermEvent = NULL;
	}

	if (this->m_hProcEvent != NULL)
	{
		CloseHandle(this->m_hProcEvent);
		this->m_hProcEvent = NULL;
	}

	if (WaitForSingleObject(this->m_hThread, 10000) == WAIT_TIMEOUT)
	{
		// KILL IT
		TerminateThread(this->m_hThread, 0);
	}

	DeleteCriticalSection(&this->m_csConstruct);
}

LONG CProbeEx::AddConstruct(void *pCodeBox, const BYTE *pRequest, UINT uReqSize, UINT uResSize, ProbeCallbackT fnCallback, void *pContext)
{
	PROBE_CONSTRUCT probeConstruct;
	void *pBuf;

	pBuf = malloc(uReqSize);
	if (!pBuf)
	{
		// メモリ不足?
		return 0xE0010003;
	}

	// リクエストをバッファにコピー
	memcpy(pBuf, pRequest, uReqSize);

	probeConstruct.pCodeBox = pCodeBox;
	probeConstruct.pRequest = (BYTE *)pBuf;
	probeConstruct.uSize = uResSize;
	probeConstruct.fnCallback = fnCallback;
	probeConstruct.pContext = pContext;

	// リストに追加、別スレッドで処理される。
	EnterCriticalSection(&this->m_csConstruct);

	this->m_lConstruct.push_back(probeConstruct);

	LeaveCriticalSection(&this->m_csConstruct);

	// シグナル状態に設定
	SetEvent(this->m_hProcEvent);

	return 0;
}

// sub_10029A58
void CProbeEx::Procedure(PROBE_CONSTRUCT *pConstruct)
{
	void *pResponse;
	DWORD dwLastError;

	pResponse = malloc(pConstruct->uSize);
	if (!pResponse)
	{
		// error 0xE0010003
		return;
	}

	if (CXignCodeMain::GetInstance()->ProbeCodeBox(pConstruct->pCodeBox, pConstruct->pRequest, pResponse, pConstruct->uSize))
	{
		if (this->m_lConstruct.size() == 0)
		{
			// Completed.
			pConstruct->fnCallback(pConstruct->pCodeBox, (const char *)pConstruct->pRequest, (char *)pResponse, pConstruct->uSize, pConstruct->pContext);
		}
	}
	else
	{
		dwLastError = GetLastError();
		if (dwLastError != 0xE0190305)
		{
			// PROBE_EX_ERROR %08x
			Log("PROBE_EX_ERROR %08x\n", dwLastError);
		}
	}

	free(pResponse);
	free(pConstruct->pRequest);
}

BOOL CProbeEx::OnProcEvent()
{
	PROBE_CONSTRUCT probeConstruct;

	EnterCriticalSection(&this->m_csConstruct);

	if (this->m_lConstruct.size() == 0)
	{
		LeaveCriticalSection(&this->m_csConstruct);
		return FALSE;
	}

	// リストから1つ取り出す
	probeConstruct = this->m_lConstruct.back();
	this->m_lConstruct.pop_back();

	LeaveCriticalSection(&this->m_csConstruct);

	this->Procedure(&probeConstruct);

	return TRUE;
}

DWORD CProbeEx::ProcThread()
{
	HANDLE aHandle[2];
	DWORD dwResult;

	aHandle[0] = this->m_hTermEvent;
	aHandle[1] = this->m_hProcEvent;

	for (;;)
	{
		dwResult = WaitForMultipleObjects(2, aHandle, FALSE, 1000);
		if (dwResult == WAIT_OBJECT_0 + 0)
		{
			// Terminate
			break;
		}
		else if (dwResult == WAIT_OBJECT_0 + 1)
		{
			// Procedure
			while (this->OnProcEvent());
		}
	}

	return 0;
}