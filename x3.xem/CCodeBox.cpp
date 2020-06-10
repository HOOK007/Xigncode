#include "stdafx.h"

#include "CCodeBox.hpp"
#include "xst.h"
#include "log.h"
#include "CXignCodeMain.hpp"
#include "xpl.h"

// sub_10021832
void ZCE_Scan2(XPL_WRITER **ppwWriter, CPacketOperator *packetList)
{
	struct ZCE_CTX
	{
		uint a; // +0x00
		uint b; // +0x04
		uint c; // +0x08
		uint d; // +0x0C
		uint f; // +0x10
		uint g; // +0x14
		uint h; // +0x18
		WCHAR wszData[1024];
	};

	XPL_WRITER *writer = *ppwWriter;
	ZCE_CTX ctx;
	ZCE_ID *pAdaptersHash;

	void(__stdcall * fnImported)(void *, int, ZCE_CTX *) = (void(__stdcall *)(void *, int, ZCE_CTX *))packetList->GetImportedF();
	if (fnImported)
	{
		pAdaptersHash = CXignCodeMain::GetInstance()->GetAdaptersHash();
		ctx.h = 0;
		swprintf_s(ctx.wszData, L"id ...%08x-%04x-%04x-%02x%02x%02x%02x%02x%02x%02x%02x:",
			pAdaptersHash->a, pAdaptersHash->b, pAdaptersHash->c, pAdaptersHash->d, pAdaptersHash->e,
			pAdaptersHash->f, pAdaptersHash->g, pAdaptersHash->h, pAdaptersHash->i, pAdaptersHash->j, pAdaptersHash->k);

		fnImported(writer->vfptr->GetRealBuffer(writer), writer->vfptr->GetRealSize(writer), &ctx);
	}
}

void Ordinal3(void(__stdcall * fnOrdinal3)(int, int, int))
{
	if (fnOrdinal3)
		fnOrdinal3(2, 0, 0);
}

// sub_10020AA4
BOOL CreateModuleLoader(CPacketOperator *packetList)
{
	MODULE_LOADER *pLoader;
	uint signature = packetList->GetSignature();

	if (signature == IMAGE_DOS_SIGNATURE)
	{
		if (pXstImport->CreateProvider(LOADER_DOS, &pLoader) >= 0)
		{
			// free provider in the class
			packetList->Load(pLoader);
			return TRUE;
		}
	}
	else if (signature == 0x786D6F4C)	// Lomx
	{
		if (pXstImport->CreateProvider(LOADER_LOMX, &pLoader) >= 0)
		{
			// free provider in the class
			packetList->Load(pLoader);
			return TRUE;
		}
	}
	return FALSE;
}

// sub_10059143
uint __stdcall InitPWriter(XPL_WRITER **dst, void *buf, uint size)
{
	int prop;
	CXignCodeMain::GetInstance()->GetDataFromProperty("{E6B6CBA2-FC19-47f4-9D1D-AA8588175786}", &prop, 4, 3);
	switch (prop)
	{
		case 1: return pPacketProvider->vfptr->InitWriter1(dst, buf, size);
		default: return pPacketProvider->vfptr->InitWriter2(dst, buf, size);
	}
}

// sub_100214A5
XPL_WRITER **InitWriter(XPL_WRITER **dst, void *buf, uint size)
{
	XPL_WRITER *pWriterLocal;
	DWORD dwErrCode;
	WCHAR szText[256];

	dwErrCode = InitPWriter(&pWriterLocal, buf, size);
	if ((dwErrCode & 0x80000000))
	{
		// dwErrCode < 0 in signed value
		pXstImport->HexToWideChar(szText, 256, (const ubyte *)buf, 50, false);
		Log("PacketError %08x %ls\n", dwErrCode, szText);
		SetLastError(dwErrCode);
		*dst = nullptr;
	}
	else
	{
		*dst = pWriterLocal;
	}
	return dst;
}

//
BOOL REUSABLE_BUFFER::Alloc(uint size)
{
	if (this->size < size)
	{
		this->Free();
		this->buf = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!this->buf)
		{
			this->requires = 0;
			this->size = 0;
			return FALSE;
		}
		this->size = size;
	}
	this->requires = size;
	return TRUE;
}

VOID REUSABLE_BUFFER::Free()
{
	if (this->buf)
	{
		VirtualFree(this->buf, 0, MEM_RELEASE);
		this->buf = 0;
		this->requires = 0;
		this->size = 0;
	}
}

// DATA
CPacketProcedure::CPacketProcedure()
{
	this->key = 0;
	this->buffer.buf = nullptr;
	this->buffer.requires = 0;
	this->buffer.size = 0;
	this->fnImported = NULL;
	this->pLoader = nullptr;
	this->hModule = NULL;
}

CPacketProcedure::~CPacketProcedure()
{
	this->buffer.Free();
}

BOOL CPacketProcedure::Read(XPL_READER *reader)
{
	this->bBufferLoaded = FALSE;

	if (reader->vfptr->GetIndex(reader) > reader->vfptr->GetSize(reader))
	{
		SetLastError(0xE0190220);
		return FALSE;
	}

	if (this->key != reader->vfptr->GetKey(reader))
	{
		int size = reader->vfptr->f24(reader);
		this->buffer.Alloc(size);
		this->value = 0;
		this->receivedPacket = 0;
		this->key = reader->vfptr->GetKey(reader);
	}

	if (reader->vfptr->GetIndex(reader) >= reader->vfptr->GetSize(reader))
	{
		if (reader->vfptr->GetIndex(reader) != reader->vfptr->GetSize(reader))
		{
			SetLastError(0xE0190221);
			return FALSE;
		}

		strcpy_s(this->szProcName, MAX_PATH, (const char *)reader->vfptr->GetDecryptedBuffer(reader));
	}
	else
	{
		if (reader->vfptr->GetR(reader) + reader->vfptr->GetO(reader) > this->buffer.requires)
		{
			Log("xclio:: PACKET INFO mi=%d, G=%08x I=%d S=%08x T=%d R=%d O=%d cd=%d\n",
				this->receivedPacket, reader->vfptr->GetKey(reader), reader->vfptr->GetIndex(reader),
				reader->vfptr->GetValue(reader), reader->vfptr->GetSize(reader), reader->vfptr->GetR(reader), reader->vfptr->GetO(reader), this->buffer.requires);

			SetLastError(0xE0190222);
			return FALSE;
		}

		memcpy((unsigned char *)this->buffer.buf + reader->vfptr->GetO(reader), reader->vfptr->GetDecryptedBuffer(reader), reader->vfptr->GetR(reader));

		Log("F i=%d G=%08x I=%d S=%08x T=%d C=%08x\n",
			this->receivedPacket, reader->vfptr->GetKey(reader), reader->vfptr->GetIndex(reader),
			reader->vfptr->GetValue(reader), reader->vfptr->GetSize(reader), pXstImport->get_hash((uint *)reader->vfptr->GetDecryptedBuffer(reader), reader->vfptr->GetR(reader)));
	}
	if (this->receivedPacket == reader->vfptr->GetSize(reader))
		this->bBufferLoaded = TRUE;

	this->value ^= reader->vfptr->GetValue(reader);

	this->receivedPacket++;

	return TRUE;
}
BOOL CPacketProcedure::Compare(XPL_READER *reader)
{
	return memcmp(
		(unsigned char *)this->buffer.buf + reader->vfptr->GetO(reader),
		reader->vfptr->GetDecryptedBuffer(reader),
		reader->vfptr->GetR(reader)) == 0;
}
BOOL CPacketProcedure::IsBufferReady()
{
	return this->key && this->bBufferLoaded;
}
BOOL CPacketProcedure::Load(MODULE_LOADER *pLoader)
{
	if (!pLoader)
		return FALSE;

	if (this->pLoader)
		this->Unload();

	if (pLoader->vfptr->XLoadLibrary(pLoader, &this->hModule, this->buffer.buf, this->buffer.requires) < 0 || !this->hModule)
		return FALSE;

	this->fnImported = pLoader->vfptr->XGetProcAddress(pLoader, this->hModule, this->szProcName);
	if (!fnImported)
	{
		pLoader->vfptr->XFreeLibrary(pLoader, this->hModule);
		this->hModule = NULL;
		return FALSE;
	}
	this->pLoader = pLoader;
	return TRUE;
}
BOOL CPacketProcedure::Unload()
{
	if (!this->hModule)
		return FALSE;

	this->pLoader->vfptr->XFreeLibrary(this->pLoader, this->hModule);
	this->fnImported = NULL;
	this->hModule = NULL;

	this->pLoader->vfptr->baseProvider.DecInstance(this->pLoader);

	return TRUE;
}
FARPROC CPacketProcedure::GetProcAddress(LPCSTR lpProcName)
{
	return this->pLoader->vfptr->XGetProcAddress(this->pLoader, this->hModule, lpProcName);
}
FARPROC CPacketProcedure::GetImportedF()
{
	return this->fnImported;
}
uint CPacketProcedure::GetValue()
{
	return this->value;
}
void CPacketProcedure::UpdateKey(uint key)
{
	this->key = key;
}
uint CPacketProcedure::GetKey()
{
	return this->key;
}
uint CPacketProcedure::GetSignature()
{
	if (!this->IsBufferReady())
		return 0;

	return *((uint *)this->buffer.buf);
}
HMODULE CPacketProcedure::GetXModuleHandle()
{
	return this->hModule;
}
uint * CPacketProcedure::GetBuffer()
{
	return (uint *)this->buffer.buf;
}
uint CPacketProcedure::GetBufferSize()
{
	return this->buffer.requires;
}
// DATA END

// LIST
CPacketOperator::CPacketOperator()
{
	this->m_nCurrentIndex = 0;
}

BOOL CPacketOperator::Read(XPL_READER *reader)
{
	CPacketProcedure *pPacketData;

	// match
	pPacketData = this->aPacketProc;
	for (int i = 0; i < 3; i++)
	{
		if (pPacketData->key == reader->vfptr->GetKey(reader))
			return pPacketData->Read(reader);

		pPacketData++;
	}

	// not used
	pPacketData = this->aPacketProc;
	for (int i = 0; i < 3; i++)
	{
		if (pPacketData->key == 0)
			return pPacketData->Read(reader);

		pPacketData++;
	}

	SetLastError(0xE0190223);

	return FALSE;
}
BOOL CPacketOperator::Compare(XPL_READER *reader)
{
	return this->aPacketProc[this->m_nCurrentIndex].Compare(reader);
}
BOOL CPacketOperator::IsBufferReady()
{
	CPacketProcedure *pPacketData = this->aPacketProc;

	for (int i = 0; i < 3; i++)
	{
		if (pPacketData->IsBufferReady())
		{
			this->m_nCurrentIndex = i;
			return TRUE;
		}

		pPacketData++;
	}

	return FALSE;
}
BOOL CPacketOperator::Load(MODULE_LOADER *pLoader)
{
	return this->aPacketProc[this->m_nCurrentIndex].Load(pLoader);
}
BOOL CPacketOperator::Unload()
{
	return this->aPacketProc[this->m_nCurrentIndex].Unload();
}
FARPROC CPacketOperator::GetProcAddress(LPCSTR lpProcName)
{
	return this->aPacketProc[this->m_nCurrentIndex].GetProcAddress(lpProcName);
}
FARPROC CPacketOperator::GetImportedF()
{
	return this->aPacketProc[this->m_nCurrentIndex].GetImportedF();
}
uint CPacketOperator::GetValue()
{
	return this->aPacketProc[this->m_nCurrentIndex].GetValue();
}
void CPacketOperator::UpdateKey(uint key)
{
	this->aPacketProc[this->m_nCurrentIndex].UpdateKey(key);
}
uint CPacketOperator::GetKey()
{
	return this->aPacketProc[this->m_nCurrentIndex].GetKey();
}
uint CPacketOperator::GetSignature()
{
	return this->aPacketProc[this->m_nCurrentIndex].GetSignature();
}
HMODULE CPacketOperator::GetXModuleHandle()
{
	return this->aPacketProc[this->m_nCurrentIndex].GetXModuleHandle();
}
uint * CPacketOperator::GetBuffer()
{
	return this->aPacketProc[this->m_nCurrentIndex].GetBuffer();
}
uint CPacketOperator::GetBufferSize()
{
	return this->aPacketProc[this->m_nCurrentIndex].GetBufferSize();
}
// LIST END

// CCodeBox
CCodeBox::CCodeBox()
{
	InitializeCriticalSection(&this->m_CriticalSection);
}

CCodeBox::~CCodeBox()
{
	DeleteCriticalSection(&this->m_CriticalSection);
}

uint CCodeBox::UpdateValue(uint key, uint value)
{
	auto it = this->m_mData.find(key);
	if (it == this->m_mData.end())
	{
		// key not found
		this->m_mData.insert(std::make_pair(key, value));
		return value;
	}

	// update value
	it->second ^= value;
	return it->second;
}

// sub_1002157E k
BOOL CCodeBox::HandleUnk(XPL_READER *reader, void *res, uint res_size)
{
	CPacketOperator *pPacketOperator;
	XPL_WRITER *writer;
	BOOL result = FALSE;

	pPacketOperator = &m_aPacket[2];
	EnterCriticalSection(&this->m_CriticalSection);

	InitWriter(&writer, res, res_size);
	if (!writer)
	{
		LeaveCriticalSection(&this->m_CriticalSection);
		return FALSE;
	}

	if (pPacketOperator->IsBufferReady())
	{
		Ordinal3((void(__stdcall *)(int, int, int))pPacketOperator->GetProcAddress((LPCSTR)3));
		pPacketOperator->Unload();
		pPacketOperator->UpdateKey(0);
	}
	if (pPacketOperator->Read(reader) && pPacketOperator->IsBufferReady())
	{
		if (CreateModuleLoader(pPacketOperator))
		{
			writer->vfptr->f0c(writer, 1);
			writer->vfptr->WriteValue(writer, pPacketOperator->GetValue());
			writer->vfptr->WriteKey(writer, pPacketOperator->GetKey());
			*writer->vfptr->GetRealBuffer(writer) = 0;
			result = TRUE;
		}
	}
	writer->vfptr->DecInstance(writer);
	LeaveCriticalSection(&m_CriticalSection);
	return result;
}

// sub_100216C0
BOOL CCodeBox::HandleNCB(XPL_READER *reader, void *res, uint res_size)
{
	XPL_WRITER	*writer;
	CPacketOperator	*packetList;
	BOOL		result = FALSE;

	packetList = &m_aPacket[1];

	EnterCriticalSection(&m_CriticalSection);

	InitWriter(&writer, res, res_size);
	if (!writer)
	{
		LeaveCriticalSection(&m_CriticalSection);
		return FALSE;
	}

	if (!packetList->Read(reader))
	{
		Log("xclio:: ncb fill error ge = %08x\n", GetLastError());
	}
	else if (packetList->IsBufferReady())
	{
		if (CreateModuleLoader(packetList))
		{
			void(__stdcall * fnImported)(void *, int) = (void(__stdcall *)(void *, int))packetList->GetImportedF();
			if (fnImported)
			{
				static auto callback = []() -> uint
				{
					return 0;
				};

				uint *v15 = writer->vfptr->GetRealBuffer(writer);
				v15[0] = 0;
				v15[1] = (uint)&callback;

				fnImported(writer->vfptr->GetRealBuffer(writer), writer->vfptr->GetRealSize(writer));
				packetList->Unload();
				writer->vfptr->f0c(writer, 1);
				writer->vfptr->WriteValue(writer, packetList->GetValue());
				writer->vfptr->WriteKey(writer, packetList->GetKey());
				packetList->UpdateKey(0);
				result = TRUE;
			}
		}
	}

	writer->vfptr->DecInstance(writer);
	LeaveCriticalSection(&m_CriticalSection);
	return result;
}

// sub_10021918
BOOL CCodeBox::HandleZCE(XPL_READER *reader, void *res, uint res_size)
{
	XPL_WRITER	*writer;
	CPacketOperator *packetList;
	BOOL		result = FALSE;
	INT			prop;

	packetList = &m_aPacket[0];
	EnterCriticalSection(&m_CriticalSection);

	InitWriter(&writer, res, res_size);
	if (!writer)
	{
		LeaveCriticalSection(&m_CriticalSection);
		return FALSE;
	}
	if (!packetList->IsBufferReady())
	{
		if (!packetList->Read(reader))
		{
			Log("xclio:: zce fill error ge = %08x\n", GetLastError());
		}
		else if (packetList->IsBufferReady())
		{
			Log("ZCE COMPLETE\n");
			if (!CreateModuleLoader(packetList))
			{
				Log("xclio:: zce load fail, GE=%08x\n", GetLastError());
			}
			else
			{
				writer->vfptr->f0c(writer, 1);
				writer->vfptr->WriteValue(writer, packetList->GetValue());
				writer->vfptr->WriteKey(writer, packetList->GetKey());
				CXignCodeMain::GetInstance()->GetDataFromProperty("{E6B6CBA2-FC19-47f4-9D1D-AA8588175786}", &prop, 4, 3);
				if (prop == 3)
				{
					ZCE_Scan2(&writer, packetList);	// zce.dll Scan2
				}
				else if (prop == 2)
				{
					*writer->vfptr->GetRealBuffer(writer) = 0;
				}

				result = TRUE;
			}
		}
	}
	else
	{
		// flash packet if flag does not contain 0x8000
		if (reader->vfptr->f38(reader) & 0x8000)
		{
			if (reader->vfptr->GetIndex(reader) != reader->vfptr->GetSize(reader))
			{
				// XOR VALUE
				this->UpdateValue(reader->vfptr->GetKey(reader), reader->vfptr->GetValue(reader));
			}
			else
			{
				writer->vfptr->WriteValue(writer, this->UpdateValue(reader->vfptr->GetKey(reader), reader->vfptr->GetValue(reader)));
				writer->vfptr->WriteKey(writer, reader->vfptr->GetKey(reader));
				writer->vfptr->f0c(writer, 1);

				// erase by key
				m_mData.erase(reader->vfptr->GetKey(reader));
				ZCE_Scan2(&writer, packetList);
				// if (writer)
				// writer->vfptr->DecInstance(writer);
				result = TRUE;
			}
		}
		else
		{
			writer->vfptr->WriteValue(writer, reader->vfptr->GetValue(reader));
			writer->vfptr->WriteKey(writer, reader->vfptr->GetKey(reader));
			writer->vfptr->f10(writer, 1);
			if (packetList->Compare(reader))
			{
				ZCE_Scan2(&writer, packetList);
			}
			else
			{
				Log("ZCE COMPLETE RESEND REPLY\n");
				packetList->Unload();
				packetList->UpdateKey(0);
				*writer->vfptr->GetRealBuffer(writer) = 0xFFFFFFFF;
			}
			// if (writer)
			// writer->vfptr->DecInstance(writer);
			result = TRUE;
		}
	}

	writer->vfptr->DecInstance(writer);
	LeaveCriticalSection(&m_CriticalSection);
	return result;
}

// sub_10021DFF
int CCodeBox::HandlePacket(XPL_READER *reader, void *res, uint res_size)
{
	WCHAR *pszErr, *pszTemp;
	WCHAR szErr[256];

	switch (reader->vfptr->GetType(reader))
	{
		case 1:
		{
			// ncb.dll (jfz.dll)
			return !this->HandleNCB(reader, res, res_size);
		}
		case 2:
		{
			// zce.dll
			return !this->HandleZCE(reader, res, res_size);
		}
		case 3:
		{
			// ?
			return !this->HandleUnk(reader, res, res_size);
		}
		case 4:
		{
			// Error Msg
			pszErr = (WCHAR *)reader->vfptr->GetDecryptedBuffer(reader);
			Log("xclio:: ProbeTerm %ls\n", pszErr);
			if (wcsncmp(pszErr, L"ZCE", 3) == 0)
			{
				// MM.CMOD SvrCodeDetected 
				// IF.CMOD SvrCodeDetected 

				// skip "ZCE "
				pszTemp = wcschr(pszErr + 4, ':');
				if (pszTemp)
				{
					// cut
					*pszTemp = '\0';
				}

				Log("CMOD SvrCodeDetected %ls\n", pszErr + 4);
			}
			else
			{
				if (!wcsncmp(pszErr, L"ERR", 3))
				{
					pszTemp = L"{65C78797-3868-4d84-8C58-E92880B2AAFA}";
				}
				else if (!wcsncmp(pszErr, L"TME", 3))
				{
					pszTemp = L"{320C0CDF-4F64-49ac-A33F-E708DED89149}";
				}
				else
				{
					pszTemp = L"{46E57FA1-2806-4702-B96B-EEF5C87D36C8}";
				}
			}
			return 1;
		}
		default:
		{
			memset(szErr, 0, sizeof(szErr));
			reader->vfptr->f34(reader, szErr, sizeof(szErr));
			Log("Packet Type Unknown %ls\n", szErr);
			Log("PacketError: undefined\n");
			return 2;
		}
	}
}
// CTX END