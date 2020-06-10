#include "stdafx.h"

#include "CXignCodeMain.hpp"
#include "CCodeBox.hpp"
#include "log.h"
#include "xpack.h"
#include "xpl.h"
#include "xst.h"
#include "CProbeEx.hpp"

#include <shellapi.h>
#include <WinInet.h>
#include <WinSock2.h>
#pragma comment(lib, "WinInet.lib")
#pragma comment(lib, "WinSock2.lib")

//
DWORD dword_100B94B0, Destination;


// sub_100590AE
uint InitPReader(XPL_READER **reader, const ubyte *request, uint req_size)
{
	//
	int prop;
	CXignCodeMain::GetInstance()->GetDataFromProperty("{E6B6CBA2-FC19-47f4-9D1D-AA8588175786}", &prop, 4, 3);

	switch (prop)
	{
		case 1:		return pPacketProvider->vfptr->InitReader1(reader, request, req_size);
		case 2:		return pPacketProvider->vfptr->InitReader2(reader, request, req_size);
		default:	return pPacketProvider->vfptr->InitReader3(reader, request, req_size);
	}
}

// hooks
const char *__stdcall getLicense(void *)
{
	return CXignCodeMain::GetInstance()->GetLicenseA();
}

uint __stdcall getData(void *, char *, uint)
{
	// printf("spoofed\n");
	return 0;
}

uint __stdcall getVersion(void *)
{
	return 40000000 + CXignCodeMain::GetInstance()->GetRevision();
}

int __stdcall GetXProp__Hook(void *p, uint id, void **dst)
{
	typedef struct
	{
		Padding(0x48);
		const char *(__stdcall *getLicense)(void *);	// +0x48
		Padding(0x24);
		uint(__stdcall * getData)(void *, char *, uint);	// +0x70
		Padding(0x08);
		uint(__stdcall * getVersion)(void *);	// +0x7C
	} FAKE_VF;

	static FAKE_VF fake = { { 0 }, getLicense, { 0 }, getData, { 0 }, getVersion }; // vf
	static FAKE_VF *pfake = &fake; // vfptr

	if (id == 0x71235ABE || id == 0x71235ABF) // abe
	{
		*dst = &pfake;
		return 0;
	}

	return -1;
	// return p->vfptr->GetXProp(p, id, dst);
}

//
rsa_ctx **RsaPublicDecrypt(rsa_ctx **rsa, void *src, uint ssize, void *key, uint keySize, void **dst, uint *dsize)
{
	int err;

	err = pXstImport->RsaCreate(rsa);
	if (err < 0)
	{
		throw err;
	}
	err = pXstImport->RsaSetPublicKey(*rsa, key, keySize);
	if (err < 0)
	{
		pXstImport->RsaClose(*rsa);
		throw err;
	}
	err = pXstImport->RsaPublicDecrypt(*rsa, src, ssize, dst, dsize);
	if (err < 0)
	{
		pXstImport->RsaClose(*rsa);
		throw err;
	}
	return rsa;
}

// CRefCounter
CRefCounter::CRefCounter()
{
	CXignCodeMain::GetInstance()->IncRefExports();
}

CRefCounter::~CRefCounter()
{
	CXignCodeMain::GetInstance()->DecRefExports();
}

// CXignCodeMain
CXignCodeMain::CXignCodeMain()
{
	this->m_nRefInstance = 0;
	this->m_nRefExports = 0;
	this->m_pLoader = NULL;
	InitializeCriticalSection(&this->m_cs);
	InitializeCriticalSection(&this->m_csCodeBox);
}

CXignCodeMain::~CXignCodeMain()
{
	DeleteCriticalSection(&this->m_cs);
	DeleteCriticalSection(&this->m_csCodeBox);
}

BOOL CXignCodeMain::SysEnterA(LPCSTR szLicense, LPCSTR szPath, UINT uFlags)
{
	WCHAR szBufLicense[MAX_PATH], szBufPath[MAX_PATH];
	WCHAR *pwszLicense = NULL, *pwszPath = NULL;

	if (szLicense)
	{
		MultiByteToWideChar(CP_ACP, 0, szLicense, -1, szBufLicense, MAX_PATH);
		pwszLicense = szBufLicense;
	}
	if (szPath)
	{
		MultiByteToWideChar(CP_ACP, 0, szPath, -1, szBufPath, MAX_PATH);
		pwszPath = szBufPath;
	}
	return this->SysEnterW(pwszLicense, pwszPath, uFlags);
}

BOOL CXignCodeMain::SysEnterW(LPCWSTR szLicense, LPCWSTR szPath, UINT uFlags)
{
	if (!this->Initialize(szLicense, szPath, uFlags))
		return FALSE;
	return this->Init();
}

BOOL CXignCodeMain::SysExit()
{
	this->Cleanup();
	return this->Finalize();
}

BOOL CXignCodeMain::Init()
{
	CRefCounter refCounter;
	if (!this->IsInitialized())
	{
		SetLastError(0xE0190304);
		return FALSE;
	}
	return this->Reset();
}

BOOL CXignCodeMain::Cleanup()
{
	CRefCounter refCounter;
	if (!this->IsInitialized())
	{
		SetLastError(0xE0190304);
		return FALSE;
	}
	return this->Reset();
}

BOOL CXignCodeMain::Probe(const unsigned char *request, unsigned char *response, uint req_size)
{
	CRefCounter refCounter;
	XPL_READER *reader;
	WCHAR szText[256];
	int prop;
	BOOL result = FALSE;

	if (!CXignCodeMain::GetInstance()->IsInitialized())
	{
		// sysenter pls
		SetLastError(0xE0190304);
		return FALSE;
	}

	InterlockedExchange(&dword_100B94B0, 1);
	if (InterlockedCompareExchange(&Destination, 1, 1) == 1)
	{
		return TRUE;
	}

	EnterCriticalSection(&this->m_csCodeBox);

	if (!this->m_pCodeBox)
	{
		SetLastError(0xE0190304);
		LeaveCriticalSection(&this->m_csCodeBox);
		return FALSE;
	}

	// init xpl reader
	int error = InitPReader(&reader, request, req_size);
	if (error < 0)
	{
		// fail to init reader
		this->GetDataFromProperty("{E6B6CBA2-FC19-47f4-9D1D-AA8588175786}", &prop, 4, 3);
		pXstImport->HexToWideChar(szText, 256, request, 50, false);
		Log("xclio:: SC Packet Parsing Error S=>%08x P=>%d SZ=>%d H=>%s\n", error, prop, req_size, szText);
		SetLastError(error);
	}
	else
	{
		error = this->m_pCodeBox->HandlePacket(reader, response, req_size);
		reader->vfptr->DecInstance(reader);
		if (error == 2)
		{
			SetLastError(0xE0190302);
		}
		else if (error != 0)
		{
			SetLastError(0xE0190305);
		}
		else
		{
			// no error
			result = TRUE;
		}
	}

	LeaveCriticalSection(&this->m_csCodeBox);

	return result;
}

BOOL CXignCodeMain::ProbeEx(const unsigned char *pRequest, UINT uReplySize, ProbeCallbackT fnCallback, void *pContext)
{
	CRefCounter refCounter;
	if (!this->IsInitialized())
	{
		SetLastError(0xE0190304);
		return FALSE;
	}

	// sub_10024ADE();
	InterlockedExchange(&dword_100B94B0, 1);
	if (InterlockedCompareExchange(&Destination, 1, 1) == 1)
		return TRUE;

	// dword_100D8DCC codebox
	int error = CProbeEx::GetInstance()->AddConstruct(this->m_pCodeBox, pRequest, uReplySize, uReplySize, fnCallback, pContext);
	if (error < 0)
	{
		SetLastError(error);
		return FALSE;
	}

	return TRUE;
}

void *CXignCodeMain::CreateCodeBox()
{
	CCodeBox *pCodeBox;
	CRefCounter refCounter;
	if (!this->IsInitialized())
	{
		SetLastError(0xE0190304);
		return NULL;
	}

	EnterCriticalSection(&this->m_csCodeBox);

	pCodeBox = new CCodeBox;
	if (pCodeBox)
	{
		this->m_lCodeBox.push_back(pCodeBox);
		LeaveCriticalSection(&this->m_csCodeBox);
		return pCodeBox;
	}

	LeaveCriticalSection(&this->m_csCodeBox);

	return pCodeBox;
}

BOOL CXignCodeMain::CloseCodeBox(void *CodeBox)
{
	BOOL result;
	CRefCounter refCounter;
	if (CXignCodeMain::GetInstance()->IsInitialized())
	{
		EnterCriticalSection(&this->m_csCodeBox);
		this->m_lCodeBox.remove((CCodeBox *)CodeBox);
		LeaveCriticalSection(&this->m_csCodeBox);
		result = TRUE;
	}
	else
	{
		SetLastError(0xE0190304);
		result = FALSE;
	}
	return result;
}

BOOL CXignCodeMain::ProbeCodeBox(void *CodeBox, const unsigned char *request, void *response, uint size)
{
	XPL_READER	*reader;
	WCHAR		szHex[256];
	CRefCounter refCounter;
	int prop;

	if (!CXignCodeMain::GetInstance()->IsInitialized())
	{
		SetLastError(0xE0190304);
		return FALSE;
	}

	InterlockedExchange(&dword_100B94B0, 1);
	if (InterlockedCompareExchange(&Destination, 1, 1) == 1)
	{
		Log("xclio:: ResetPending Skip\n");
		return FALSE;
	}

	auto it = std::find(this->m_lCodeBox.begin(), this->m_lCodeBox.end(), CodeBox);
	if (it == this->m_lCodeBox.end())
	{
		SetLastError(0xE0190301);
		return FALSE;
	}

	if (strcmp((const char *)request, "ECHOTEST") == 0)
	{
		Log("xclio:: ProbeECHO Complete - 1 %d\n", size);
		memcpy(response, request, size);
		return TRUE;
	}

	// init xpl reader
	int error = InitPReader(&reader, request, size);
	if (error < 0)
	{
		CXignCodeMain::GetInstance()->GetDataFromProperty("{E6B6CBA2-FC19-47f4-9D1D-AA8588175786}", &prop, 4, 3);
		pXstImport->HexToWideChar(szHex, 256, request, 50, false);
		Log("xclio:: SC Packet Parsing Error S=>%08x P=>%d SZ=>%d H=>%s\n", error, prop, size, szHex);
		SetLastError(error);
		return FALSE;
	}

	error = reinterpret_cast<CCodeBox*>(CodeBox)->HandlePacket(reader, response, size);
	reader->vfptr->DecInstance(reader);

	if (error == 2)
	{
		SetLastError(0xE0190302);
	}
	else if (error != 0)
	{
		SetLastError(0xE0190305);
	}
	else
	{
		// no error
		return TRUE;
	}

	return FALSE;
}

BOOL CXignCodeMain::ProbeCodeBoxEx(void *CodeBox, const unsigned char *request, uint req_size, uint res_size, ProbeCallbackT Callback, void *Context)
{
	LONG nError;
	CRefCounter refCounter;

	if (!CXignCodeMain::GetInstance()->IsInitialized())
	{
		SetLastError(0xE0190304);
		return FALSE;
	}

	InterlockedExchange(&dword_100B94B0, 1);
	if (InterlockedCompareExchange(&Destination, 1, 1) == 1)
		return TRUE;

	auto it = std::find(this->m_lCodeBox.begin(), this->m_lCodeBox.end(), CodeBox);
	if (it == this->m_lCodeBox.end())
	{
		SetLastError(0xE0190301);
		return FALSE;
	}

	nError = CProbeEx::GetInstance()->AddConstruct(CodeBox, request, req_size, res_size, Callback, Context);
	if (nError < 0)
	{
		SetLastError(nError);
		return FALSE;
	}

	return TRUE;
}

VOID CXignCodeMain::RegisterCallback(XigncodeCallbackT Callback, void *Context)
{
	InterlockedExchange(reinterpret_cast<DWORD*>(&m_fnCallback), reinterpret_cast<DWORD>(Callback));
	InterlockedExchange(reinterpret_cast<DWORD*>(&m_lpCallbackContext), reinterpret_cast<DWORD>(Context));
}

// sub_10022B22
BOOL QueryFastFunction(uint fid, void **dst)
{
	switch (fid)
	{
		case 2000:
			*dst = LoadLibraryA;
			break;
		case 2100:
			*dst = LoadLibraryW;
			break;
		case 2400:
			*dst = FreeLibrary;
			break;
		case 2500:
			*dst = GetProcAddress;
			break;
		case 3100:
			*dst = malloc;
			break;
		case 3200:
			*dst = free;
			break;
		case 3300:
			*dst = fopen_s;
			break;
		case 3400:
			*dst = fclose;
			break;
		case 3500:
			*dst = fread;
			break;
		case 3600:
			*dst = fwrite;
			break;
		case 3700:
			*dst = fseek;
			break;
		case 3800:
			*dst = ftell;
			break;
		case 3810:
			*dst = CreateFileA;
			break;
		case 3820:
			*dst = CreateFileW;
			break;
		case 3830:
			*dst = ReadFile;
			break;
		case 3840:
			*dst = WriteFile;
			break;
		case 3850:
			*dst = SetFilePointer;
			break;
		case 3860:
			*dst = vfscanf;
			break;
		case 3870:
			*dst = vfwscanf;
			break;
		case 3880:
			*dst = fopen_s;
			break;
		case 3890:
			*dst = _wfopen_s;
			break;
		case 3900:
			*dst = vfprintf;
			break;
		case 3910:
			*dst = vfwprintf;
			break;
		case 3920:
			*dst = ShellExecuteA;
			break;
		case 3930:
			*dst = ShellExecuteW;
			break;
		case 3940:
			*dst = ShellExecuteExA;
			break;
		case 3950:
			*dst = ShellExecuteExW;
			break;
		case 3960:
			*dst = GetTickCount;
			break;
		//case 3970:
			//*dst = rand; // not sure
			//break;
		default:
			SetLastError(0xE0010002);
			return FALSE;
	}
	return TRUE;
}

BOOL CXignCodeMain::SendCommandVa(uint cid, va_list ap)
{
	CRefCounter refCounter;
	if (!this->IsInitialized())
	{
		SetLastError(0xE0190304);
		return FALSE;
	}

	switch (cid)
	{
		case 100:
		{
			// MyUserInfoCallback(unsigned int iid, char *buffer, unsigned int size, void *context)
			uint callback = va_arg(ap, uint);
			uint context = va_arg(ap, uint);
			Log("xclio:: set user info callback A %08X, %08X\n", callback, context);
			break;
		}
		case 7100:
		{
			uint fid = va_arg(ap, uint);
			void **dst = va_arg(ap, void **);
			return QueryFastFunction(fid, dst);
		}
		default:
		{
			Log("SendCommandVa cid = %08X\n", cid);
			SetLastError(0xE0010002);
			return FALSE;
		}
	}

	return TRUE;
}

// sub
BOOL CXignCodeMain::IsInitialized()
{
	// 関数は、Destination の値と Comperand の値の原子比較を実行します。
	// Destination の値と Comperand の値が等しいときは、Destination で指定されるアドレスに Exchange の値を格納します。
	// 等しくないときは、何もしません。
	// 操作対象の初期値が返ります。
	return InterlockedCompareExchange(&this->m_nRefInstance, 0, 0) != 0;
}

BOOL CXignCodeMain::Initialize(LPCWSTR szLicense, LPCWSTR szPath, UINT uFlags)
{
	WSADATA wsaData;
	int nError;
	MEMORY_BASIC_INFORMATION mbi;
	DWORD flOldProtect;

	// 最初のみ初期化する。
	if (InterlockedIncrement(&this->m_nRefInstance) <= 1)
	{
		nError = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (nError != 0)
		{
			SetLastError(0xE0300000 | nError);
			return FALSE;
		}

		std::wstring xmag = std::wstring(szPath) + L"\\xmag.xem";	// contains everything including xmina files
		std::wstring xnina = std::wstring(szPath) + L"\\xnina.xem";	// contains xup.xem, xdna.xem, splash.xem, xst.xem
		std::wstring xst = std::wstring(szPath) + L"\\xst.xem.dll";	// extract xst.xem somehow... lel

		// setup xst
		hXst = LoadLibraryW(xst.c_str());
		if (!hXst)
		{
			Log("xst.xem.dll\n");
			return FALSE;
		}

		xst_exports *(__stdcall *fnGetExport)() = reinterpret_cast<xst_exports * (__stdcall *)()>(GetProcAddress(hXst, (LPCSTR)1));
		if (!fnGetExport)
		{
			Log("xst@1\n");
			return FALSE;
		}

		pXstImport = fnGetExport();
		if (!pXstImport)
		{
			Log("xst@1\n");
			return FALSE;
		}

		// for NCB ZCE
		if (pXstImport->CreateProvider(PROPERTIES, &pXstImport->pProperties) < 0)
		{
			Log("pProperties\n");
			return FALSE;
		}

		VirtualQuery(&pXstImport->pProperties->vfptr->GetXProp, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
		VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &flOldProtect);
		pXstImport->pProperties->vfptr->GetXProp = GetXProp__Hook;
		VirtualProtect(mbi.BaseAddress, mbi.RegionSize, flOldProtect, &flOldProtect);

		if (pXstImport->CreateProvider(LOADER_LOMX, &this->m_pLoader) < 0)
		{
			Log("SysEnterW InitProvider\n");
			return FALSE;
		}

		// maybe bad idea...
#ifdef xc_update
		HMODULE hXup;
		MODULE_CTX xdna_ctx, splash_ctx;
		typedef int(__stdcall * rva_1T)(const wchar_t *Path, void *xdna, uint xdna_size);
		typedef int(__stdcall * rva_12T)(const wchar_t *Path, void *xdna, uint xdna_size, void *splash, uint splash_size);

		if (!XmagLoadLibrary(pLomxLoader, xnina.c_str(), "xup.xem", &hXup))
		{
			Log("SysEnterW XmagLoadLibrary\n");
			return FALSE;
		}

		if (GetXmagFileInfo(xnina.c_str(), "xdna.xem", &xdna_ctx))
		{
			if (GetXmagFileInfo(xnina.c_str(), "splash.xem", &splash_ctx))
			{
				rva_1T update =
					(rva_1T)pLomxLoader->vfptr->XGetProcAddress(pLomxLoader, hXup, (LPCSTR)1); // only image
				if (update)
				{
					if (update(Path, xdna_ctx.packedBuf, xdna_ctx.size) < 0)
					{
						Log("update failed\n");
						// return FALSE;
					}
				}
				free(splash_ctx.packedBuf);
			}
			free(xdna_ctx.packedBuf);
		}
		pLomxLoader->vfptr->XFreeLibrary(pLomxLoader, hXup);
#endif
		// xpl.xem
		if (!LomxLoadLibrary(this->m_pLoader, xmag.c_str(), "xpl.xem", &hXpl))
		{
			Log("SysEnterW xpl.xem\n");
			return FALSE;
		}

		CreatePacketProviderT fnCreatePacketProvider = (CreatePacketProviderT)this->m_pLoader->vfptr->XGetProcAddress(this->m_pLoader, hXpl, "CreatePacketProvider");
		if (!fnCreatePacketProvider)
		{
			Log("SysEnterW fnCreatePacketProvider\n");
			return FALSE;
		}

		pPacketProvider = fnCreatePacketProvider();
		if (!pPacketProvider)
		{
			Log("SysEnterW CreatePacketProvider\n");
			return FALSE;
		}

		if (!this->LoadPropertiesFromFile(xnina.c_str()))
		{
			Log("Xdna_Init\n");
			return FALSE;
		}

		if (!this->GetInformation(xnina.c_str()))
		{
			Log("GrabInformation\n");
			return FALSE;
		}

		// sub_10019055
		// CProbeEx::getInstance(); // new

		Log("xclio:: WOW, XIGNCODE SYSTEM %d INITIALIZATION IS COMPLETE !!!\n", CXignCodeMain::GetInstance()->GetRevision());
	}

	return TRUE;
}

BOOL CXignCodeMain::Finalize()
{
	if (!this->IsInitialized())
	{
		SetLastError(0xE0190304);
		return FALSE;
	}

	Log("xclio:: ZCWAVE_SysExit !!!\n");

	// 参照カウントが0の時のみFinalize
	if (InterlockedDecrement(&this->m_nRefInstance) == 0)
	{
		Log("xclio:: api status check\n");
		for (int i = 0; i < 100; i++)
		{
			if (this->CanShutdown())
				break;

			Sleep(10);
		}

		Log("xclio:: shutdown ready\n");

		this->Shutdown();
	}
}

BOOL CXignCodeMain::Reset()
{
	InterlockedExchange(&Destination, 1);
	while (InterlockedExchange(&dword_100B94B0, 0) == 1)
		Sleep(300);

	InterlockedExchange(&Destination, 0);

	EnterCriticalSection(&this->m_csCodeBox);

	if (this->m_pCodeBox)
	{
		this->m_lCodeBox.remove(this->m_pCodeBox);
		delete this->m_pCodeBox;
		this->m_pCodeBox = NULL;
	}

	this->m_pCodeBox = new CCodeBox;
	if (this->m_pCodeBox)
		this->m_lCodeBox.push_back(this->m_pCodeBox);

	Log("xclio:: ZCWAVE_Init/Cleanup Reset Complete\n");

	LeaveCriticalSection(&this->m_csCodeBox);

	return TRUE;
}

void CXignCodeMain::Shutdown()
{
	this->m_pLoader->vfptr->XFreeLibrary(this->m_pLoader, hXpl);

	if (this->m_pLoader->vfptr->baseProvider.DecInstance(this->m_pLoader) == 0)
		this->m_pLoader = NULL;

	if (pPacketProvider)
		pPacketProvider->vfptr->baseProvider.DecInstance(pPacketProvider);

	this->ClearProperties();

	if (pXstImport->pProperties->vfptr->baseProvider.DecInstance(pXstImport->pProperties) == 0)
	{
		pXstImport->pProperties = nullptr;

		if (hXst)
			FreeLibrary(hXst);

		hXst = NULL;
		pXstImport = nullptr;
	}

	// sub_10026D2C(&dword_100C22B4, 0);
	{
		// v5 = *(v1 + 0xEC);
		// if (v5)
		// sub_10012EE1(v5, 1);

		//CProbeEx::Destroy();

	}

	// WSACleanup();
}

void CXignCodeMain::IncRefExports()
{
	InterlockedIncrement(&this->m_nRefExports);
}

void CXignCodeMain::DecRefExports()
{
	InterlockedDecrement(&this->m_nRefExports);
}

BOOL CXignCodeMain::CanShutdown()
{
	// 関数は、Destination の値と Comperand の値の原子比較を実行します。
	// Destination の値と Comperand の値が等しいときは、Destination で指定されるアドレスに Exchange の値を格納します。
	// 等しくないときは、何もしません。
	// 操作対象の初期値が返ります。
	return InterlockedCompareExchange(&this->m_nRefExports, 0, 0) != 0;
}

// info
LPCSTR CXignCodeMain::GetLicenseA() { return this->m_szLicense; }
LPWSTR CXignCodeMain::GetLicenseW() { return this->m_wszLicense; }
DWORD CXignCodeMain::GetRevision() { return this->m_uRevision; }
ZCE_ID *CXignCodeMain::GetAdaptersHash() { return &this->m_adaptersHash; }

// XDNA
BOOL CXignCodeMain::GetInformation(__in LPCWSTR lpFile)
{
	HINTERNET hInternet, hFile;
	DWORD dwNumberOfBytesRead;
	DWORD dwRevHash;
	BOOL bResult;
	WCHAR szProtocol[128];
	WCHAR szServer[128];
	WCHAR szRoot[128];
	WCHAR szVersion[128];
	WCHAR szUrl[1024];

	if (!this->GetDataFromProperty("UpdateProtocol", szProtocol, sizeof(szProtocol)))
	{
		lstrcpyW(szProtocol, L"http");
	}

	if (!this->GetDataFromProperty("UpdateServer", szServer, sizeof(szServer)))
	{
		Log("Xdna_getData UpdateServer\n");
		return FALSE;
	}

	if (!this->GetDataFromProperty("UpdateRoot", szRoot, sizeof(szRoot)))
	{
		Log("Xdna_getData UpdateRoot\n");
		return FALSE;
	}

	if (!this->GetDataFromProperty("UpdateVersion", szVersion, sizeof(szVersion)))
	{
		Log("Xdna_getData UpdateVersion\n");
		return FALSE;
	}

	if (!this->GetDataFromProperty("License", this->m_wszLicense, sizeof(this->m_wszLicense)))
	{
		Log("Xdna_getData License\n");
		return FALSE;
	}

	WideCharToMultiByte(CP_ACP, 0, this->m_wszLicense, -1, this->m_szLicense, 16, NULL, NULL);

	wsprintf(szUrl, L"%ls://%ls%ls/%ls%ls/%ls", szProtocol, szServer, szRoot, this->m_wszLicense, L"/List", szVersion);

	Log("Download Url : %ls\n", szUrl);

	bResult = FALSE;

	hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
	if (hInternet != NULL)
	{
		hFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE, NULL);
		if (hFile != NULL)
		{
			bResult = InternetReadFile(hFile, &dwRevHash, 4, &dwNumberOfBytesRead);
			InternetCloseHandle(hFile);

			if (bResult && dwNumberOfBytesRead == 4)
			{
				this->m_uRevision = dwRevHash ^ 0x19810118;
			}
		}
		InternetCloseHandle(hInternet);
	}

	memset(m_adaptersHash.buffer, 0, 16);

	return bResult;
}

BOOL CXignCodeMain::LoadPropertiesFromFile(__in LPCWSTR lpFile)
{
	MODULE_LOADER *pLoader;
	PACKED_FILE_CTX file;

	RSA_FILE_HEADER header;
	ubyte *spackedBuf, *rsaBuf;
	uint publicKeySize;
	rsa_ctx *rsa;
	ubyte *xdna, *pCurrent, *pEnd;
	uint xdna_size;
	BOOL result;

	// lock_guardを使うと、スコープの終わりでlock()変数が破棄されるのにともなって、自動的にロックも解除される
	std::lock_guard<std::mutex> lock(this->m_mtxProperty);

	if (pXstImport->CreateProvider(LOADER_LOMX, &pLoader) < 0)
	{
		return FALSE;
	}

	if (!GetXFileInfo(lpFile, "xdna.xem", &file))
	{
		pLoader->vfptr->baseProvider.DecInstance(pLoader);
		return FALSE;
	}

	result = FALSE;
	// RSA->
	memcpy(&header, file.buf, sizeof(RSA_FILE_HEADER));
	spackedBuf = (ubyte *)malloc(header.bufSize);
	if (spackedBuf)
	{
		publicKeySize = header.rsaKeyLen << 3;
		rsaBuf = (ubyte *)malloc(header.originSize);
		if (rsaBuf)
		{
			memcpy(spackedBuf, (unsigned char *)file.buf + sizeof(RSA_FILE_HEADER), header.bufSize);
			pXstImport->Unspack(rsaBuf, &header.originSize, spackedBuf, &header.bufSize, header.start, 5); // dst, dsize, src, ssize, data, dataSize

			// rsa_buf { rsa_public_key -> rsa_public_src }
			RsaPublicDecrypt(&rsa, rsaBuf + publicKeySize, header.originSize - publicKeySize, rsaBuf, publicKeySize, (void **)&xdna, &xdna_size);
			// <-RSA

			// read xdna.xem
			pCurrent = xdna;
			pEnd = xdna + xdna_size;

			while (pCurrent < pEnd)
			{
				XDNA_PROPERTY *lpProp = (XDNA_PROPERTY *)pCurrent;
				XignCode_Property xcProperty;
				xcProperty.nType = lpProp->type;
				xcProperty.nSize = lpProp->dataSize;
				xcProperty.pData = malloc(lpProp->dataSize);
				if (xcProperty.pData)
				{
					memcpy(xcProperty.pData, lpProp->buf + lpProp->keySize, xcProperty.nSize);
					this->m_mProperty[lpProp->szKey] = xcProperty;
				}

				pCurrent += lpProp->keySize + lpProp->dataSize + 6; // seek
			}
			result = TRUE;

			// RSA->
			// free
			if (xdna)
				pXstImport->RsaFreeBuffer(rsa, xdna);
			if (rsa)
				pXstImport->RsaClose(rsa);
			free(rsaBuf);
		}
		free(spackedBuf);
	}

	free(file.buf);
	// <-RSA

	pLoader->vfptr->baseProvider.DecInstance(pLoader);

	return result;
}

void CXignCodeMain::ClearProperties()
{
	std::lock_guard<std::mutex> lock(this->m_mtxProperty);
	this->m_mProperty.clear();
}

BOOL CXignCodeMain::GetDataFromProperty(__in LPCSTR lpKey, __out LPVOID lpDst, __in DWORD dwSize)
{
	if (!lpDst)
		return FALSE;

	if (!this->IsInitialized())
		return FALSE;

	std::lock_guard<std::mutex> lock(this->m_mtxProperty);
	auto it = this->m_mProperty.find(lpKey);
	if (it == this->m_mProperty.end())
		return FALSE;
	
	memcpy(lpDst, it->second.pData, it->second.nSize);
	return TRUE;
}

BOOL CXignCodeMain::GetDataFromProperty(__in LPCSTR lpKey, __out LPVOID lpDst, __in DWORD dwSize, __in DWORD dwDefaultKey)
{
	XignCode_Property xcProperty;
	BOOL bResult;

	if (!lpDst)
		return FALSE;

	if (!this->IsInitialized())
		return FALSE;

	std::lock_guard<std::mutex> lock(this->m_mtxProperty);

	bResult = FALSE;

	auto it = this->m_mProperty.find(lpKey);
	if (it != this->m_mProperty.end())
	{
		memcpy(lpDst, it->second.pData, it->second.nSize);
		bResult = TRUE;
	}
	else if (dwSize == 4)
	{
		*(DWORD*)lpDst = dwDefaultKey;
		xcProperty.nType = 0;
		xcProperty.nSize = 4;
		xcProperty.pData = malloc(4);
		if (xcProperty.pData)
		{
			memcpy(xcProperty.pData, &dwDefaultKey, 4);
			this->m_mProperty[lpKey] = xcProperty;
			bResult = TRUE;
		}
	}
	return bResult;
}