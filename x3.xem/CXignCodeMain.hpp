#pragma once

#include "TSingleton.hpp"
#include <list>
#include <map>
#include <mutex>

struct CCodeBox;

typedef struct _ZCE_ID
{
	union
	{
		unsigned char buffer[16];
		struct
		{
			uint			a;
			unsigned short	b;
			unsigned short	c;
			unsigned char	d;
			unsigned char	e;
			unsigned char	f;
			unsigned char	g;
			unsigned char	h;
			unsigned char	i;
			unsigned char	j;
			unsigned char	k;
		};
	};
} ZCE_ID;

#pragma pack(push, 1)
typedef struct _RSA_FILE_HEADER
{
	CHAR	name[30];
	uint	signature;
	uint	bufSize;
	uint	originSize;
	ubyte	rsaKeyLen;
	ubyte	start[5];
} RSA_FILE_HEADER;

typedef struct _XDNA_PROPERTY
{
	ubyte	type;
	ubyte	keySize;
	uint	dataSize;
	union
	{
		CHAR szKey[1];
		ubyte	buf[1];
	};
} XDNA_PROPERTY, *PXDNA_PROPERTY, *LPXDNA_PROPERTY;
#pragma pack(pop)

struct XignCode_Property
{
	int nType;
	int nSize;
	void *pData;
};

class CRefCounter
{
public:
	CRefCounter();
	~CRefCounter();
};

class CXignCodeMain : public TSingleton<CXignCodeMain>
{
	friend class TSingleton<CXignCodeMain>;

private:
	CXignCodeMain();

public:
	~CXignCodeMain();
	
	// exports functions?
	BOOL SysEnterA(LPCSTR szLicense, LPCSTR szPath, UINT uFlags);
	BOOL SysEnterW(LPCWSTR szLicense, LPCWSTR szPath, UINT uFlags);
	BOOL SysExit();
	BOOL Init();
	BOOL Cleanup();
	BOOL Probe(const unsigned char *request, unsigned char *response, uint req_size);
	BOOL ProbeEx(const unsigned char *request, uint req_size, ProbeCallbackT callback, void *context);
	void *CreateCodeBox();
	BOOL CloseCodeBox(void *CodeBox);
	BOOL ProbeCodeBox(void *CodeBox, const unsigned char *request, void *response, uint size);
	BOOL ProbeCodeBoxEx(void *CodeBox, const unsigned char *request, uint req_size, uint res_size, ProbeCallbackT Callback, void *Context);
	VOID RegisterCallback(XigncodeCallbackT Callback, void *Context);
	BOOL SendCommandVa(uint cid, va_list ap);

	// sub functions
	BOOL IsInitialized();
	BOOL Initialize(LPCWSTR szLicense, LPCWSTR szPath, UINT uFlags);
	BOOL Finalize();
	BOOL Reset();
	void Shutdown();

	// support
	void IncRefExports();
	void DecRefExports();
	BOOL CanShutdown();

	// data
	LPCSTR GetLicenseA();
	LPWSTR GetLicenseW();
	DWORD GetRevision();
	ZCE_ID *GetAdaptersHash();

	// xdna
	BOOL GetInformation(__in LPCWSTR lpFile);
	BOOL LoadPropertiesFromFile(__in LPCWSTR lpFile);
	void ClearProperties();
	BOOL GetDataFromProperty(__in LPCSTR lpKey, __out LPVOID lpDst, __in DWORD dwSize);
	BOOL GetDataFromProperty(__in LPCSTR lpKey, __out LPVOID lpDst, __in DWORD dwSize, __in DWORD dwDefaultKey);

private:
	CHAR m_szLicense[16];
	WCHAR m_wszLicense[16];
	UINT m_uRevision;
	ZCE_ID m_adaptersHash;

	CRITICAL_SECTION m_cs, m_csCodeBox;
	std::mutex m_mtxProperty;
	volatile LONG m_nRefInstance;
	volatile LONG m_nRefExports;

	CCodeBox *m_pCodeBox;
	std::list<CCodeBox*> m_lCodeBox;
	std::map<std::string, XignCode_Property> m_mProperty;
	
	MODULE_LOADER *m_pLoader;

	void *m_lpCallbackContext;
	XigncodeCallbackT m_fnCallback;
};