#pragma once

typedef struct _ABSTRACT_XPROVIDER_VF
{
	int(__stdcall * IncInstance)(void *);
	int(__stdcall * DecInstance)(void *);
} ABSTRACT_XPROVIDER_VF;

// xpl
typedef struct _XPL_READER_FUNCTIONS
{
	// off_10015BE0
	int(__thiscall * IncInstance)(void *);
	int(__thiscall * DecInstance)(void *);
	unsigned int(__thiscall * f08)(void *);
	unsigned int(__thiscall * GetType)(void *);		// sub_10002E3E
	unsigned int(__thiscall * GetValue)(void *);
	unsigned short(__thiscall * GetIndex)(void *);
	unsigned short(__thiscall * GetSize)(void *);	// thunk
	unsigned int(__thiscall * GetKey)(void *);		// sub_10002EA1
	unsigned int(__thiscall * GetR)(void *);
	unsigned int(__thiscall * f24)(void *);
	unsigned int(__thiscall * GetO)(void *);
	unsigned int(__thiscall * f2c)(void *);
	unsigned char *(__thiscall * GetDecryptedBuffer)(void *);	// sub_10002F03
	void(__thiscall * f34)(void *, wchar_t *, unsigned int);	// sub_10002F5E
	unsigned int(__thiscall * f38)(void *);
	unsigned int(__thiscall * f3c)(void *);
	unsigned int(__thiscall * f40)(void *);
} XPL_READER_FUNCTIONS;

typedef struct _XPL_READER
{
	// off_10015BE0
	XPL_READER_FUNCTIONS	*vfptr;
	unsigned char			*request;
	unsigned char			*request_decrypted;
	unsigned long			_0c;
	unsigned long			_10;
	unsigned long			_14;
	unsigned long			_18;
	unsigned long			_1c;
	unsigned long			instances;		// gc
} XPL_READER;

typedef struct _XPL_WRITER_FUNCTIONS
{
	// off_1000FB7C or off_1000FBEC
	int(__thiscall * IncInstance)(void *);
	int(__thiscall * DecInstance)(void *);
	unsigned int(__thiscall * f08)(void *, unsigned int);	// sub_100018A2 +0x08	xor
	unsigned int(__thiscall * f0c)(void *, unsigned int);	// sub_100018B5 +0x0C
	unsigned int(__thiscall * f10)(void *, unsigned int);	// sub_100018CB +0x10
	unsigned int(__thiscall * WriteValue)(void *, unsigned int);// sub_100018E1 +0x14	buf[4] = s;
	unsigned int(__thiscall * WriteKey)(void *, unsigned int);// sub_100018EE +0x18	buf[2] = g;
	unsigned int *(__thiscall * GetRealBuffer)(void *);		// sub_100018FB +0x1C	buf + 0x28
	unsigned int(__thiscall * GetRealSize)(void *);			// sub_10001902 +0x20	size - 0x2B
	unsigned int(__thiscall * Free)(void *, bool);			// sub_100017D8 +0x24	free
} XPL_WRITER_FUNCTIONS;

typedef struct _XPL_WRITER
{
	XPL_WRITER_FUNCTIONS	*vfptr;
	unsigned char			*buffer;
	unsigned int			size;
	unsigned long			instances;		// gc
	unsigned char			*buffer_new;	// heapalloc by xpl
} XPL_WRITER;

// xst
typedef struct _XPACK_PROVIDER_VF
{
	// off_100E17C0
	ABSTRACT_XPROVIDER_VF baseProvider;
	void *reserverd[4];
	int(__stdcall * GetPackedBuffer)(void *, const char *, void *buf, uint size);	// +0x18
	int(__stdcall * GetSize)(void *, const char *, uint *);	// +0x1C
} XPACK_PROVIDER_VF;

typedef struct _XPACK_PROVIDER
{
	XPACK_PROVIDER_VF *vfptr;
	// XPACK xpack;
} XPACK_PROVIDER;

typedef struct _MODULE_LOADER_VF
{
	ABSTRACT_XPROVIDER_VF baseProvider;
	void *reserverd[3];
	int(__stdcall *XLoadLibrary)(void *, HMODULE *phModule, void *, uint);	// +0x14
	BOOL(__stdcall *XFreeLibrary)(void *, HMODULE hModule);
	FARPROC(__stdcall *XGetProcAddress)(void *, HMODULE hModule, LPCSTR lpProcName);
} MODULE_LOADER_VF;

typedef struct _MODULE_LOADER
{
	MODULE_LOADER_VF *vfptr;
} MODULE_LOADER;

typedef struct _XPROPERTIES_VF
{
	ABSTRACT_XPROVIDER_VF baseProvider;
	Padding(0x0C);
	int(__stdcall * GetXProp)(void *, uint, void **);
} XPROPERTIES_VF;

typedef struct _XPROPERTIES
{
	XPROPERTIES_VF *vfptr;
} XPROPERTIES;

typedef struct _ADAPTER_INFO_PROVIDER_VF
{
	ABSTRACT_XPROVIDER_VF baseProvider;
	Padding(0x90);
	ULONG(__stdcall * GetAdaptersInfo)(void *, void *AdapterInfo, PULONG SizePointer);
} ADAPTER_INFO_PROVIDER_VF;

typedef struct _ADAPTER_INFO_PROVIDER
{
	ADAPTER_INFO_PROVIDER_VF *vfptr;
} ADAPTER_INFO_PROVIDER;