#pragma once

typedef enum _xst_codeid
{
	LOADER_DOS		= 0xF00D,
	ADAPTER_INFO	= 0xF00F,
	LOADER_XMAG		= 0xF015,
	LOADER_LOMX		= 0xF01A,
	PROPERTIES		= 0x11000,
} xst_codeid;

typedef enum _xst_cryption
{
	BLOWFISH = 0,
	AES = 1,
	RC4 = 2
} xst_cryption;

typedef struct _rsa_ctx
{
	uint a;
	uint b;
	uint c;
	uint d;
	uint e;
	uint f;
	uint g;
	uint h;
	uint i;
	uint j;
	// size = 0x28
} rsa_ctx;

typedef struct _xst_exports
{
	Padding(0xF0);
	wchar_t *(__stdcall *AppendWideChar)(wchar_t *dst, uint len, const wchar_t *src);	// +0xF0
	Padding(0x54);
	void(__stdcall *md5_init)(void *);	// +0x148
	void(__stdcall *md5_process)(void *, ubyte *, uint);	// +0x14C
	void(__stdcall *md5_done)(void *, ubyte *);	// +0x150
	Padding(0x4C);
	void(__stdcall *Unspack)(void *dst, uint *dsize, void *src, uint *ssize, ubyte *, uint);	// +0x1A0
	Padding(0x38);
	int(__stdcall *Encrypt)(void *src, uint ssize, const char * key, uint keySize, void *dst, uint dsize, uint *decryptedSize, xst_cryption type);	// +0x1DC
	int(__stdcall *Decrypt)(void *src, uint ssize, const char * key, uint keySize, void *dst, uint dsize, uint *decryptedSize, xst_cryption type);	// +0x1E0
	Padding(0x1C);
	int(__stdcall *RsaGenerateKey)(void *, void *, void *, void *, void *, void *);// +0x200
	int(__stdcall *RsaSetPrivateKey)(rsa_ctx *, void *, uint);						// +0x204
	int(__stdcall *RsaSetPublicKey)(rsa_ctx *, void *, uint);						// +0x208
	int(__stdcall *RsaPrivateEncrypt)(rsa_ctx *, void *, uint, void *, void *);	// +0x20C
	int(__stdcall *RsaPublicEncrypt)(rsa_ctx *, void *, uint, void *, void *);		// +0x210
	int(__stdcall *RsaPrivateDecrypt)(rsa_ctx *, void *, uint, void *, void *);	// +0x214
	int(__stdcall *RsaPublicDecrypt)(rsa_ctx *, void *, uint, void *, void *);		// +0x218
	int(__stdcall *RsaClose)(rsa_ctx *);											// +0x21C
	int(__stdcall *RsaCreate)(rsa_ctx **);											// +0x220
	int(__stdcall *RsaFreeBuffer)(rsa_ctx *, void *);								// +0x224
	Padding(0x74);
	uint(__stdcall *get_hash)(uint *src, uint len);	// +0x29c
	Padding(0x1C);
	int(__stdcall *HexToWideChar)(wchar_t *dst, uint dsize, const unsigned char *src, uint ssize, bool large);	// +0x2bc
	Padding(0x3C);
	int(__cdecl *CreateProvider)(xst_codeid codeid, void *p, ...); // +0x2fc sub_1003BEC7
	Padding(0x14);
	int(__stdcall *GetFileNameByLicense)(wchar_t *, uint, void *p); // +0x314
	Padding(0x30);
	XPROPERTIES *pProperties; // +0x348
} xst_exports;

extern HMODULE hXst;
extern xst_exports *pXstImport;