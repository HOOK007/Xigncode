#pragma once

extern void Log(const char *fmt, ...);
extern void Log(const wchar_t *fmt, ...);
extern void Hexdump(void *ptr, int buflen);