#include "stdafx.h"

#include "log.h"

void Log(const char *fmt, ...)
{
	va_list list;
	char buffer[1024];
	FILE *f;
	DWORD dwNumberOfCharsWritten;
	DWORD len;

	va_start(list, fmt);

	// to console
	len = vsprintf_s(buffer, fmt, list);
	WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), buffer, len, &dwNumberOfCharsWritten, NULL);

	if (fopen_s(&f, "XignCode\\x3.log", "a+") == 0)
	{
		if (f)
		{
			vfprintf(f, fmt, list);
			fflush(f);
			fclose(f);
		}
	}

	va_end(list);
}

void Log(const wchar_t *fmt, ...)
{
	va_list list;
	wchar_t buffer[1024];
	FILE *f;
	DWORD dwNumberOfCharsWritten;
	DWORD len;

	va_start(list, fmt);

	// to console
	len = wvsprintf(buffer, fmt, list);
	WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), buffer, len, &dwNumberOfCharsWritten, NULL);

	if (fopen_s(&f, "XignCode\\x3.log", "a+") == 0)
	{
		if (f)
		{
			vfwprintf(f, fmt, list);
			fflush(f);
			fclose(f);
		}
	}

	va_end(list);
}