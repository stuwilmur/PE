#pragma once

#include <windows.h> // necessary, even though VS suggests it may not be
#include <winnt.h>
#include <stdio.h>

#ifdef PEDLL_EXPORTS
#define PEDLL_API __declspec(dllexport)
#else
#define PEDLL_API __declspec(dllimport)
#endif

struct RICH_HEADER_ENTRY
{
    WORD product;
    WORD build;
    DWORD count;
};

extern "C" PEDLL_API void fn();
extern "C" PEDLL_API _IMAGE_DOS_HEADER read_dos_header(FILE* pe_file);
extern "C" PEDLL_API ULONGLONG read_rich_header(FILE* pe_file, RICH_HEADER_ENTRY* buffer, int buffer_size);