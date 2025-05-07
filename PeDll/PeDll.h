#pragma once

#include <cstdint>
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

PEDLL_API void fn();
PEDLL_API _IMAGE_DOS_HEADER read_dos_header(FILE* pe_file);
PEDLL_API size_t read_dos_stub(FILE* pe_file, uint8_t* buffer, size_t buffer_size);
PEDLL_API size_t read_rich_header(FILE* pe_file, RICH_HEADER_ENTRY* buffer, size_t buffer_size);