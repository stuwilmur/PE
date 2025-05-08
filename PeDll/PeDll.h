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

enum PE_TYPE
{
    PE32,
    PE64
};

PEDLL_API void fn();
PEDLL_API _IMAGE_DOS_HEADER read_dos_header(FILE* pe_file);
PEDLL_API size_t read_dos_stub(FILE* pe_file, uint8_t* buffer, size_t buffer_size);
PEDLL_API size_t read_rich_header(FILE* pe_file, RICH_HEADER_ENTRY* buffer, size_t buffer_size);
PEDLL_API IMAGE_NT_HEADERS32 read_nt_headers_32(FILE* pe_file);
PEDLL_API IMAGE_NT_HEADERS64 read_nt_headers_64(FILE* pe_file);
PEDLL_API PE_TYPE get_pe_type(FILE* pe_file);