#pragma once

#include <windows.h> // necessary, even though VS suggests it may not be
#include <winnt.h>
#include <stdio.h>

#ifdef PEDLL_EXPORTS
#define PEDLL_API __declspec(dllexport)
#else
#define PEDLL_API __declspec(dllimport)
#endif

extern "C" PEDLL_API void fn();
extern "C" PEDLL_API _IMAGE_DOS_HEADER read_dos_header(FILE* pe_file);