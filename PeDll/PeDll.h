#pragma once

#ifdef PEDLL_EXPORTS
#define PEDLL_API __declspec(dllexport)
#else
#define PEDLL_API __declspec(dllimport)
#endif

extern "C" PEDLL_API void fn();