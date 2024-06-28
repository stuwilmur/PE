#pragma once

#ifdef EXAMPLEDLL_EXPORTS
#define EXAMPLEDLL_API __declspec(dllexport)
#else
#define EXAMPLEDLL_API __declspec(dllimport)
#endif

extern "C" EXAMPLEDLL_API void fn();