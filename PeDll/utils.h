#pragma once

#include <cstdio>
#include <sys/types.h>

namespace utils
{
    void safe_seek(FILE* file, off_t offset);
}