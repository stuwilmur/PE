#pragma once

#include <cstdio>
#include <sys/types.h>

void safe_seek(FILE* file, off_t offset);