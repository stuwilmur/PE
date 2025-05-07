#pragma once

#include <stdio.h>

namespace explore
{
    void explore_pe();
    void explore_dos_header(FILE* file);
    void explore_dos_stub(FILE* file);
    void explore_rich_header(FILE* file);
}