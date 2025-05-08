#pragma once

#include <stdio.h>

#include <windows.h> // necessary, even though VS suggests it may not be
#include <winnt.h>
#include <string>
#include <vector>

namespace explore
{
    void explore_pe();
    void explore_dos_header(FILE* file);
    void explore_dos_stub(FILE* file);
    void explore_rich_header(FILE* file);
    void explore_nt_headers(FILE* file);
    void dump_image_file_header(const IMAGE_FILE_HEADER * header);
    std::vector<std::string> get_characteristics_descriptions(DWORD characteristics);
}