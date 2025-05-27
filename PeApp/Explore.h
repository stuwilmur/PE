#pragma once

#include <map>
#include <stdio.h>

#include <windows.h> // necessary, even though VS suggests it may not be
#include <winnt.h>
#include <string>
#include <vector>

namespace explore
{
    void explore_pe(FILE* file);
    void explore_dos_header(FILE* file);
    void explore_dos_stub(FILE* file);
    void explore_rich_header(FILE* file);
    void explore_nt_headers(FILE* file);
    void explore_image_section_headers(FILE* file);
    void explore_import_directory_table(FILE* file);
    void dump_image_file_header(const IMAGE_FILE_HEADER * header);
    void dump_image_optional_header32(const IMAGE_OPTIONAL_HEADER32* header);
    void dump_image_optional_header64(const IMAGE_OPTIONAL_HEADER64* header);
    void dump_image_section_header(const IMAGE_SECTION_HEADER* header);
    void dump_image_import_descriptor(const IMAGE_IMPORT_DESCRIPTOR* descriptor);
    std::vector<std::string> get_characteristics_descriptions(DWORD characteristics, const std::map<DWORD, const char*>*);
}