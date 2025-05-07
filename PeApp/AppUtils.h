#pragma once

#include <windows.h>
#include <string>
#include <vector>

namespace app_utils
{
    enum DumpFormat
    {
        HexFormat,
        AsciiFormat
    };

    int get_abs_path_from_filename(WCHAR*, const WCHAR*, DWORD);
    std::string wchar_t_buffer_to_string(const WCHAR*);
    void dump_bytes(std::vector<uint8_t>* buffer, DumpFormat format);
}
