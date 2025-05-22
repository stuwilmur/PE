#pragma once

#include <windows.h>
#include <string>
#include <vector>

namespace app_utils
{
    enum dump_format
    {
        hex_format,
        ascii_format
    };

    int get_abs_path_from_filename(WCHAR*, const WCHAR*, DWORD);
    std::string wchar_t_buffer_to_string(const WCHAR*);
    void dump_bytes(const std::vector<uint8_t>* buffer, dump_format format);
    std::string format_unix_timestamp(time_t time);
    FILE* open_local_file(const WCHAR* fileName);
}
