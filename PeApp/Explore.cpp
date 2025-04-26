#include <sstream>

#include "PeDll.h"
#include "AppUtils.h"

#include "Explore.h"

constexpr int MAX_BUF_LENGTH = 4096;

/**
 * \brief Explore the PE file
 */
void explore()
{
    FILE* file;
    WCHAR full_file_name[MAX_BUF_LENGTH];
    const WCHAR* dllName = L"ExampleDll.dll";

    if (app_utils::get_abs_path_from_filename(full_file_name, dllName, MAX_BUF_LENGTH) != 0)
    {
        std::stringstream ss;
        ss << "Can't get full path of " << dllName;
        throw std::runtime_error(ss.str());
    }

    const std::string file_name_string = app_utils::wchar_t_buffer_to_string(full_file_name);

    if (fopen_s(&file, file_name_string.c_str(), "r") != 0)
    {
        std::stringstream ss;
        ss << "Can't open file " << file_name_string;
        throw std::runtime_error(ss.str());
    }

    _IMAGE_DOS_HEADER dos_header = read_dos_header(file);
    dos_header = dos_header;
}