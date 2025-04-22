// PeApp.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <sstream>

#include "PeDll.h"
#include "AppUtils.h"

constexpr int MAX_BUF_LENGTH = 4096;

/**
 * \brief Entry point
 * \return Exit code
 */
int main()
{
    fn();

    FILE * file;
    WCHAR full_file_name[MAX_BUF_LENGTH];
    const WCHAR* dllName = L"ExampleDll.dll";

    if (get_abs_path_from_filename(full_file_name, dllName, MAX_BUF_LENGTH) != 0)
    {
        std::stringstream ss;
        ss << "Can't get full path of " << dllName;
        throw std::runtime_error(ss.str());
    }

    const std::string file_name_string = wchar_t_buffer_to_string(full_file_name);

    if (fopen_s(&file, file_name_string.c_str(), "r") != 0)
    {
        std::stringstream ss;
        ss << "Can't open file " << file_name_string;
        throw std::runtime_error(ss.str());
    }

    _IMAGE_DOS_HEADER dos_header = read_dos_header(file);
    dos_header = dos_header;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
