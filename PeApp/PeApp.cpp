// PeApp.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <sstream>
#include <stdexcept>

#include "AppUtils.h"
#include "Explore.h"

/**
 * \brief Entry point
 * \return Exit code
 */
int main()
{
    const WCHAR* file_name = L"ExampleDll.dll";
    FILE* file = app_utils::open_local_file(file_name);

    explore::explore_pe(file);

    if (fclose(file) != 0)
    {
        std::stringstream ss;
        ss << "Failed to close file " << file_name;
        throw std::runtime_error(ss.str());
    }

    return 0;
}
