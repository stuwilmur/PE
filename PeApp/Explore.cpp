#include <sstream>
#include <vector>

#include "PeDll.h"
#include "AppUtils.h"
#include "Explore.h"

#include <iomanip>
#include <iostream>

constexpr int MAX_BUF_LENGTH = 4096;
constexpr int MAX_DOS_STUB_SIZE = 256;
constexpr int MAX_RICH_HEADER_ENTRIES = 100;

namespace explore
{
    /**
     * \brief Explore the PE file
     */
    void explore_pe()
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

        explore_dos_header(file);
        explore_dos_stub(file);
        explore_rich_header(file);

        if (fclose(file) != 0)
        {
            std::stringstream ss;
            ss << "Failed to close file " << file_name_string;
            throw std::runtime_error(ss.str());
        }
    }

    /**
     * \brief Explore the DOS header
     * \param file File pointer
     */
    void explore_dos_header(FILE* file)
    {
        if (!file)
        {
            throw std::invalid_argument("Invalid file pointer");
        }

        const _IMAGE_DOS_HEADER dos_header = read_dos_header(file);

        std::stringstream ss;
        ss << "DOS header:\ne_magic: " << static_cast<char>(LOBYTE(dos_header.e_magic)) << static_cast<char>(HIBYTE(dos_header.e_magic))
        << " = 0x" << std::hex << dos_header.e_magic
        << "\ne_lfanew: 0x" << std::hex << dos_header.e_lfanew;
        std::cout << ss.str();
    }

    /**
     * \brief Explore the DOS stub
     * \param file File pointer
     */
    void explore_dos_stub(FILE* file)
    {
        if (!file)
        {
            throw std::invalid_argument("Invalid file pointer");
        }
        std::vector<uint8_t> dos_stub(MAX_DOS_STUB_SIZE);
        const size_t dos_stub_length = read_dos_stub(file, dos_stub.data(), dos_stub.size());
        dos_stub.resize(dos_stub_length);

        std::cout << "\n\nDOS stub (ASCII):\n";
        dump_bytes(&dos_stub, app_utils::ascii_format);
        std::cout << "\n\nDOS stub (hex):\n";
        dump_bytes(&dos_stub, app_utils::hex_format);
    }

    /**
     * \brief Explore the Rich header
     * \param file File pointer
     */
    void explore_rich_header(FILE* file)
    {
        if (!file)
        {
            throw std::invalid_argument("Invalid file pointer");
        }

        std::vector<RICH_HEADER_ENTRY> rich_header(MAX_RICH_HEADER_ENTRIES);
        const size_t number_of_header_entries = read_rich_header(file, rich_header.data(), rich_header.size());
        rich_header.resize(number_of_header_entries);

        std::stringstream ss;
        ss << "\n\nRich header entries info:\n";
        for (const auto entry : rich_header)
        {
            ss << "product: " << std::setw(2 * sizeof RICH_HEADER_ENTRY::product)
            << std::setfill('0') << std::hex << entry.product << "\t"
            << "build: " << std::setw(2 * sizeof RICH_HEADER_ENTRY::build)
            << std::setfill('0') << std::hex << entry.build << "\t"
            << "count: " << entry.count << "\n";
        }
        std::cout << ss.str();
    }
}