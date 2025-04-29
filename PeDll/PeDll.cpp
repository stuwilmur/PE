#include "pch.h" // use stdafx.h in Visual Studio 2017 and earlier
#include "PeDll.h"

#include <sstream>
#include <stdexcept>
#include <vector>

#include "PeLib.h"
#include "Utils.h"

/**
 * \brief Just an example exported function
 * Also an example of calling into PeLib
 */
void fn()
{
    fnPeLib();
}

/**
 * \brief Read the DOS header from a file
 * \param pe_file File pointer to the PE file to be read
 * \return Structure representing the DOS header
 */
_IMAGE_DOS_HEADER read_dos_header(FILE* pe_file)
{
    safe_seek(pe_file, 0);
    _IMAGE_DOS_HEADER dos_header = _IMAGE_DOS_HEADER();
    if (fread_s(&dos_header, sizeof(_IMAGE_DOS_HEADER), sizeof(_IMAGE_DOS_HEADER), 1, pe_file) != 1)
    {
        throw std::runtime_error("Can't read DOS header");
    }

    return dos_header;
}

/**
 * \brief Read the DOS header from a file
 * \param pe_file File pointer to the PE file to be read
 * \param buffer The buffer to populate with header entries
 * \param buffer_size The size of the buffer (number of header entries)
 * \return The number of parsed Rich header entries
 */
ULONGLONG read_rich_header(FILE* pe_file, RICH_HEADER_ENTRY* buffer, int buffer_size)
{
    _IMAGE_DOS_HEADER dos_header = read_dos_header(pe_file);
    long start_offset = sizeof(_IMAGE_DOS_HEADER);
    long end_offset = dos_header.e_lfanew;
    std::vector<uint8_t>::size_type size_bytes = end_offset - start_offset;
    std::vector<uint8_t> header_bytes(size_bytes * 2);

    safe_seek(pe_file, start_offset);
    if (fread_s(header_bytes.data(), header_bytes.size(), sizeof(uint8_t), size_bytes, pe_file) != size_bytes)
    {
        throw std::runtime_error("Can't read Rich header");
    }

    std::vector<uint8_t> decrypted_bytes(header_bytes);
    const std::vector<uint8_t>::difference_type KEY_SIZE = 4;
    const std::vector<uint8_t>::difference_type RICH_SIZE = 4;
    const std::vector<uint8_t>::difference_type DANS_SIZE = 4;
    const std::string rich_string = "Rich";
    const std::string dans_string = "DanS";
    const std::vector<uint8_t> rich_vector(rich_string.begin(), rich_string.end());
    const std::vector<uint8_t> dans_vector(dans_string.begin(), dans_string.end());
    const std::vector<uint8_t>::difference_type COMBINED_SIZE = KEY_SIZE + RICH_SIZE;

    std::vector<uint8_t> key;
    bool key_found = false;
    int key_index;
    ptrdiff_t rich_start_position = -1;
    std::vector<uint8_t>::iterator start_of_entries;
    std::vector<uint8_t>::iterator end_of_entries;
    bool dans_found = false;

    for (auto end_it = header_bytes.rbegin(), start_it = end_it + COMBINED_SIZE, decrypt_it = decrypted_bytes.rbegin() + 8; start_it != header_bytes.rend(); ++end_it, ++start_it, ++decrypt_it)
    {
        if (key_found)
        {
            *decrypt_it = *decrypt_it ^ key[key_index];
            std::vector<uint8_t> maybe_dans((decrypt_it + 1).base(), (decrypt_it + 1).base() + DANS_SIZE);
            if (maybe_dans == dans_vector)
            {
                dans_found = true;
                ptrdiff_t dans_end_position = std::distance(decrypted_bytes.begin(), (decrypt_it + 1).base() + DANS_SIZE);
                start_of_entries = decrypted_bytes.begin() + dans_end_position + 3 * sizeof(DWORD);
                end_of_entries = decrypted_bytes.begin() + rich_start_position + 1;
            }
            if (key_index > 0)
            {
                key_index--;
            }
            else
            {
                key_index = KEY_SIZE - 1;
            }
        }
        else
        {
            std::vector<uint8_t> sub(end_it, start_it);
            std::reverse(sub.begin(), sub.end());
            std::vector<uint8_t> maybe_rich(sub.begin(), sub.begin() + RICH_SIZE);
            if (maybe_rich == rich_vector)
            {
                key = std::vector<uint8_t>(sub.begin() + RICH_SIZE, sub.begin() + COMBINED_SIZE);
                key_found = true;
                key_index = KEY_SIZE - 1;
                rich_start_position = std::distance(header_bytes.begin(), (start_it + 1).base());
                --decrypt_it;
            }
        }
    }

    if (!key_found)
    {
        throw std::runtime_error("Couldn't find Rich header XOR key");
    }

    if (!dans_found)
    {
        throw std::runtime_error("Couldn't find Rich header DanS marker");
    }

    std::vector<RICH_HEADER_ENTRY> parsed_header_data;
    int ENTRY_SIZE = sizeof(DWORD) * 2;
    auto it = start_of_entries;
    int BYTE = 8;

    while(std::distance(it, end_of_entries) >= ENTRY_SIZE)
    {
        RICH_HEADER_ENTRY entry = {};

        entry.product = *it++;
        entry.product |= *it++ << BYTE;

        entry.build = *it++;
        entry.build |= *it++ << BYTE;

        entry.count = *it++;
        entry.count |= *it++ << BYTE;
        entry.count |= *it++ << 2 * BYTE;
        entry.count |= *it++ << 3 * BYTE;
        
        parsed_header_data.emplace_back(entry);
    }

    if (buffer_size < static_cast<int>(parsed_header_data.size()))
    {
        std::stringstream ss;
        ss << "Supplied buffer of size " << buffer_size
        << "is too small for number of Rich header entries "
        << parsed_header_data.size();
        throw std::runtime_error(ss.str());
    }

    std::copy(parsed_header_data.begin(), parsed_header_data.end(), buffer);
    return parsed_header_data.size();
}
