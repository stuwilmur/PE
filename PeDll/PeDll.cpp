
#include "pch.h" // use stdafx.h in Visual Studio 2017 and earlier
#include "PeDll.h"

#include <sstream>
#include <stdexcept>
#include <vector>
#include <algorithm>
#include <iterator>

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
    utils::safe_seek(pe_file, 0);
    _IMAGE_DOS_HEADER dos_header = _IMAGE_DOS_HEADER();
    if (fread_s(&dos_header, sizeof(_IMAGE_DOS_HEADER), sizeof(_IMAGE_DOS_HEADER), 1, pe_file) != 1)
    {
        throw std::runtime_error("Can't read DOS header");
    }

    return dos_header;
}

/**
 * \brief Read the DOS stub from a file. The bytes read
 * include both the DOS stub program, and the raw Rich
 * header bytes.
 * \param pe_file File pointer to the PE file to be read
 * \param buffer The buffer to populate with DOS stub bytes
 * \param buffer_size The size of the buffer (number of bytes)
 * \return The number of bytes copied into the buffer
 */
size_t read_dos_stub(FILE* pe_file, uint8_t* buffer, size_t buffer_size)
{
    const _IMAGE_DOS_HEADER dos_header = read_dos_header(pe_file);
    constexpr long start_offset = sizeof(_IMAGE_DOS_HEADER);
    const long end_offset = dos_header.e_lfanew - 1;
    if (end_offset <= start_offset)
    {
        throw std::runtime_error("Invalid DOS header offsets");
    }

    const size_t dos_stub_size = end_offset - start_offset;
    if (buffer_size < dos_stub_size)
    {
        throw std::runtime_error("Buffer size is too small for DOS stub");
    }

    utils::safe_seek(pe_file, start_offset);
    if (fread_s(buffer, buffer_size, sizeof(uint8_t), dos_stub_size, pe_file) != dos_stub_size)
    {
        throw std::runtime_error("Can't read DOS stub");
    }

    return dos_stub_size;
}

/**
 * \brief Read the Rich header from a file
 * \param pe_file File pointer to the PE file to be read
 * \param buffer The buffer to populate with header entries
 * \param buffer_size The size of the buffer (number of header entries)
 * \return The number of parsed Rich header entries
 */
size_t read_rich_header(FILE* pe_file, RICH_HEADER_ENTRY* buffer, size_t buffer_size)
{
    if (!pe_file || !buffer)
    {
        throw std::invalid_argument("Invalid file pointer or buffer");
    }

    constexpr long MAX_SIZE_DOS_HEADER = 1024;

    std::vector<uint8_t> header_bytes(MAX_SIZE_DOS_HEADER);
    size_t dos_stub_size = read_dos_stub(pe_file, header_bytes.data(), header_bytes.size());
    header_bytes.resize(dos_stub_size);
    std::vector<uint8_t> decrypted_bytes(header_bytes);

    constexpr int KEY_SIZE = 4;
    constexpr int RICH_SIZE = 4;
    constexpr int DANS_SIZE = 4;
    constexpr int DANS_PADDING_SIZE = 3 * sizeof(DWORD); // Three padding DWORDS of zeros after the DanS sentinel

    // Generate the sequences of sentinel bytes that will be sought
    const std::string rich_string = "Rich";
    const std::string dans_string = "DanS";
    const std::vector<uint8_t> rich_vector(rich_string.begin(), rich_string.end());
    const std::vector<uint8_t> dans_vector(dans_string.begin(), dans_string.end());

    std::vector<uint8_t> key;
    bool key_found = false;
    int key_index = 0;
    ptrdiff_t rich_start_position = -1;
    std::vector<uint8_t>::iterator start_of_entries;
    std::vector<uint8_t>::iterator end_of_entries;
    bool dans_found = false;
    ptrdiff_t distance_to_dans_start;

    // Process the encrypted header bytes one byte at a time from the end to the beginning, initially seeking the
    // "Rich" sentinel followed by the XOR key. Once found, cotninue to process by decrypting each
    // byte while looking for the DanS sentinel in the plaintext bytes.
    for (auto end_it = header_bytes.rbegin(), // end of the potential sentinel/key pair
        // Start of the potential sentinel/key pair
        start_it = header_bytes.rbegin() + KEY_SIZE + RICH_SIZE,
        // Start of the potential sentinel/key pair, in the decrypted bytes
        decrypt_it = decrypted_bytes.rbegin() + KEY_SIZE + RICH_SIZE;
        start_it != header_bytes.rend();
        ++end_it, ++start_it, ++decrypt_it)
    {
        if (key_found)
        {
            // We have the key: decrypt the current byte
            *decrypt_it ^= key[key_index];
            if (std::equal(decrypt_it.base(), decrypt_it.base() + DANS_SIZE, dans_vector.begin()))
            {
                // We have reached the DanS marker
                dans_found = true;
                // Get iterators pointing to the start and end of the entries
                distance_to_dans_start = std::distance(decrypted_bytes.begin(), decrypt_it.base());
                ptrdiff_t distance_to_dans_end = distance_to_dans_start + DANS_SIZE;
                start_of_entries = decrypted_bytes.begin() + distance_to_dans_end + DANS_PADDING_SIZE;
                end_of_entries = decrypted_bytes.begin() + rich_start_position + 1;
                break;
            }
            // Cycle the XOR key byte
            key_index = (key_index > 0) ? key_index - 1 : KEY_SIZE - 1;
        }
        else
        {
            // Get a subvector at the current position which contains a potential Rich/key pair
            std::vector<uint8_t> sub(end_it, start_it);
            std::reverse(sub.begin(), sub.end());

            // Check if the subvector starts with "Rich"
            if (std::equal(sub.begin(), sub.begin() + RICH_SIZE, rich_vector.begin()))
            {
                // Store the key and flag found
                key.assign(sub.begin() + RICH_SIZE, sub.begin() + KEY_SIZE + RICH_SIZE);
                key_found = true;
                // Set the initial XOR byte to be the last byte in the key
                key_index = KEY_SIZE - 1;
                // Keep the start position of the Rich sentinel for later
                rich_start_position = std::distance(header_bytes.begin(), start_it.base());
                // Ensure the current byte gets decrypted on the next iteration
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
    constexpr int ENTRY_SIZE = sizeof(DWORD) * 2; // Allocate generously for safety
    auto it = start_of_entries;

    // Process the plaintext bytes (ignoring sentinel bytes) to a set of
    // RICH_HEADER_ENTRY structures. Only bytes sufficient to make a full
    // entry are processed; any remaining trailing bytes are ignored.
    while (std::distance(it, end_of_entries) >= ENTRY_SIZE)
    {
        constexpr int BYTE = 8;
        RICH_HEADER_ENTRY entry = {};

        // Byte format: build, product, count; all values are little-endian
        entry.build = *it++;
        entry.build |= *it++ << BYTE;

        entry.product = *it++;
        entry.product |= *it++ << BYTE;

        entry.count = *it++;
        entry.count |= *it++ << BYTE;
        entry.count |= *it++ << 2 * BYTE;
        entry.count |= *it++ << 3 * BYTE;

        parsed_header_data.emplace_back(entry);
    }

    if (buffer_size < parsed_header_data.size())
    {
        std::stringstream ss;
        ss << "Supplied buffer of size " << buffer_size
            << " is too small for number of Rich header entries "
            << parsed_header_data.size();
        throw std::runtime_error(ss.str());
    }

    // Copy the parsed entries into the supplied buffer
    std::copy(parsed_header_data.begin(), parsed_header_data.end(), buffer);
    return parsed_header_data.size();
}
