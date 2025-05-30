
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
    auto dos_header = _IMAGE_DOS_HEADER();
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
size_t read_dos_stub(FILE* pe_file, uint8_t* buffer, const size_t buffer_size)
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
            key_index = key_index > 0 ? key_index - 1 : KEY_SIZE - 1;
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

/**
 * \brief Read the NT headers of a 32-bit PE file
 * \param pe_file File pointer to the PE file to be read
 * \return NT headers structure
 */
PEDLL_API IMAGE_NT_HEADERS32 read_nt_headers_32(FILE* pe_file)
{
    if (!pe_file)
    {
        throw std::invalid_argument("Invalid file pointer");
    }

    if (get_pe_type(pe_file) != PE32)
    {
        throw std::runtime_error("File is not a 32-bit PE file");
    }

    const _IMAGE_DOS_HEADER dos_header = read_dos_header(pe_file);
    utils::safe_seek(pe_file, dos_header.e_lfanew);
    IMAGE_NT_HEADERS32 nt_headers32;
    if (fread_s(&nt_headers32, sizeof nt_headers32, sizeof nt_headers32, 1, pe_file) != 1)
    {
        throw std::runtime_error("Can't read NT header");
    }
    return nt_headers32;
}

/**
 * \brief Read the NT headers of a 64-bit PE file
 * \param pe_file File pointer to the PE file to be read
 * \return NT headers structure
 */
PEDLL_API IMAGE_NT_HEADERS64 read_nt_headers_64(FILE* pe_file)
{
    if (!pe_file)
    {
        throw std::invalid_argument("Invalid file pointer");
    }

    if (get_pe_type(pe_file) != PE64)
    {
        throw std::runtime_error("File is not a 64-bit PE file");
    }

    const _IMAGE_DOS_HEADER dos_header = read_dos_header(pe_file);
    utils::safe_seek(pe_file, dos_header.e_lfanew);
    IMAGE_NT_HEADERS64 nt_headers64;
    if (fread_s(&nt_headers64, sizeof nt_headers64, sizeof nt_headers64 , 1, pe_file) != 1)
    {
        throw std::runtime_error("Can't read NT header");
    }
    return nt_headers64;
}

/**
 * \brief Return the type (32- or 64-bit) of a PE file
 * \param pe_file File pointer to the PE file to be read
 * \return Type of the file
 */
PE_TYPE get_pe_type(FILE* pe_file)
{
    if (!pe_file)
    {
        throw std::invalid_argument("Invalid file pointer");
    }

    const _IMAGE_DOS_HEADER dos_header = read_dos_header(pe_file);
    const off_t magic_offset = static_cast<off_t>(dos_header.e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);

    utils::safe_seek(pe_file, magic_offset);
    WORD magic;
    if (fread_s(&magic, sizeof magic, sizeof magic, 1, pe_file) != 1)
    {
        throw std::runtime_error("Can't read Optional header magic number");
    }

    constexpr WORD PE32_MAGIC = 0x10b;
    constexpr WORD PE64_MAGIC = 0x20b;

    PE_TYPE pe_type;
    switch (magic)
    {
    case PE32_MAGIC:
        pe_type = PE32;
        break;
    case PE64_MAGIC:
        pe_type = PE64;
        break;
    default:
        throw std::runtime_error("Unrecognised magic number in Optional header: unknown PE type");
    }
    return pe_type;
}

/**
 * \brief Get the number of image section headers in the PE file
 * \param  pe_file Pointer to PE file
 * \return The number of IMAGE_SECTION_HEADER entries
 */
PEDLL_API WORD get_number_image_section_headers(FILE* pe_file)
{
    if (!pe_file)
    {
        throw std::invalid_argument("Invalid file pointer");
    }

    const PE_TYPE pe_type = get_pe_type(pe_file);
    WORD number_of_sections;

    if (pe_type == PE32)
    {
        const IMAGE_NT_HEADERS32 nt_headers32 = read_nt_headers_32(pe_file);
        number_of_sections = nt_headers32.FileHeader.NumberOfSections;
    }
    else if (pe_type == PE64)
    {
        const IMAGE_NT_HEADERS64 nt_headers64 = read_nt_headers_64(pe_file);
        number_of_sections = nt_headers64.FileHeader.NumberOfSections;
    }
    else
    {
        throw std::invalid_argument("Invalid PE file type");
    }

    return number_of_sections;
}

/**
 * \brief Read the image data directory entries into a buffer
 * \param  pe_file Pointer to PE file
 * \param buffer Pointer to a buffer which will be populated
 * \param buffer_size Number of entries the buffer can hold
 */
PEDLL_API void read_image_data_directory(FILE* pe_file, IMAGE_DATA_DIRECTORY* buffer, size_t buffer_size)
{
    if (!pe_file || !buffer)
    {
        throw std::invalid_argument("Invalid file pointer or buffer");
    }

    if (buffer_size < IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
    {
        throw std::invalid_argument("Supplied buffer is smaller than number of image directory entries");
    }

    const PE_TYPE pe_type = get_pe_type(pe_file);
    const IMAGE_DATA_DIRECTORY* p_data_directory;

    if (pe_type == PE32)
    {
        const IMAGE_NT_HEADERS32 nt_headers32 = read_nt_headers_32(pe_file);
        p_data_directory = nt_headers32.OptionalHeader.DataDirectory;
    }
    else if (pe_type == PE64)
    {
        const IMAGE_NT_HEADERS64 nt_headers64 = read_nt_headers_64(pe_file);
        p_data_directory = nt_headers64.OptionalHeader.DataDirectory;
    }
    else
    {
        throw std::invalid_argument("Invalid PE file type");
    }

    memcpy(buffer, p_data_directory, IMAGE_NUMBEROF_DIRECTORY_ENTRIES * sizeof(IMAGE_DATA_DIRECTORY));
}

/**
 * \brief Read the image section headers to a buffer
 * \param  pe_file Pointer to PE file
 * \param  buffer Pointer to supplied buffer which will be populated with image section headers
 * \param  buffer_size Size of the supplied buffer: number of IMAGE_SECTION_HEADER entries it can hold
 * \return The number of read IMAGE_SECTION_HEADER entries
 */
size_t read_image_section_headers(FILE* pe_file, IMAGE_SECTION_HEADER* buffer, const size_t buffer_size)
{
    if (!pe_file || !buffer)
    {
        throw std::invalid_argument("Invalid file pointer or buffer");
    }

    const _IMAGE_DOS_HEADER dos_header = read_dos_header(pe_file);
    const PE_TYPE pe_type = get_pe_type(pe_file);
    off_t size_of_nt_headers;

    if (pe_type == PE32)
    {
        size_of_nt_headers = sizeof(IMAGE_NT_HEADERS32);
    }
    else if (pe_type == PE64)
    {
        size_of_nt_headers = sizeof(IMAGE_NT_HEADERS64);
    }
    else
    {
        throw std::invalid_argument("Invalid PE file type");
    }

    const off_t section_headers_offset = dos_header.e_lfanew + size_of_nt_headers;
    utils::safe_seek(pe_file, section_headers_offset);

    const WORD number_of_sections = get_number_image_section_headers(pe_file);
    if (number_of_sections > buffer_size)
    {
        std::stringstream ss;
        ss << "Supplied buffer of size " << buffer_size
            << " is too small for number of image section header entries "
            << number_of_sections;
        throw std::runtime_error(ss.str());
    }

    std::vector<IMAGE_SECTION_HEADER> section_headers;

    for (int i = 0; i < number_of_sections; i++)
    {
        IMAGE_SECTION_HEADER section_header;
        if (fread_s(&section_header, sizeof(IMAGE_SECTION_HEADER), sizeof(IMAGE_SECTION_HEADER), 1, pe_file) != 1)
        {
            throw std::runtime_error("Can't read image section header");
        }
        section_headers.emplace_back(section_header);
    }

    std::copy(section_headers.begin(), section_headers.end(), buffer);
    return section_headers.size();
}

/**
 * \brief Read the import directory table into a buffer
 * \param  pe_file Pointer to PE file
 * \param  buffer Pointer to supplied buffer which will be populated with image import descriptor entries
 * \param  buffer_size Size of the supplied buffer: number of IMAGE_IMPORT_DESCRIPTOR entries it can hold
 * \return The number of read IMAGE_IMPORT_DESCRIPTOR entries in the table
 */
size_t read_import_directory_table(FILE* pe_file, IMAGE_IMPORT_DESCRIPTOR* buffer, size_t buffer_size)
{
    if (!pe_file || !buffer)
    {
        throw std::invalid_argument("Invalid file pointer or buffer");
    }

    // Read the image section headers
    const WORD number_of_section_headers = get_number_image_section_headers(pe_file);
    const auto allocated_size = static_cast<size_t>(number_of_section_headers * 2);
    std::vector<IMAGE_SECTION_HEADER> image_section_headers(allocated_size);
    const size_t number_of_read_section_headers = read_image_section_headers(pe_file, image_section_headers.data(), allocated_size);
    image_section_headers.resize(number_of_read_section_headers);

    std::vector<IMAGE_DATA_DIRECTORY> image_data_directory(IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
    read_image_data_directory(pe_file, image_data_directory.data(), image_data_directory.size());

    const DWORD import_directory_rva = image_data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    const off_t import_data_file_offset = rva_to_file_offset(import_directory_rva, image_section_headers);

    std::vector<IMAGE_IMPORT_DESCRIPTOR> image_import_descriptors;
    utils::safe_seek(pe_file, import_data_file_offset);

    while (true)
    {
        IMAGE_IMPORT_DESCRIPTOR image_import_descriptor;

        if (fread_s(&image_import_descriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, pe_file) != 1)
        {
            throw std::runtime_error("Can't read image import descriptor");
        }

        if (image_import_descriptor.Name == 0
            && image_import_descriptor.FirstThunk == 0
            && image_import_descriptor.ForwarderChain == 0
            && image_import_descriptor.TimeDateStamp == 0
            && image_import_descriptor.Characteristics == 0)
        {
            break;
        }
        image_import_descriptors.emplace_back(image_import_descriptor);
    }

    if (image_import_descriptors.size() > buffer_size)
    {
        std::stringstream ss;
        ss << "Supplied buffer of size " << buffer_size
            << " is too small for number of image section header entries "
            << image_import_descriptors.size();
        throw std::runtime_error(ss.str());
    }

    std::copy(image_import_descriptors.begin(), image_import_descriptors.end(), buffer);
    return image_import_descriptors.size();
}

/**
 * \brief Calculate a file offset given an RVA and the read image section headers.
 * This is achieved by checking whether the supplied RVA falls within the bounds
 * of each section header, using its virtual address and size of raw data.
 * \param rva RVA to be converted
 * \param image_section_headers Reference to a vector of IMAGE_SECTION_HEADERs
 * \return The calculated offset
 */
off_t rva_to_file_offset(DWORD rva, const std::vector<IMAGE_SECTION_HEADER>& image_section_headers)
{
    for (const auto & image_section_header : image_section_headers)
    {
        if (rva >= image_section_header.VirtualAddress && rva <= image_section_header.VirtualAddress + image_section_header.SizeOfRawData)
        {
            return rva - image_section_header.VirtualAddress + image_section_header.PointerToRawData;
        }
    }

    std::stringstream ss;
    ss << "Unable to find image section that includes RVA " << std::hex << rva;
    throw std::runtime_error(ss.str());
}
