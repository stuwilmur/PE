#include <sstream>
#include <vector>

#include "PeDll.h"
#include "AppUtils.h"
#include "Explore.h"

#include <iomanip>
#include <iostream>
#include <map>

constexpr int MAX_BUF_LENGTH = 4096;
constexpr int MAX_DOS_STUB_SIZE = 256;
constexpr int MAX_RICH_HEADER_ENTRIES = 100;

const std::map<WORD, const char*> MACHINE_NAMES = {
    {IMAGE_FILE_MACHINE_UNKNOWN           ,"Unknown"},
    {IMAGE_FILE_MACHINE_TARGET_HOST       ,"Useful for indicating we want to interact with the host and not a WoW guest."},
    {IMAGE_FILE_MACHINE_I386              ,"Intel 386."},
    {IMAGE_FILE_MACHINE_R3000             ,"MIPS little-endian, 0x160 big-endian"},
    {IMAGE_FILE_MACHINE_R4000             ,"MIPS little-endian"},
    {IMAGE_FILE_MACHINE_R10000            ,"MIPS little-endian"},
    {IMAGE_FILE_MACHINE_WCEMIPSV2         ,"MIPS little-endian WCE v2"},
    {IMAGE_FILE_MACHINE_ALPHA             ,"Alpha_AXP"},
    {IMAGE_FILE_MACHINE_SH3               ,"SH3 little - endian"},
    {IMAGE_FILE_MACHINE_SH3DSP            ,""},
    {IMAGE_FILE_MACHINE_SH3E              ,"SH3E little-endian"},
    {IMAGE_FILE_MACHINE_SH4               ,"SH4 little-endian"},
    {IMAGE_FILE_MACHINE_SH5               ,"SH5"},
    {IMAGE_FILE_MACHINE_ARM               ,"ARM Little-Endian"},
    {IMAGE_FILE_MACHINE_THUMB             ,"ARM Thumb/Thumb-2 Little-Endian"},
    {IMAGE_FILE_MACHINE_ARMNT             ,"ARM Thumb - 2 Little - Endian"},
    {IMAGE_FILE_MACHINE_AM33              ,""},
    {IMAGE_FILE_MACHINE_POWERPC           ,"IBM PowerPC Little - Endian"},
    {IMAGE_FILE_MACHINE_POWERPCFP         ,""},
    {IMAGE_FILE_MACHINE_IA64              ,"Intel 64"},
    {IMAGE_FILE_MACHINE_MIPS16            ,"MIPS"},
    {IMAGE_FILE_MACHINE_ALPHA64           ,"ALPHA64"},
    {IMAGE_FILE_MACHINE_MIPSFPU           ,"MIPS"},
    {IMAGE_FILE_MACHINE_MIPSFPU16         ,"MIPS"},
    {IMAGE_FILE_MACHINE_AXP64             ,"ALPHA64"},
    {IMAGE_FILE_MACHINE_TRICORE           ,"Infineon"},
    {IMAGE_FILE_MACHINE_CEF               ,""},
    {IMAGE_FILE_MACHINE_EBC               ,"EFI Byte Code"},
    {IMAGE_FILE_MACHINE_AMD64             ,"AMD64 (K8)"},
    {IMAGE_FILE_MACHINE_M32R              ,"M32R little-endian"},
    {IMAGE_FILE_MACHINE_ARM64             ,"ARM64 Little - Endian"},
    {IMAGE_FILE_MACHINE_CEE               ,""}
};

const std::map<WORD, const char*> CHARACTERISTICS_DESCRIPTIONS = {
    {IMAGE_FILE_RELOCS_STRIPPED         , "Relocation info stripped from file"},
    {IMAGE_FILE_EXECUTABLE_IMAGE        , "File is executable  (i.e. no unresolved external references)"},
    {IMAGE_FILE_LINE_NUMS_STRIPPED      , "Line numbers stripped from file"},
    {IMAGE_FILE_LOCAL_SYMS_STRIPPED     , "Local symbols stripped from file"},
    {IMAGE_FILE_AGGRESIVE_WS_TRIM       , "Aggressively trim working set"},
    {IMAGE_FILE_LARGE_ADDRESS_AWARE     , "App can handle >2GB addresses"},
    {IMAGE_FILE_BYTES_REVERSED_LO       , "Bytes of machine word are reversed"},
    {IMAGE_FILE_32BIT_MACHINE           , "32 bit word machine"},
    {IMAGE_FILE_DEBUG_STRIPPED          , "Debugging info stripped from file in .DBG file"},
    {IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP , "If Image is on removable media, copy and run from the swap file"},
    {IMAGE_FILE_NET_RUN_FROM_SWAP       , "If Image is on Net, copy and run from the swap file"},
    {IMAGE_FILE_SYSTEM                  , "System File"},
    {IMAGE_FILE_DLL                     , "File is a DLL"},
    {IMAGE_FILE_UP_SYSTEM_ONLY          , "File should only be run on a UP machine"},
    { IMAGE_FILE_BYTES_REVERSED_HI      , "Bytes of machine word are reversed"}
};

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
        explore_nt_headers(file);

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
        ss << "DOS header:\ne_magic:\t" << static_cast<char>(LOBYTE(dos_header.e_magic)) << static_cast<char>(HIBYTE(dos_header.e_magic))
            << " = 0x" << std::hex << dos_header.e_magic
            << "\ne_lfanew:\t0x" << std::hex << dos_header.e_lfanew;
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

    /**
     * \brief Explore the NT headers
     * \param file File pointer
     */
    void explore_nt_headers(FILE* file)
    {
        const PE_TYPE pe_type = get_pe_type(file);
        switch (pe_type)
        {
        case PE64:
            const IMAGE_NT_HEADERS64 nt_headers64 = read_nt_headers_64(file);
            dump_image_file_header(&nt_headers64.FileHeader);
            break;
        case PE32:
            IMAGE_NT_HEADERS32 nt_headers32 = read_nt_headers_32(file);
            break;
        }
    }

    /**
     * \brief Pretty print the IMAGE_FILE_HEADER structure 
     * \param header Pointer to IMAGE_FILE_HEADER structure
     */
    void dump_image_file_header(const IMAGE_FILE_HEADER * const header)
    {
        if (!header)
        {
            throw std::invalid_argument("Invalid file header pointer");
        }
        std::stringstream ss;

        const char * machine_name;
        try
        {
            machine_name = MACHINE_NAMES.at(header->Machine);
        }
        catch (std::out_of_range &)
        {
            machine_name = "Unrecognized machine type";
        }

        ss << "\nFile header\n"
            << "Machine:\t\t"
            << std::setw(2 * sizeof header->Machine) << std::setfill('0') << std::hex << header->Machine
            << "\t\t" << machine_name
            << "\nSections count\t\t"
            << std::setfill('0') << std::hex << header->NumberOfSections
            << "\t\t" << std::dec << header->NumberOfSections
            << "\nTimestamp\t\t"
            << std::setw(2 * sizeof header->TimeDateStamp) << std::setfill('0') << std::hex << header->TimeDateStamp
            << "\t" << app_utils::format_unix_timestamp(header->TimeDateStamp)
            << "Pointer to symbol table\t"
            << std::setw(2 * sizeof header->PointerToSymbolTable) << std::setfill('0') << std::hex << header->PointerToSymbolTable
            << "\t" << std::dec << header->PointerToSymbolTable
            << "\nNumber of symbols\t"
            << std::setw(2 * sizeof header->NumberOfSymbols) << std::setfill('0') << std::hex << header->NumberOfSymbols
            << "\t" << std::dec << header->NumberOfSymbols
            << "\nSize of optional header\t"
            << std::setw(2 * sizeof header->SizeOfOptionalHeader) << std::setfill('0') << std::hex << header->SizeOfOptionalHeader
            << "\t\t" << std::dec << header->SizeOfOptionalHeader
            << "\nCharacteristics:\t\t"
            << std::setw(2 * sizeof header->Characteristics) << std::setfill('0') << std::hex << header->Characteristics;
        for (auto& description : get_characteristics_descriptions(header->Characteristics))
        {
            ss << "\n\t" << description;
        }
        std::cout << ss.str();
    }

    /**
     * \brief Get vector of strings containing human-readable characteristics
     * of the PE file
     * \param characteristics DWORD value
     * \return Vector of strings
     */
    std::vector<std::string> get_characteristics_descriptions(DWORD characteristics)
    {
        std::vector<std::string > descriptions;
        for (auto characteristic : CHARACTERISTICS_DESCRIPTIONS)
        {
            if ((characteristics & characteristic.first) != 0)
            {
                descriptions.emplace_back(characteristic.second);
            }
        }
        return descriptions;
    }
}