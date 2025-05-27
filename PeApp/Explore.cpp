#include <sstream>
#include <vector>

#include "PeDll.h"
#include "AppUtils.h"
#include "Explore.h"

#include <iomanip>
#include <iostream>
#include <map>

constexpr int MAX_DOS_STUB_SIZE = 256;
constexpr int MAX_RICH_HEADER_ENTRIES = 100;

const std::map<DWORD, const char*> MACHINE_NAMES = {
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

const std::map<DWORD, const char*> CHARACTERISTICS_DESCRIPTIONS = {
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

const std::map<DWORD, const char*> SUBSYSTEM_DESCIRPTIONS = {
    {IMAGE_SUBSYSTEM_UNKNOWN                 , "Unknown subsystem"},
    {IMAGE_SUBSYSTEM_NATIVE                  , "Image doesn't require a subsystem"},
    {IMAGE_SUBSYSTEM_WINDOWS_GUI             , "Image runs in the Windows GUI subsystem"},
    {IMAGE_SUBSYSTEM_WINDOWS_CUI             , "Image runs in the Windows character subsystem"},
    {IMAGE_SUBSYSTEM_OS2_CUI                 , "Image runs in the OS/2 character subsystem"},
    {IMAGE_SUBSYSTEM_POSIX_CUI               , "Image runs in the Posix character subsystem"},
    {IMAGE_SUBSYSTEM_NATIVE_WINDOWS          , "Image is a native Win9x driver"},
    {IMAGE_SUBSYSTEM_WINDOWS_CE_GUI          , "Image runs in the Windows CE subsystem"},
    {IMAGE_SUBSYSTEM_EFI_APPLICATION         , "EFI application"},
    {IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER , "EFI boot service driver"},
    {IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER      , "EFI runtime driver"},
    {IMAGE_SUBSYSTEM_EFI_ROM                 , "EFI ROM"},
    {IMAGE_SUBSYSTEM_XBOX                    , "XBOX"},
    {IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION, "Windows boot application"},
    {IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG       , "XBOX code catalog"},
};

const std::map<DWORD, const char*> DLL_CHARACTERISTICS_DESCIRPTIONS = {
    {IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA       , "Image can handle a high entropy 64-bit virtual address space."},
    {IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE          , "DLL can move"},
    {IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY       , "Code Integrity Image"},
    {IMAGE_DLLCHARACTERISTICS_NX_COMPAT             , "Image is NX compatible"},
    {IMAGE_DLLCHARACTERISTICS_NO_ISOLATION          , "Image understands isolation and doesn't want it"},
    {IMAGE_DLLCHARACTERISTICS_NO_SEH                , "Image does not use SEH.  No SE handler may reside in this image"},
    {IMAGE_DLLCHARACTERISTICS_NO_BIND               , "Do not bind this image"},
    {IMAGE_DLLCHARACTERISTICS_APPCONTAINER          , "Image should execute in an AppContainer"},
    {IMAGE_DLLCHARACTERISTICS_WDM_DRIVER            , "Driver uses WDM model"},
    {IMAGE_DLLCHARACTERISTICS_GUARD_CF              , "Image supports Control Flow Guard"},
    {IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE , "Terminal server aware"},
};

const std::map<DWORD, const char*> OS_NAMES = {
    { 100, "Windows Server 2016/2019/2022/Windows 10/100"},
    { 63, "Windows Server 2012 R2/Windows 8.1"},
    { 62, "Windows Server 2012/Windows 8"},
    { 61, "Windows Server 2008 R2/Windows 7"},
    { 60, "Windows Vista/Windows Server 2008"},
    { 52, "Windows XP 64 - Bit Edition/Windows Server 2003"},
    { 51, "Windows XP"},
    { 50, "Windows 2000"},
};

const std::map<DWORD, const char*> DATA_DIRECTORY_NAMES = {
    { IMAGE_DIRECTORY_ENTRY_EXPORT        , "Export Directory"},
    { IMAGE_DIRECTORY_ENTRY_IMPORT        , "Import Directory"},
    { IMAGE_DIRECTORY_ENTRY_RESOURCE      , "Resource Directory" },
    { IMAGE_DIRECTORY_ENTRY_EXCEPTION     , "Exception Directory" },
    { IMAGE_DIRECTORY_ENTRY_SECURITY      , "Security Directory" },
    { IMAGE_DIRECTORY_ENTRY_BASERELOC     , "Base Relocation Table" },
    { IMAGE_DIRECTORY_ENTRY_DEBUG         , "Debug Directory" },
    { IMAGE_DIRECTORY_ENTRY_ARCHITECTURE  , "Architecture Specific Data" },
    { IMAGE_DIRECTORY_ENTRY_GLOBALPTR     , "RVA of GP" },
    { IMAGE_DIRECTORY_ENTRY_TLS           , "TLS Directory" },
    { IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG   , "Load Configuration Directory" },
    { IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT  , "Bound Import Directory in headers" },
    { IMAGE_DIRECTORY_ENTRY_IAT           , "Import Address Table" },
    { IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT  , "Delay Load Import Descriptors"},
    { IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, "COM Runtime descriptor" },
};

const std::map<DWORD, const char*> IMAGE_SECTION_CHARACTERISTICS = {
    {IMAGE_SCN_TYPE_NO_PAD, "The section should not be padded to next boundary."},
    {IMAGE_SCN_CNT_CODE, "The section contains executable code."},
    {IMAGE_SCN_CNT_INITIALIZED_DATA, "The section contains initialized data."},
    {IMAGE_SCN_CNT_UNINITIALIZED_DATA, "The section contains uninitialized data."},
    {IMAGE_SCN_LNK_INFO, "The section contains comments or or information" },
    {IMAGE_SCN_LNK_REMOVE, "The section will not become part of the image."},
    {IMAGE_SCN_LNK_COMDAT, "The section contains COMDAT data."},
    {IMAGE_SCN_GPREL, "The section contains data referenced through global pointer (GP)."},
    {IMAGE_SCN_ALIGN_1BYTES, "Align data on a 1-byte boundary."},
    {IMAGE_SCN_ALIGN_2BYTES, "Align data on a 2-byte boundary."},
    {IMAGE_SCN_ALIGN_4BYTES, "Align data on a 4-byte boundary."},
    {IMAGE_SCN_ALIGN_8BYTES, "Align data on an 8-byte boundary."},
    {IMAGE_SCN_ALIGN_16BYTES, "Align data on a 16-byte boundary."},
    {IMAGE_SCN_ALIGN_32BYTES, "Align data on a 32-byte boundary."},
    {IMAGE_SCN_ALIGN_64BYTES, "Align data on a 64-byte boundary."},
    {IMAGE_SCN_ALIGN_128BYTES, "Align data on a 128-byte boundary."},
    {IMAGE_SCN_ALIGN_256BYTES, "Align data on a 256-byte boundary."},
    {IMAGE_SCN_ALIGN_512BYTES, "Align data on a 512-byte boundary."},
    {IMAGE_SCN_ALIGN_1024BYTES, "Align data on a 1024-byte boundary."},
    {IMAGE_SCN_ALIGN_2048BYTES, "Align data on a 2048-byte boundary."},
    {IMAGE_SCN_ALIGN_4096BYTES, "Align data on a 4096-byte boundary."},
    {IMAGE_SCN_ALIGN_8192BYTES, "Align data on an 8192-byte boundary."},
    {IMAGE_SCN_LNK_NRELOC_OVFL, "The section contains extended relocations."},
    {IMAGE_SCN_MEM_DISCARDABLE, "The section can be discarded as needed."},
    {IMAGE_SCN_MEM_NOT_CACHED, "The section cannot be cached."},
    {IMAGE_SCN_MEM_NOT_PAGED, "The section is not pageable."},
    {IMAGE_SCN_MEM_SHARED, "The section can be shared in memory."},
    {IMAGE_SCN_MEM_EXECUTE, "The section can be executed as code."},
    {IMAGE_SCN_MEM_READ, "The section can be read."},
    {IMAGE_SCN_MEM_WRITE, "The section can be written to."},
};

namespace explore
{
    /**
     * \brief Explore the PE file
     */
    void explore_pe(FILE* file)
    {
        if (!file)
        {
            throw std::invalid_argument("Invalid file pointer");
        }

        std::cout << "PE info\n========\n\n";

        explore_dos_header(file);
        explore_dos_stub(file);
        explore_rich_header(file);
        explore_nt_headers(file);
        explore_image_section_headers(file);
        explore_import_directory_table(file);
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
        ss << "DOS header:\n\ne_magic:\t" << static_cast<char>(LOBYTE(dos_header.e_magic)) << static_cast<char>(HIBYTE(dos_header.e_magic))
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

        std::cout << "\n\nDOS stub (ASCII):\n\n";
        dump_bytes(&dos_stub, app_utils::ascii_format);
        std::cout << "\n\nDOS stub (hex):\n\n";
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
        ss << "\n\nRich header entries info:\n\n";
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
            std::cout << std::endl;
            dump_image_optional_header64(&nt_headers64.OptionalHeader);
            break;
        case PE32:
            const IMAGE_NT_HEADERS32 nt_headers32 = read_nt_headers_32(file);
            std::cout << std::endl;
            dump_image_optional_header32(&nt_headers32.OptionalHeader);
            break;
        }
    }

    /**
     * \brief Explore the image section headers
     * \param file File pointer
     */
    void explore_image_section_headers(FILE* file)
    {
        if (!file)
        {
            throw std::invalid_argument("Invalid file pointer");
        }

        const WORD number_of_section_headers = get_number_image_section_headers(file);
        const auto allocated_size = static_cast<size_t>(number_of_section_headers * 2);
        std::vector<IMAGE_SECTION_HEADER> image_section_headers(allocated_size);
        const size_t number_of_read_section_headers = read_image_section_headers(file, image_section_headers.data(), allocated_size);
        image_section_headers.resize(number_of_read_section_headers);

        std::cout << "\n\nImage section headers:\n\n";
        for (auto image_section_header : image_section_headers)
        {
            dump_image_section_header(&image_section_header);
            std::cout << "\n\n";
        }
    }

    /**
     * \brief Explore the import directory table
     * \param file File pointer
     */
    void explore_import_directory_table(FILE* file)
    {
        if (!file)
        {
            throw std::invalid_argument("Invalid file pointer");
        }

        constexpr int MAX_NUM_IMAGE_SECTION_HEADERS = 20;

        std::vector<IMAGE_IMPORT_DESCRIPTOR> image_import_descriptors(MAX_NUM_IMAGE_SECTION_HEADERS);
        const size_t number_read_image_import_descriptors = read_import_directory_table(file, image_import_descriptors.data(), MAX_NUM_IMAGE_SECTION_HEADERS);
        image_import_descriptors.resize(number_read_image_import_descriptors);

        std::cout << "\nImage import descriptors:";
        for (const auto &image_import_descriptor : image_import_descriptors)
        {
            std::cout << "\n\n";
            dump_image_import_descriptor(&image_import_descriptor);
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

        ss << "\nFile header:\n\n"
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
        for (auto& description : get_characteristics_descriptions(header->Characteristics, &CHARACTERISTICS_DESCRIPTIONS))
        {
            ss << "\n\t" << description;
        }
        std::cout << ss.str();
    }

    /**
     * \brief Pretty print the 32-bit optional header information
     * \param header Pointer to a IMAGE_OPTIONAL_HEADER32
     */
    void dump_image_optional_header32(const IMAGE_OPTIONAL_HEADER32* const header)
    {
        if (!header)
        {
            throw std::invalid_argument("Invalid optional header pointer");
        }
        std::stringstream ss;

        const char* os_name;
        try
        {
            os_name = OS_NAMES.at(header->MajorOperatingSystemVersion);
        }
        catch (std::out_of_range&)
        {
            os_name = "Unrecognized OS";
        }

        const char* subsystem_description;
        try
        {
            subsystem_description = SUBSYSTEM_DESCIRPTIONS.at(header->Subsystem);
        }
        catch (std::out_of_range&)
        {
            subsystem_description = "Unrecognized subsytem";
        }

        ss << "\nOptional Header:\n\n"
            << "Magic:\t\t\t"
            << std::setw(2 * sizeof header->Magic) << std::setfill('0') << std::hex << header->Magic
            << "\t" << (header->Magic == 0x10 ? "NT32" : "NT64")
            << "\nMajor Linker Version:\t"
            << std::dec << static_cast<int>(header->MajorLinkerVersion)
            << "\nMinor Linker Version:\t"
            << std::dec << static_cast<int>(header->MinorLinkerVersion)
            << "\nSize of Code:\t\t"
            << std::setw(2 * sizeof header->SizeOfCode) << std::setfill('0') << std::hex << header->SizeOfCode
            << "\nSize of Initialized Data:\t"
            << std::setw(2 * sizeof header->SizeOfInitializedData) << std::setfill('0') << std::hex << header->SizeOfInitializedData
            << "\nSize of Uninitialized Data:\t"
            << std::setw(2 * sizeof header->SizeOfUninitializedData) << std::setfill('0') << std::hex << header->SizeOfUninitializedData
            << "\nAddress of Entry Point:\t"
            << std::setw(2 * sizeof header->AddressOfEntryPoint) << std::setfill('0') << std::hex << header->AddressOfEntryPoint
            << "\nBase of Code:\t\t"
            << std::setw(2 * sizeof header->BaseOfCode) << std::setfill('0') << std::hex << header->BaseOfCode
            << "\nBase of Data:\t\t"
            << std::setw(2 * sizeof header->BaseOfData) << std::setfill('0') << std::hex << header->BaseOfData
            << "\nImage Base:\t\t"
            << std::setw(2 * sizeof header->ImageBase) << std::setfill('0') << std::hex << header->ImageBase
            << "\nSection Alignment:\t"
            << std::setw(2 * sizeof header->SectionAlignment) << std::setfill('0') << std::hex << header->SectionAlignment
            << "\nFile Alignment:\t\t"
            << std::setw(2 * sizeof header->FileAlignment) << std::setfill('0') << std::hex << header->FileAlignment
            << "\nMajor OS Version:\t"
            << std::dec << header->MajorOperatingSystemVersion
            << os_name
            << "\nMinor OS Version:\t"
            << std::dec << header->MinorOperatingSystemVersion
            << "\nMajor Image Version:\t"
            << std::dec << header->MajorImageVersion
            << "\nMinor Image Version:\t"
            << std::dec << header->MinorImageVersion
            << "\nMajor Subsystem Version:\t"
            << std::dec << header->MajorSubsystemVersion
            << "\nMinor Subsystem Version:\t"
            << std::dec << header->MinorSubsystemVersion
            << "\nWin32 Version Value:\t"
            << std::setw(2 * sizeof header->Win32VersionValue) << std::setfill('0') << std::hex << header->Win32VersionValue
            << "\nSize of Image:\t\t"
            << std::setw(2 * sizeof header->SizeOfImage) << std::setfill('0') << std::hex << header->SizeOfImage
            << "\nSize of Headers:\t"
            << std::setw(2 * sizeof header->SizeOfHeaders) << std::setfill('0') << std::hex << header->SizeOfHeaders
            << "\nChecksum:\t\t"
            << std::setw(2 * sizeof header->CheckSum) << std::setfill('0') << std::hex << header->CheckSum
            << "\nSubsystem:\t\t"
            << std::setw(2 * sizeof header->Subsystem) << std::setfill('0') << std::hex << header->Subsystem
            << "\t" << subsystem_description
            << "\nDLL Characteristics:\t"
            << std::setw(2 * sizeof header->DllCharacteristics) << std::setfill('0') << std::hex << header->DllCharacteristics;

        for (auto& description : get_characteristics_descriptions(header->DllCharacteristics, &DLL_CHARACTERISTICS_DESCIRPTIONS))
        {
            ss << "\n\t" << description;
        }

        ss << "\nSize of Stack Reserve:\t"
            << std::setw(2 * sizeof header->SizeOfStackReserve) << std::setfill('0') << std::hex << header->SizeOfStackReserve
            << "\nSize of Stack Commit:\t"
            << std::setw(2 * sizeof header->SizeOfStackCommit) << std::setfill('0') << std::hex << header->SizeOfStackCommit
            << "\nSize of Heap Reserve:\t"
            << std::setw(2 * sizeof header->SizeOfHeapReserve) << std::setfill('0') << std::hex << header->SizeOfHeapReserve
            << "\nSize of Heap Commit:\t"
            << std::setw(2 * sizeof header->SizeOfHeapCommit) << std::setfill('0') << std::hex << header->SizeOfHeapCommit
            << "\nLoader Flags:\t\t"
            << std::setw(2 * sizeof header->LoaderFlags) << std::setfill('0') << std::hex << header->LoaderFlags
            << "\nNumber of RVA and Sizes:\t"
            << std::setw(2 * sizeof header->NumberOfRvaAndSizes) << std::setfill('0') << std::hex << header->NumberOfRvaAndSizes;

        for (unsigned short i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i)
        {
            const char* data_directory_name;
            try
            {
                data_directory_name = DATA_DIRECTORY_NAMES.at(i);
            }
            catch (std::out_of_range&)
            {
                data_directory_name = "Unrecognized data directory";
            }
            ss << "\nData Directory[" << i << "]" << std::setw(35) << std::setfill(' ') << data_directory_name << "\t"
                << "RVA: " << std::setw(2 * sizeof header->DataDirectory[i].VirtualAddress) << std::setfill('0') << std::hex << header->DataDirectory[i].VirtualAddress
                << "\tSize: " << std::setw(2 * sizeof header->DataDirectory[i].Size) << std::setfill('0') << std::hex << header->DataDirectory[i].Size;
        }

        std::cout << ss.str();
    }

    /**
     * \brief Pretty print the 64-bit optional header information
     * \param header Pointer to a IMAGE_OPTIONAL_HEADER64
     */
    void dump_image_optional_header64(const IMAGE_OPTIONAL_HEADER64* const header)
    {
        if (!header)
        {
            throw std::invalid_argument("Invalid optional header pointer");
        }
        std::stringstream ss;

        const char* os_name;
        try
        {
            os_name = OS_NAMES.at(header->MajorOperatingSystemVersion * 10 + header->MinorOperatingSystemVersion);
        }
        catch (std::out_of_range&)
        {
            os_name = "Unrecognized OS";
        }

        const char* subsystem_description;
        try
        {
            subsystem_description = SUBSYSTEM_DESCIRPTIONS.at(header->Subsystem);
        }
        catch (std::out_of_range&)
        {
            subsystem_description = "Unrecognized subsytem";
        }

        ss << "\nOptional Header (64-bit):\n\n"
            << "Magic:\t\t\t"
            << std::setw(2 * sizeof header->Magic) << std::setfill('0') << std::hex << header->Magic
            << "\t" << (header->Magic == 0x10 ? "NT32" : "NT64")
            << "\nMajor Linker Version:\t"
            << std::dec << static_cast<int>(header->MajorLinkerVersion)
            << "\nMinor Linker Version:\t"
            << std::dec << static_cast<int>(header->MinorLinkerVersion)
            << "\nSize of Code:\t\t"
            << std::setw(2 * sizeof header->SizeOfCode) << std::setfill('0') << std::hex << header->SizeOfCode
            << "\nSize of Initialized Data:\t"
            << std::setw(2 * sizeof header->SizeOfInitializedData) << std::setfill('0') << std::hex << header->SizeOfInitializedData
            << "\nSize of Uninitialized Data:\t"
            << std::setw(2 * sizeof header->SizeOfUninitializedData) << std::setfill('0') << std::hex << header->SizeOfUninitializedData
            << "\nAddress of Entry Point:\t"
            << std::setw(2 * sizeof header->AddressOfEntryPoint) << std::setfill('0') << std::hex << header->AddressOfEntryPoint
            << "\nBase of Code:\t\t"
            << std::setw(2 * sizeof header->BaseOfCode) << std::setfill('0') << std::hex << header->BaseOfCode
            << "\nImage Base:\t\t"
            << std::setw(2 * sizeof header->ImageBase) << std::setfill('0') << std::hex << header->ImageBase
            << "\nSection Alignment:\t"
            << std::setw(2 * sizeof header->SectionAlignment) << std::setfill('0') << std::hex << header->SectionAlignment
            << "\nFile Alignment:\t\t"
            << std::setw(2 * sizeof header->FileAlignment) << std::setfill('0') << std::hex << header->FileAlignment
            << "\nMajor OS Version:\t"
            << std::dec << header->MajorOperatingSystemVersion
            << "\nMinor OS Version:\t"
            << std::dec << header->MinorOperatingSystemVersion
            << "\n\t" << os_name
            << "\nMajor Image Version:\t"
            << std::dec << header->MajorImageVersion
            << "\nMinor Image Version:\t"
            << std::dec << header->MinorImageVersion
            << "\nMajor Subsystem Version:\t"
            << std::dec << header->MajorSubsystemVersion
            << "\nMinor Subsystem Version:\t"
            << std::dec << header->MinorSubsystemVersion
            << "\nWin32 Version Value:\t"
            << std::setw(2 * sizeof header->Win32VersionValue) << std::setfill('0') << std::hex << header->Win32VersionValue
            << "\nSize of Image:\t\t"
            << std::setw(2 * sizeof header->SizeOfImage) << std::setfill('0') << std::hex << header->SizeOfImage
            << "\nSize of Headers:\t"
            << std::setw(2 * sizeof header->SizeOfHeaders) << std::setfill('0') << std::hex << header->SizeOfHeaders
            << "\nChecksum:\t\t"
            << std::setw(2 * sizeof header->CheckSum) << std::setfill('0') << std::hex << header->CheckSum
            << "\nSubsystem:\t\t"
            << std::setw(2 * sizeof header->Subsystem) << std::setfill('0') << std::hex << header->Subsystem
            << "\t" << subsystem_description
            << "\nDLL Characteristics:\t"
            << std::setw(2 * sizeof header->DllCharacteristics) << std::setfill('0') << std::hex << header->DllCharacteristics;

        for (auto& description : get_characteristics_descriptions(header->DllCharacteristics, &DLL_CHARACTERISTICS_DESCIRPTIONS))
            {
                ss << "\n\t" << description;
            }

        ss << "\nSize of Stack Reserve:\t"
            << std::setw(2 * sizeof header->SizeOfStackReserve) << std::setfill('0') << std::hex << header->SizeOfStackReserve
            << "\nSize of Stack Commit:\t"
            << std::setw(2 * sizeof header->SizeOfStackCommit) << std::setfill('0') << std::hex << header->SizeOfStackCommit
            << "\nSize of Heap Reserve:\t"
            << std::setw(2 * sizeof header->SizeOfHeapReserve) << std::setfill('0') << std::hex << header->SizeOfHeapReserve
            << "\nSize of Heap Commit:\t"
            << std::setw(2 * sizeof header->SizeOfHeapCommit) << std::setfill('0') << std::hex << header->SizeOfHeapCommit
            << "\nLoader Flags:\t\t"
            << std::setw(2 * sizeof header->LoaderFlags) << std::setfill('0') << std::hex << header->LoaderFlags
            << "\nNumber of RVA and Sizes:\t"
            << std::setw(2 * sizeof header->NumberOfRvaAndSizes) << std::setfill('0') << std::hex << header->NumberOfRvaAndSizes;

        for (unsigned short i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i)
        {
            const char * data_directory_name;
            try
            {
                data_directory_name = DATA_DIRECTORY_NAMES.at(i);
            }
            catch (std::out_of_range&)
            {
                data_directory_name = "Unrecognized data directory";
            }
            ss << "\nData Directory[" << i << "]" << std::setw(35) << std::setfill(' ') << data_directory_name << "\t"
                << "RVA: " << std::setw(2 * sizeof header->DataDirectory[i].VirtualAddress) << std::setfill('0') << std::hex << header->DataDirectory[i].VirtualAddress
                << "\tSize: " << std::setw(2 * sizeof header->DataDirectory[i].Size) << std::setfill('0') << std::hex << header->DataDirectory[i].Size;
        }

        std::cout << ss.str();
    }

    /**
     * \brief Pretty print an individual image section header
     * \param header Pointer to an IMAGE_SECTION_HEADER
     */
    void dump_image_section_header(const IMAGE_SECTION_HEADER* header)
    {
        if (!header)
        {
            throw std::invalid_argument("Invalid image section header pointer");
        }
        
        std::stringstream ss;
        ss << header->Name << "\n";

        constexpr int labelWidth = 24;

        ss << std::left
            << std::setw(labelWidth) << "VirtualSize:" << std::hex << std::setw(8) << std::setfill(' ') << header->Misc.VirtualSize << "\n"
            << std::setw(labelWidth) << "VirtualAddress:" << std::hex << std::setw(8) << std::setfill(' ') << header->VirtualAddress << "\n"
            << std::setw(labelWidth) << "SizeOfRawData:" << std::hex << std::setw(8) << std::setfill(' ') << header->SizeOfRawData << "\n"
            << std::setw(labelWidth) << "PointerToRawData:" << std::hex << std::setw(8) << std::setfill(' ') << header->PointerToRawData << "\n"
            << std::setw(labelWidth) << "PointerToRelocations:" << std::hex << std::setw(8) << std::setfill(' ') << header->PointerToRelocations << "\n"
            << std::setw(labelWidth) << "PointerToLinenumbers:" << std::hex << std::setw(8) << std::setfill(' ') << header->PointerToLinenumbers << "\n"
            << std::setw(labelWidth) << "NumberOfRelocations:" << std::hex << std::setw(8) << std::setfill(' ') << header->NumberOfRelocations << "\n"
            << std::setw(labelWidth) << "NumberOfLinenumbers:" << std::hex << std::setw(8) << std::setfill(' ') << header->NumberOfLinenumbers << "\n"
            << std::setw(labelWidth) << "Characteristics:" << std::hex << std::setw(8) << std::setfill(' ') << header->Characteristics;

        for (auto& description : get_characteristics_descriptions(header->Characteristics, &IMAGE_SECTION_CHARACTERISTICS))
        {
            ss << "\n\t" << description;
        }

        std::cout << ss.str();

    }

    /**
     * \brief Pretty print an import image descriptor
     * \param descriptor Pointer to IMAGE_IMPORT_DESCRIPTOR
     */
    void dump_image_import_descriptor(const IMAGE_IMPORT_DESCRIPTOR* descriptor)
    {
        if (!descriptor)
        {
            throw std::invalid_argument("Invalid image import descriptor pointer");
        }

        std::stringstream ss;

        constexpr int labelWidth = 24;

        ss << std::left
            << std::setw(labelWidth) << "Name:" << std::hex << std::setw(8) << std::setfill(' ') << descriptor->Name << "\n"
            << std::setw(labelWidth) << "OriginalFirstThunk:" << std::hex << std::setw(8) << std::setfill(' ') << descriptor->OriginalFirstThunk << "\n"
            << std::setw(labelWidth) << "TimeDateStamp:" << std::hex << std::setw(8) << std::setfill(' ') << descriptor->TimeDateStamp << "\n"
            << std::setw(labelWidth) << "ForwarderChain:" << std::hex << std::setw(8) << std::setfill(' ') << descriptor->ForwarderChain << "\n"
            << std::setw(labelWidth) << "FirstThunk:" << std::hex << std::setw(8) << std::setfill(' ') << descriptor->FirstThunk;

        std::cout << ss.str();
    }
    
    /**
     * \brief Get vector of strings containing human-readable characteristics
     * of the PE file
     * \param characteristics DWORD value
     * \param descriptions Map containing key-description pairs
     * \return Vector of strings
     */
    std::vector<std::string> get_characteristics_descriptions(const DWORD characteristics, const std::map<DWORD, const char*>* descriptions)
    {
        std::vector<std::string > matched_descriptions;
        for (auto characteristic : *descriptions)
        {
            if ((characteristics & characteristic.first) != 0)
            {
                matched_descriptions.emplace_back(characteristic.second);
            }
        }
        return matched_descriptions;
    }
}