# NT headers
Found immediately after the DOS stub, the NT headers are where we start to learn interesting information about a PE file. The headers may be represented by one of two structs, depending on whether the file is a 32- or 64-bit PE file:
```C++
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
```
We need to work out the file type before reading the NT header bytes into the appropriate struct. The optional header is where we look for this information. At the start of this header we see the following:
```C++
typedef struct _IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //

    WORD    Magic;
```
Here Magic indicates the file type:
- 0x10: PE32 executable;
- 0x20: PE32+ executable.

The function `get_pe_type` works out the file type by reading `Magic`. To do so it must calculate the offset to this `WORD`: we know the start of the NT headers is at `e_lfanew` in `_IMAGE_DOS_HEADER`, and from there we to skip over four bytes for the `Signature`, plus the number of bytes in `IMAGE_FILE_HEADER`, before reaching the offset from which to read `Magic`.

Having got the PE type, we can call appropriate functions `read_nt_headers_32` and `read_nt_headers_64` which read the header bytes to the appropriate structure.

## Exploring the `IMAGE_FILE_HEADER`
This structure contains lots of interesting information; let's add a function `dump_image_file_header` to dump it in a nice format to examine it a bit further. The structure looks like this:
```C++
typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```
Taking each in turn:
- `Machine`: an ID indicating the machine architecture, which are specified using macros in winnt.h. These macros each have a helpful description, so I decided to print this as well. To do this, we can define `const std::map<WORD, const char*> MACHINE_NAMES` which associates each ID with a description string;
- `NumberOfSections`: numerical value;
- `TimeDateStamp`: this is a UNIX timestamp; we define a helper function `app_utils::_format_unix_timestamp` to format this as a human-readable datetime using the standard function `ctime_s`;
- `PointerToSymbolTable`: an address;
- `NumberOfSymbols`: numerical value;
- `SizeOfOptionalHeader`: numerical value;
- `Characteristics`: a two-byte bitflag, which encodes a number of characteristics which the PE file may have. To pretty print them, we first get a vector of string descriptions of all applicable characteristics using the helper function `get_characteristics_descriptions`: this simply loops over all bits in the characteristics and if a bit is set, adds the relevant description (drawn from a map as with the machine names) string to a vector.

