#include "pch.h" // use stdafx.h in Visual Studio 2017 and earlier
#include "PeDll.h"
#include "PeLib.h"
#include "utils.h"

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
    _IMAGE_DOS_HEADER dos_header {};
    fread_s(&dos_header, sizeof(_IMAGE_DOS_HEADER), sizeof(_IMAGE_DOS_HEADER), 1, pe_file);

    return dos_header;
}