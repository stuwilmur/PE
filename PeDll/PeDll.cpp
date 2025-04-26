#include "pch.h" // use stdafx.h in Visual Studio 2017 and earlier
#include "PeDll.h"

#include <stdexcept>

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