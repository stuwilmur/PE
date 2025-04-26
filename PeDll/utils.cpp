#include "pch.h"
#include "Utils.h"
#include <sstream>
#include <stdexcept>

/**
 * \brief Safe wrapper for fseek; throws an exception
 * if fseek fails for any reason, and in addition checks
 * that a seek is not requested beyond EOF.
 * \param file File pointer of file in which to seek
 * \param offset Offset
 */
void safe_seek(FILE* file, off_t offset) {
    if (fseek(file, 0, SEEK_END) != 0)
    {
        throw std::runtime_error("Can't seek to end of file");
    }
    off_t file_length = ftell(file);

    if (file_length < offset) {
        std::stringstream ss;
        ss << "Can't seek: offset=" << offset << " is greater than file length=" << file_length;
        throw std::runtime_error(ss.str());
    }

    if (fseek(file, offset, SEEK_SET) != 0)
    {
        std::stringstream ss;
        ss << "Can't seek: offset=" << offset;
        throw std::runtime_error(ss.str());
    }
}
