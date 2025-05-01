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
    if (!file) {
        throw std::invalid_argument("Invalid file pointer");
    }

    // Get the length of the file
    if (fseek(file, 0, SEEK_END) != 0) {
        throw std::runtime_error("Can't seek to end of file");
    }
    off_t file_length = ftell(file);
    if (file_length == -1) {
        throw std::runtime_error("Can't determine file length");
    }

    // Check if the offset is beyond the end of the file
    if (offset > file_length) {
        std::stringstream ss;
        ss << "Can't seek: offset=" << offset << " is greater than file length=" << file_length;
        throw std::runtime_error(ss.str());
    }

    // Seek to the specified offset
    if (fseek(file, offset, SEEK_SET) != 0) {
        std::stringstream ss;
        ss << "Can't seek: offset=" << offset;
        throw std::runtime_error(ss.str());
    }
}

