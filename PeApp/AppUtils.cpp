
#include "AppUtils.h"

#include <iomanip>
#include <iostream>
#include <PathCch.h>
#include <libloaderapi.h>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <string>

namespace app_utils {
    /**
     * \brief Get the absolute path of a file that is located in the
     * same directory as the currently executing module
     * \param buffer String buffer that will hold the generated absolute path
     * \param file_name The name of the file
     * \param buffer_length Length of buffer
     * \return 0 if no error, otherwise 1
     */
    int get_abs_path_from_filename(WCHAR* buffer, const WCHAR* file_name, const DWORD buffer_length)
    {
        // Get the full absolute path of the current module
        if (GetModuleFileName(nullptr, buffer, buffer_length) == 0)
            return 1;

        // Strip the module file name
        if (PathCchRemoveFileSpec(buffer, buffer_length) != S_OK)
            return 1;

        // Append the supplied file name
        if (PathCchAppend(buffer, buffer_length, file_name) != S_OK)
            return 1;

        return 0;
    }

    /**
     * \brief Convert a buffer of WCHAR to a std::string
     * \param buffer Buffer to convert
     * \return The resulting converted string
     */
    std::string wchar_t_buffer_to_string(const WCHAR* buffer)
    {
        if (!buffer)
        {
            throw std::invalid_argument("Invalid buffer pointer");
        }

        // Calculate the required size for the multibyte string,
        // adding one to account for the null-terminating character,
        // and up to two bytes per character
        size_t origsize = wcslen(buffer) + 1;
        size_t newsize = origsize * 2;
        std::vector<char> char_vec(newsize);

        // Convert the wide-character string to a multibyte string
        size_t converted_chars = 0;
        if (wcstombs_s(&converted_chars, char_vec.data(), newsize, buffer, _TRUNCATE) != 0)
        {
            throw std::runtime_error("wcstombs_s failed to convert buffer of wchar_t");
        }

        // Return a string created from the vector
        return { char_vec.data() };
    }

    /**
     * \brief Output a set of bytes in either ASCII or hex
     * \param buffer Pointer to vector of bytes
     * \param format Format specifier
     */
    void dump_bytes(const std::vector<uint8_t>* buffer, const dump_format format)
    {
        std::stringstream ss;
        int byte_count = 0;
        for (const auto byte : *buffer)
        {
            constexpr int LINE_LENGTH = 16;
            if (byte_count % LINE_LENGTH == 0)
            {
                ss << std::hex << byte_count << "\t|\t";
            }
            if (format == hex_format || !isprint(byte))
            {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
            }
            else
            {
                ss << std::setw(2) << std::setfill(' ') << static_cast<char>(byte);
            }
            if (byte_count % LINE_LENGTH == LINE_LENGTH - 1)
            {
                ss << "\n";
            }
            else
            {
                ss << " ";
            }
            byte_count++;
        }
        std::cout << ss.str();
    }

    /**
     * \brief Format a UNIX timestamp as a string
     * \param time Timestamp
     * \return Datetime string
     */
    std::string format_unix_timestamp(time_t time)
    {
        char formatted_time[100];

        const size_t result = ctime_s(formatted_time, sizeof(formatted_time), &time);

        if (result == 0) {
            return { formatted_time };
        }
        throw std::runtime_error("Error formatting timestamp");
    }
}
