
#include "AppUtils.h"
#include <PathCch.h>
#include <libloaderapi.h>
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
    int get_abs_path_from_filename(WCHAR* buffer, const WCHAR* file_name, DWORD buffer_length)
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
        size_t convertedChars = 0;
        if (wcstombs_s(&convertedChars, char_vec.data(), newsize, buffer, _TRUNCATE) != 0)
        {
            throw std::runtime_error("wcstombs_s failed to convert buffer of wchar_t");
        }

        // Return a string created from the vector
        return std::string(char_vec.data());
    }
}
