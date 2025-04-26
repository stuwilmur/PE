#include "AppUtils.h"
#include <PathCch.h>
#include <libloaderapi.h>
#include <stdexcept>
#include <vector>

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
        // First, get the full absolute path of the current module
        if (GetModuleFileName(0, buffer, buffer_length) == 0)
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
        // Convert the wchar_t string to a char* string. Record
        // the length of the original string and add 1 to it to
        // account for the terminating null character.
        size_t origsize = wcslen(buffer) + 1;
        size_t convertedChars = 0;

        // Allocate two bytes in the multibyte output string for every wide
        // character in the input string (including a wide character
        // null). Because a multibyte character can be one or two bytes,
        // you should allot two bytes for each character. Having extra
        // space for the new string isn't an error, but having
        // insufficient space is a potential security problem.
        const size_t newsize = origsize * 2;
        std::vector<char> char_vec;
        char_vec.reserve(newsize);

        // Put a copy of the converted string into char_vec
        if (wcstombs_s(&convertedChars, char_vec.data(), newsize, buffer, _TRUNCATE) != 0)
        {
            throw std::runtime_error("wcstombs_s failed to convert buffer of wchar_t");
        }

        // Return a string created from the vector
        return std::string(char_vec.data());
    }
}
