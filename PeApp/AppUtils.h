#pragma once

#include <windows.h>
#include <string>

int get_abs_path_from_filename(WCHAR*, const WCHAR*, DWORD);

std::string wchar_t_buffer_to_string(const WCHAR*);
