# Project code overview
Let's set up a simple Visual Studio solution to develop an application for parsing PE files.
![The project as seen in the Solution Explorer](img/solution_projects.png "The project as seen in the Solution Explorer")

The solution has four projects:
- **ExampleDll**: this is a simple DLL which is built with the project. We will use it as an example of a file whose PE format may be read.
- **PeClient**: the main application which will be used to read and parse PE files; here a simple console app. It is a client of PeDll.
- **PeDll**: a DLL which exposes all the functions which we will develop to parse PE files. This way, they may be used by clients other than PeClient.
- **PeLib**: a C static library, designed to allow us to easily use existing C functions for handling PE files. This is a dependency of PeDLL.

Let's look at the skeleton of each project in turn, to see how they are set up.

## ExampleDll
ExampleDll is a very simple DLL, which we can use as a test input for our PE parsing code. It exposes a single function, with signature `void fn()`.
### Header files
- **ExampleDll.h** declares the exposed function `pedll::fn` which is declared`extern "C"` to give it C linkage, and `__declspec(dllexport)` to export it, i.e. to allow the symbol to be loaded dynamically at runtime;
- **framework.h** declares some standard Windows stuff;
- **pch.h** defines some standard precompiled header stuff.
### Source files
- **dllmain.cpp** defines the standard DLL entry point function, `DllMain`, which Visual Studio helpfully supplies for us;
- **ExampleDll.cpp** defines `pedll::fn`; it is just a stub i.e. does nothing;
- **pch.cpp** is necessary for the precompiled header stuff in pch.h to compile.

## PeClient
This is the main application, which will open, read and parse our ExampleDll DLL. As such, it includes the application entry point `main` function.
### Header files
- **AppUtils.h** declares utility functions that are application-specific. This saves bloating PeDll with functions that it doesn't need;
- **Explore.h** functions for exploring the PE file.
### Source files
- **AppUtils.cpp** defines the utility functions;
- **Explore.cpp** defines the exploratory functions;
- **PeApp.cpp** defines the entry point, with signature `int main()`. This function will call functions in Explore.cpp to open and read the PE file, parse it, and display some of PE information.

## PeDll
This DLL exposes all the functions which we will develop to parse PE files. As such, it may be linked and used by clients other than PeClient.
### Header files
- **framework.h** declares standard Windows stuff;
- **pch.h** declares standard precompiled headers stuff;
- **PeDll.h** declares all the DLL's exposed functions, each suitably declared `extern "C" __declspec(dllexport)`. This is where we will declare all the the interface functions which clients can use to read and parse PE files;
- **Utils.h** delcares a set of utlity functions for reading and parsing PE files.
### Source files
- **dllmain.cpp** defines the standard DLL entry point function, `DllMain`;
- **pch.cpp** is necessary for the precompiled header stuff in pch.h to compile;
- **PeDll.cpp** is where the PeDll interface functions declared in PeDll.h will be defined;
- **Utils.cpp** includes definitions for the utility functions declared in utils.h.

## PeLib
This static library defines C functions useful for reading and parsing PE files: it is linked by PeDll.
### Header files
- **framework.h** declares standard Windows stuff;
- **pch.h** declares standard precompiled headers stuff;
- **PeLib.h** declares the library functions, each suitably declared `extern "C"` (but not `__declspec(dllexport)`, since we don't need to export them).
### Source files
- **pch.c** is necessary for the precompiled header stuff in pch.h to compile;
- **PeLib.c** contains the definitions for functions delcared in PeLib.h.

## Settings
- The C++ projects target C++14, which is the default; the choice of C compiler is also left as the default (Legacy MSVC, which targets ANSI C89);
- in order for PeClient to include header files found in PeDLL, we must add /PeDLL as an additional include directory in the PeClient project settings. Similarly, PeDll must add /PeLib as an additional include directory:\
!["PeClient additional include directories"](img/peclient_additional_includes.png "PeClient additional include directories")
- PeClient has PeDLL added as a project reference:\
![PeDll as a project reference of PeClient](img/peclient_project_reference.png "PeDll as a project reference of PeClient")
- Default solution configurations Debug and Release are left as they are: note that in Debug, the preprocessor macro `_DEBUG` is defined, which allows us to define debug-specific code. Solution platforms are left as x64 and x86.

