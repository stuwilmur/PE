# PE
## No, not Physical Education, but certainly mental exercise
The PE (Portable Executable) format is used by executables, object code, dynamic-link-libraries (DLLs), and binary files on 32-bit and 64-bit Windows operating systems. These notes accompany Ahmed Hesham's excellent guide [*A dive into the PE file format*](https://0xrick.github.io/win-internals/pe1/). They document my process of learning about the PE format (and by doing so, trying to relearn some C++), by developing some simple software for parsing PE files as I progress through the guide. The intention is not to develop robust software to interrogate PE files: existing software is available that does this much better. Instead, this is very much a project intended for my own educational benefit, while others may potentially find the odd detail useful.

## Contents
1. [Project code overview](./Docs/project.md)
1. [DOS header](./Docs/dos_header.md)
1. [DOS stub and Rich header](./Docs/dos_stub_rich_header.md)


