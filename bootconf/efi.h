#pragma once

#include <stdint.h>
#include <string.h>
#include <uchar.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
// #include <unistd.h>

// ==========================================================================
// IMPORTANT NOTE

// We build two types of binary from this source tree: UEFI executables
// (the chainloader itself) and OS utilities (eg steamos-bootconf) for
// managing chainloader metadata.

// We want the metadata parsing and saving tools to share their
// implementations BUT UEFI is not very psox shaped, so these #defines
// are here to allow utility functions with the same signatures to be
// used transparently in both the UEFI and POSIX/ELF implementations
// without changing the parser/etc code.

// This allows chainloader/config.c to be reused in both classes of binary
// with as little duplication/reimplementation as possible:
// ==========================================================================

#define IN
#define OUT
#define CONST const

#define strlen_a(x)     strlen((char *)x)
#define strncmpa(x,y,z) strncmp((char *)x,(char *)y,z)
#define strcmpa(x,y)    strcmp((char *)x,(char *)y)
#define mem_copy(d,s,l) memcpy(d,s,l)
#define efi_alloc(s)    calloc(1, s)
#define efi_free(p)     free(p)

#define EFI_SUCCESS 0
#define EFI_OUT_OF_RESOURCES ENOMEM
#define EFI_END_OF_FILE EIO

typedef unsigned int EFI_STATUS;
typedef void VOID;
typedef unsigned char CHAR8;
typedef uint64_t UINT64;
typedef uint64_t UINTN;
typedef char16_t CHAR16;

int Print(const char16_t *f, ...);

