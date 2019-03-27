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

// definitions so we can reuse chainloader/config.c with as little
// duplication/reimplementation as possible:

#define IN
#define OUT
#define CONST const

#define strlena(x)      strlen((char *)x)
#define strncmpa(x,y,z) strncmp((char *)x,(char *)y,z)
#define strcmpa(x,y)    strcmp((char *)x,(char *)y)
#define CopyMem(d,s,l)  memcpy(d,s,l)
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

