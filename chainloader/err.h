#pragma once

#define ERR_FMT(fmt, s, ...)                                    \
    fmt L": %s (%d)\n", ##__VA_ARGS__, efi_statstr(s), s

#define ERROR_RETURN(s, r, fmt, ...)             \
    if( s != EFI_SUCCESS )                       \
    {                                            \
        Print( ERR_FMT(fmt, s, ##__VA_ARGS__) ); \
        return r;                                \
    }

#define WARN_STATUS(s, fmt, ...) \
    if( s != EFI_SUCCESS )                       \
    {                                            \
        Print( ERR_FMT(fmt, s, ##__VA_ARGS__) ); \
    }

#define ERROR_JUMP(s, target, fmt, ...) \
    if( s != EFI_SUCCESS )                       \
    {                                            \
        Print( ERR_FMT(fmt, s, ##__VA_ARGS__) ); \
        goto target;                             \
    }

#define ALLOC_OR_GOTO(s, tgt) \
    ({ VOID *x = efi_alloc( s ); \
       EFI_STATUS stat = (x ? EFI_SUCCESS : EFI_OUT_OF_RESOURCES); \
       ERROR_JUMP( stat, tgt, L"Allocating %d bytes", s );         \
       x; })
