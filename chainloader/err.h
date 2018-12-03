#pragma once

#define ERR_FMT(fmt, s, ...)                                    \
    fmt L": %s (%d)\n", ##__VA_ARGS__, efi_statstr(s), s

#define ERROR_X(s, x, fmt, ...) \
    if( s != EFI_SUCCESS )                             \
    {                                                  \
        if( *(CHAR16 *)fmt != L'0' )                   \
            Print( ERR_FMT( fmt, s, ##__VA_ARGS__ ) ); \
        x;                                             \
    }

#define ERROR_RETURN(s, r, fmt, ...)             \
    ERROR_X( s, return r, fmt, ##__VA_ARGS__ )

#define ERROR_CONTINUE(s, fmt, ...) \
    ERROR_X( s, continue, fmt, ##__VA_ARGS__ )

#define ERROR_JUMP(s, target, fmt, ...) \
    ERROR_X( s, goto target, fmt, ##__VA_ARGS__ )

#define WARN_STATUS(s, fmt, ...) \
    if( s != EFI_SUCCESS )                       \
    {                                            \
        Print( ERR_FMT(fmt, s, ##__VA_ARGS__) ); \
    }

#define ALLOC_OR_GOTO(s, tgt) \
    ({ VOID *x = efi_alloc( s ); \
       EFI_STATUS stat = (x ? EFI_SUCCESS : EFI_OUT_OF_RESOURCES); \
       ERROR_JUMP( stat, tgt, L"Allocating %d bytes", s );         \
       x; })
