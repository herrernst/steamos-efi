// steamos-efi  --  SteamOS EFI Chainloader

// SPDX-License-Identifier: GPL-2.0+
// Copyright © 2018,2019 Collabora Ltd
// Copyright © 2018,2019 Valve Corporation
// Copyright © 2018,2019 Vivek Das Mohapatra <vivek@etla.org>

// steamos-efi is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 2.0 of the License, or
// (at your option) any later version.

// steamos-efi is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with steamos-efi.  If not, see <http://www.gnu.org/licenses/>.

#pragma once

#ifndef NO_EFI_TYPES
#include <efi.h>
#include <efilib.h>
#include "debug.h"
#endif

#ifndef NO_EFI_TYPES
#define ERR_FMT(fmt, s, ...)                                    \
    fmt L": %s (%d)\n", ##__VA_ARGS__, efi_statstr(s), s
#else
#define ERR_FMT(fmt, s, ...)                                    \
    fmt L": error-code %d\n", ##__VA_ARGS__, s
#endif

#ifndef NO_EFI_TYPES
#define ERROR_X(s, x, fmt, ...) \
    if( s != EFI_SUCCESS )                             \
    {                                                  \
        if( *(CHAR16 *)fmt != L'0' )                   \
        {                                              \
            if( verbose )                              \
                Print( ERR_FMT( fmt, s, ##__VA_ARGS__ ) ); \
            DEBUG_VMSG( fmt L": %s\n", ##__VA_ARGS__, efi_statstr(s) ); \
        }                                              \
        x;                                             \
    }
#else
#define ERROR_X(s, x, fmt, ...) ({ if( s != 0 ) x; })
#endif

#define ERROR_RETURN(s, r, fmt, ...)             \
    ERROR_X( s, return r, fmt, ##__VA_ARGS__ )

#define ERROR_BREAK(s, fmt, ...) \
    ERROR_X( s, break, fmt, ##__VA_ARGS__ )

#define ERROR_CONTINUE(s, fmt, ...) \
    ERROR_X( s, continue, fmt, ##__VA_ARGS__ )

#define ERROR_JUMP(s, target, fmt, ...) \
    ERROR_X( s, goto target, fmt, ##__VA_ARGS__ )

#define WARN_STATUS(s, fmt, ...) \
    if( s != EFI_SUCCESS )                                              \
    {                                                                   \
        if( verbose ) Print( ERR_FMT(fmt, s, ##__VA_ARGS__) );          \
        DEBUG_VMSG( fmt L": %s\n", ##__VA_ARGS__, efi_statstr(s) );     \
    }

#define ALLOC_OR_GOTO(s, tgt) \
    ({ VOID *x = efi_alloc( s ); \
       EFI_STATUS stat = (x ? EFI_SUCCESS : EFI_OUT_OF_RESOURCES); \
       ERROR_JUMP( stat, tgt, L"Allocating %d bytes", (int)s );    \
       x; })

#define v_msg(fmt, ...) \
    ({ if( verbose ) Print( fmt, ##__VA_ARGS__ ); \
       DEBUG_VMSG( fmt, ##__VA_ARGS__ ); })

#define v_hex(indent, offset, size, data) \
    ({ if( verbose ) DumpHex( indent, offset, size, data ); })

extern UINTN verbose;
extern UINTN nvram_debug;

UINTN set_verbosity (UINTN level);
UINTN set_nvram_debug (UINTN level);
