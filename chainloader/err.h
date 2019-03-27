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

#include <efi.h>

#define ERR_FMT(fmt, s, ...)                                    \
    fmt L": %s (%d)\n", ##__VA_ARGS__, efi_statstr(s), s

#define ERROR_X(s, x, fmt, ...) \
    if( s != EFI_SUCCESS )                             \
    {                                                  \
        if( verbose && *(CHAR16 *)fmt != L'0' )        \
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
    if( verbose && (s != EFI_SUCCESS) )          \
    {                                            \
        Print( ERR_FMT(fmt, s, ##__VA_ARGS__) ); \
    }

#define ALLOC_OR_GOTO(s, tgt) \
    ({ VOID *x = efi_alloc( s ); \
       EFI_STATUS stat = (x ? EFI_SUCCESS : EFI_OUT_OF_RESOURCES); \
       ERROR_JUMP( stat, tgt, L"Allocating %d bytes", s );         \
       x; })

extern UINTN verbose;
UINTN set_verbosity (UINTN level);

