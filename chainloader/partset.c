// steamos-efi  --  SteamOS EFI Chainloader

// SPDX-License-Identifier: GPL-2.0+
// Copyright © 2021 Collabora Ltd
// Copyright © 2021 Valve Corporation
// Copyright © 2021 Vivek Das Mohapatra <vivek@etla.org>

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

#include "util.h"

#ifndef NO_EFI_TYPES
#include <efilib.h>
#endif

CONST CHAR8 *
get_partset_value (CHAR8 *buf, UINTN size, CONST CHAR8 *key)
{
    UINTN i = 0;
    // We currently have a maximum of 3 images in our installs, A,B,dev
    // each one requires 3 image specific partitions: efi,var,root.
    // in addition there are 2 shared partitions, esp and home.
    // 64 entries therefore allows (64 - 2) / 3 which allows for
    // up to 20 images, which should be plenty. We can always up this
    // number if we reach that level of complexity.
    CHAR8 *item[64] = { 0 };

    if (!buf)
        return NULL;

    if (!key || !*key)
        return NULL;

    // slice the partset buffer into tokens (this is idempotent)
    for( CHAR8 *c = buf; c < buf + size; c++ )
        if( *c == '\n' || *c == ' ' || *c == '\t' )
            *c = (CHAR8)0;

    // copy the token start addresses
    for( CHAR8 *c = buf; (c < buf + size) && (i < ARRAY_SIZE(item)); c++ )
    {
        if( *c )
            item[ i++ ] = c;
        while( *c++ );
        c--;
    }

    // find the value for KEY and return the token following it:
    for( UINTN j = 0; j < i - 1; j += 2 )
    {
        if( strcmpa( item[ j ], key ) != 0 )
            continue;
        return item[ j + 1 ];
    }

    return NULL;
}
