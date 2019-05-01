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

#include <efi.h>
#include <efilib.h>
#include <efiprot.h>

#include "err.h"
#include "util.h"
#include "fileio.h"
#include "bootload.h"
#include "debug.h"
#include "exec.h"

// this is x86_64 specific
#define EFI_STUB_ARCH 0x8664

EFI_STATUS valid_efi_binary (EFI_FILE_PROTOCOL *dir, CONST CHAR16 *path)
{
    EFI_STATUS res;
    EFI_FILE_PROTOCOL *bin = NULL;
    CHAR8 header[512] = { '0','x','d','e','a','d','b','e','e','f', 0, 0 };
    CONST UINTN hsize = sizeof(header);
    UINTN bytes = hsize;
    UINTN s;
    UINT16 arch;

    res = efi_file_open( dir, &bin, path, 0, 0 );
    ERROR_RETURN( res, res, L"open( %s )", path );

    res = efi_file_read( bin, (CHAR8 *)header, &bytes );
    ERROR_RETURN( res, res, L"read( %s, %u )", path, hsize );

    efi_file_close( bin );

    if( bytes < hsize )
        return EFI_END_OF_FILE;

    if( header[0] != 'M' || header[1] != 'Z' )
        return EFI_LOAD_ERROR;

    // The uint32 starting at offset 0x3c
    s = * (UINT32 *) &header[ 0x3c ];

    if( s >=  0x180 ||
        header[ s   ] != 'P' ||
        header[ s+1 ] != 'E' ||
        header[ s+2 ] != 0   ||
        header[ s+3 ] != 0   )
        return EFI_LOAD_ERROR;

    arch = * (UINT16 *) &header[ s+4 ];

    if( arch != EFI_STUB_ARCH )
        return EFI_LOAD_ERROR;

    return EFI_SUCCESS;
}

typedef struct
{
    EFI_HANDLE partition;
    EFI_DEVICE_PATH device_path;
    CHAR16 *loader;
    cfg_entry *cfg;
    UINT64 at;
} found_cfg;

static UINTN update_scheduled_now (const cfg_entry *conf)
{
    if( get_conf_uint( conf, "update" ) )
    {
        UINT64 beg = get_conf_uint( conf, "update-window-start" );
        UINT64 end = get_conf_uint( conf, "update-window-end"   );

        // no beginning or end of update window specified,
        // update mode is unconditional:
        if( !end && !beg )
            return 1;

        UINT64 now = utc_datestamp();

        // only a window end is specified, update if we are before it:
        if( !beg )
            return ( now <= beg ) ? 1 : 0;

        // only a window start is specified, upate if we are after it:
        if( !end )
            return ( now >= end ) ? 1 : 0;

        // both specified, update mode only if within time window:
        return (( now >= beg ) && ( now <= end )) ? 1 : 0;
    }

    return 0;
}

static VOID dump_found (found_cfg *c)
{
    for(UINTN i = 0; c && c->cfg; c++)
        Print( L"#%u %x @%lu %s%s[%s]\n",
               i++,
               c->partition,
               c->at,
               get_conf_uint( c->cfg, "boot-other" ) ? L"OTHER " : L"",
               update_scheduled_now( c->cfg )        ? L"UPDATE ": L"",
               c->loader );
}

#define COPY_FOUND(src,dst) \
    ({ dst.cfg         = src.cfg;         \
       dst.at          = src.at;          \
       dst.partition   = src.partition;   \
       dst.loader      = src.loader;      \
       dst.device_path = src.device_path; \
       dst.at          = src.at;          })

UINTN swap_cfgs (found_cfg *f, UINTN a, UINTN b)
{
    found_cfg c;

    COPY_FOUND( f[ a ], c      );
    COPY_FOUND( f[ b ], f[ a ] );
    COPY_FOUND( c     , f[ b ] );

    return 1;
}

EFI_STATUS choose_steamos_loader (EFI_HANDLE *handles,
                                  CONST UINTN n_handles,
                                  OUT bootloader *chosen)
{
    EFI_STATUS res;
    EFI_FILE_PROTOCOL *root_dir = NULL;
    static EFI_GUID fs_guid = SIMPLE_FILE_SYSTEM_PROTOCOL;
    static EFI_GUID dp_guid = DEVICE_PATH_PROTOCOL;
    cfg_entry *conf = NULL;
    UINTN j = 0;
    found_cfg found[MAX_BOOTCONFS + 1] = { { NULL } };

    chosen->partition = NULL;
    chosen->loader_path = NULL;
    chosen->args = NULL;
    chosen->config = NULL;

    for ( UINTN i = 0; i < n_handles && j < MAX_BOOTCONFS; i++ )
    {
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs = NULL;

        efi_unmount( &root_dir );

        res = get_handle_protocol( &handles[i], &fs_guid, (VOID **)&fs );
        ERROR_CONTINUE( res, L"handle #%u: no simple file system protocol", i );

        res = efi_mount( fs, &root_dir );
        ERROR_CONTINUE( res, L"partition #%u not opened", i );

        res = get_handle_protocol( &handles[ i ], &dp_guid,
                                   (VOID **)&found[ i ].device_path );
        ERROR_CONTINUE( res, L"partition #%u has no device path (what?)", i );

        res = efi_file_exists( root_dir, BOOTCONFPATH );
        if( res != EFI_SUCCESS )
            continue;

        if( parse_config( root_dir, &conf ) != EFI_SUCCESS )
            continue;

        // entry is known-bad. ignore it
        if( get_conf_uint( conf, "image-invalid" ) > 0 )
        {
            free_config( &conf );
            continue;
        }

        // TODO? allow the 'loader' config entry to specify an alternative
        // bootloader. This code was causing EFI runtime service errors
        // that made the kernel explode on boot, so it's been backed out for
        // now. May drop this feature entirely from the spec.
        CHAR8 *alt_cfg = get_conf_str( conf, "loader" );
        if( alt_cfg && *alt_cfg )
        {
            CHAR16 *alt_ldr =
              resolve_path( alt_cfg, BOOTCONFPATH, 1 );

            if( valid_efi_binary( root_dir, alt_ldr ) == EFI_SUCCESS )
                found[ j ].loader = alt_ldr;
            else
                efi_free( alt_ldr );
        }
        efi_free( alt_cfg );

        // use the default bootloader:
        if( !found[ j ].loader )
            if( valid_efi_binary( root_dir, STEAMOSLDR ) == EFI_SUCCESS )
                found[ j ].loader = StrDuplicate( STEAMOSLDR );

        if( !found[ j ].loader )
        {
            free_config( &conf );
            continue;
        }

        found[ j ].cfg       = conf;
        found[ j ].partition = handles[ i ];
        found[ j ].at        = get_conf_uint( conf, "boot-requested-at" );
        j++;
    }

    found[ j ].cfg = NULL;
    efi_unmount( &root_dir );

    Print( L"Went through %u filesystems, %u SteamOS loaders found\n", n_handles, j);

    Print( L"Unsorted\n" );
    dump_found( &found[0] );
    // yes I know, bubble sort is terribly gauche, but we really don't care:
    // usually there will be only two entries (and at most 16, which would be
    // a fairly psychosis-inducing setup):
    UINTN sort = j > 1 ? 1 : 0;
    while( sort )
        for( UINTN i = sort = 0; i < j - 1; i++ )
            if( found[ i ].at > found[ i + 1 ].at  )
                sort += swap_cfgs( &found[0], i, i + 1 );
    Print( L"Sorted\n" );
    dump_found( &found[0] );
    // we now have a sorted (oldest to newest) list of configs
    // and their respective partition handles, none of which are known-bad.

    INTN selected = -1;
    UINTN update  = 0;

    // pick the newest entry to start with.
    // if boot-other is set, we need to bounce along to the next entry:
    for( INTN i = (INTN) j - 1; i >= 0; i-- )
    {
        selected = i;

        if( get_conf_uint( found[i].cfg, "boot-other" ) )
        {
            // if boot-other is set, update should persist until we get to
            // a non-boot-other entry:
            if( !update)
                update = update_scheduled_now( found[i].cfg );
            continue;
        }

        // boot other is not set, whatever we found is good
        break;
    }

    if( selected > -1 )
    {
        chosen->device_path = found[selected].device_path;
        chosen->loader_path = found[selected].loader;
        chosen->partition   = found[selected].partition;
        chosen->config      = found[selected].cfg;

        found[selected].cfg    = NULL;
        found[selected].loader = NULL;

        // we never un-set an update we inherited from boot-other
        // but we might have it set in our own config:
        if( !update )
            update = update_scheduled_now( chosen->config );

        if( update )
            chosen->args = L" steamos-update=1 ";

        // free the unused configs:
        for( INTN i = 0; i < (INTN) j; i++ )
        {
            efi_free( found[ i ].loader );
            free_config( &found[ i ].cfg );
        }

        return EFI_SUCCESS;
    }

    return EFI_NOT_FOUND;
}

static VOID dump_bootloader_paths (EFI_DEVICE_PATH *target)
{
    CHAR16 *this = NULL;
    CHAR16 *that = NULL;
    EFI_GUID lip_guid = LOADED_IMAGE_PROTOCOL;
    EFI_LOADED_IMAGE *li;
    EFI_STATUS res;
    EFI_DEVICE_PATH *fqdp = NULL;
    EFI_HANDLE current = get_self_handle();

    that = DevicePathToStr( target );
    Print( L"Loading bootloader @ %s\n", that );

    res = get_handle_protocol( &current, &lip_guid, (VOID **) &li );
    ERROR_RETURN( res, , L"No loaded image protocol. wat." );

    fqdp = AppendDevicePath( DevicePathFromHandle( li->DeviceHandle ),
                             li->FilePath );

    this = DevicePathToStr( fqdp );

    Print( L"Within chainloader @ %s\n", this );
}

EFI_STATUS exec_bootloader (bootloader *boot)
{
    EFI_STATUS res = EFI_SUCCESS;
    EFI_HANDLE efi_app = NULL;
    EFI_LOADED_IMAGE *child = NULL;
    EFI_DEVICE_PATH *dpath = NULL;
    UINTN esize;
    CHAR16 *edata = NULL;

    dpath = make_absolute_device_path( boot->partition, boot->loader_path );
    if( !dpath )
        res = EFI_INVALID_PARAMETER;

    ERROR_JUMP( res, unload,
                L"FDP could not construct a device path from %x + %s",
                (UINT64) &boot->device_path, boot->loader_path );

    dump_bootloader_paths( dpath );

    res = load_image( dpath, &efi_app );
    ERROR_JUMP( res, unload, L"load-image failed" );

    // TODO: do the self-reload trick to keep shim + EFI happy
    // we don't can't support secureboot yet because of the NVIDIA
    // module/dkms/initrd problem, but if we ever fix that, we'll
    // need to do what refind.main.c@394 does.

    res = set_image_cmdline( &efi_app, boot->args, &child );
    ERROR_JUMP( res, unload, L"command line not set" );

#if DEBUG_ABORT
    res = EFI_ABORTED;
    ERROR_JUMP( res, unload, L"aborting deliberately to show config data" );
#endif

    res = exec_image( efi_app, &esize, &edata );
    WARN_STATUS( res, L"start image returned with exit code: %u; data @ 0x%x",
                 esize, (UINT64) edata );

unload:
    if( child )
        dump_loaded_image( child );

    if( efi_app )
    {
        EFI_STATUS r2 = uefi_call_wrapper( BS->UnloadImage, 1, efi_app );
        WARN_STATUS( r2, L"unload of image failed" );
    }

    efi_free( dpath );

    return res;
}

