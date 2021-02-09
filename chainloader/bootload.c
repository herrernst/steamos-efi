// steamos-efi  --  SteamOS EFI Chainloader

// SPDX-License-Identifier: GPL-2.0+
// Copyright © 2018,2021 Collabora Ltd
// Copyright © 2018,2021 Valve Corporation
// Copyright © 2018,2020 Vivek Das Mohapatra <vivek@etla.org>

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
#include "exec.h"
#include "variable.h"
#include "console.h"

// this is the console output attributes for the menu
#define SELECTED_ATTRIBUTES (EFI_MAGENTA   | EFI_BACKGROUND_BLACK)
#define DEFAULT_ATTRIBUTES  (EFI_LIGHTGRAY | EFI_BACKGROUND_BLACK)

// this converts micro-seconds to event timeout in 10ns
#define EFI_TIMER_PERIOD_MICROSECONDS(s) (s * 10)

// this is x86_64 specific
#define EFI_STUB_ARCH 0x8664

// this will always return a zeroed-out buffer
static EFI_STATUS allocate (VOID **p, UINTN s)
{
    if( p == NULL )
        return EFI_INVALID_PARAMETER;

    efi_free( *p );
    *p = NULL;
    *p = efi_alloc( s );

    return (*p != NULL) ? EFI_SUCCESS : EFI_OUT_OF_RESOURCES;
}

// this is a rewrite of function LibFileSystemVolumeLabelInfo() to handle buggy
// firmwares that does not return a NULL-terminated string and/or that makes
// mismatch with the sizes of UTF-16 characters
static EFI_FILE_SYSTEM_VOLUME_LABEL_INFO *volume_label_info (IN EFI_FILE_HANDLE fh)
{
    EFI_STATUS status;
    UINTN      size     = SIZE_OF_EFI_FILE_SYSTEM_VOLUME_LABEL_INFO + 200;
    EFI_GUID   vol_guid = EFI_FILE_SYSTEM_VOLUME_LABEL_INFO_ID;
    EFI_FILE_SYSTEM_VOLUME_LABEL_INFO *buffer = NULL;

    //
    // Call the real function
    //
    if( fh == NULL )
        return NULL;

    while( TRUE )
    {
        // Some firmware implementations misinterpret byte-size as char16-size
        // So above we allocate twice as much as we expect to need:
        UINTN alloc_size = size * 2;

        status = allocate( (VOID **)&buffer, alloc_size );
        ERROR_RETURN( status, NULL, "Memory alloc failure: %d bytes", alloc_size );

        // This will reset size to the required value if EFI_BUFFER_TOO_SMALL:
        status = uefi_call_wrapper( fh->GetInfo, 4, fh, &vol_guid, &size, (VOID *)buffer );
        if( status == EFI_BUFFER_TOO_SMALL )
            continue;

        ERROR_RETURN( status, NULL, L"failed to get volume info" );

        // Must have had a success to get this far.
        // Make sure we have a NUL terminated string:
        // We can't actually tell where the string ends, so just set the last
        // allocated CHAR16 location to (CHAR16) NUL:
        *((CHAR16 *)buffer + (alloc_size / 2) - 1) = (CHAR16)0;
        break;
    }

    return buffer;
}

CHAR16 *a2u (CHAR8 *str)
{
    CHAR16 *ptr = NULL;
    UINTN len;
    int i;

    if( !str )
        return NULL;

    len = strlena( str );
    if( !str )
        return NULL;

    ptr = efi_alloc( len * sizeof(CHAR16) + 1 );
    if( !ptr )
        return NULL;

    for( i = 0; str[i]; i++ )
        ptr[ i ] = (CHAR16)str[ i ];
    ptr[ i ] = 0;

    return ptr;
}

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

    if( header[ 0 ] != 'M' || header[ 1 ] != 'Z' )
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
    EFI_DEVICE_PATH *device_path;
    CHAR16 *loader;
    cfg_entry *cfg;
    CHAR16 *title;
    EFI_GUID uuid;
    UINT64 at;
} found_cfg;

static BOOLEAN update_scheduled_now (const cfg_entry *conf)
{
    if( get_conf_uint( conf, "update" ) )
    {
        UINT64 beg = get_conf_uint( conf, "update-window-start" );
        UINT64 end = get_conf_uint( conf, "update-window-end"   );

        // no beginning or end of update window specified,
        // update mode is unconditional:
        if( !end && !beg )
            return TRUE;

        UINT64 now = utc_datestamp();

        // only a window end is specified, update if we are before it:
        if( !beg )
            return ( now <= beg ) ? TRUE : FALSE;

        // only a window start is specified, upate if we are after it:
        if( !end )
            return ( now >= end ) ? TRUE : FALSE;

        // both specified, update mode only if within time window:
        return (( now >= beg ) && ( now <= end )) ? 1 : 0;
    }

    return FALSE;
}

#define COPY_FOUND(src,dst) \
    ({ dst.cfg         = src.cfg;         \
       dst.partition   = src.partition;   \
       dst.loader      = src.loader;      \
       dst.device_path = src.device_path; \
       dst.title       = src.title;       \
       dst.uuid        = src.uuid;        \
       dst.at          = src.at;          })

static UINTN swap_cfgs (found_cfg *f, UINTN a, UINTN b)
{
    found_cfg c;

    COPY_FOUND( f[ a ], c      );
    COPY_FOUND( f[ b ], f[ a ] );
    COPY_FOUND( c     , f[ b ] );

    return 1;
}

static CHAR16 *volume_label (EFI_FILE_PROTOCOL *handle)
{
    EFI_FILE_SYSTEM_VOLUME_LABEL_INFO *volume = NULL;

    volume = volume_label_info( handle );

    if( !volume )
        return NULL;

    return volume->VolumeLabel;
}

static EFI_GUID partition_uuid (EFI_HANDLE *handle)
{
    EFI_DEVICE_PATH *dp;

    if( !handle )
        return NullGuid;

    dp  = DevicePathFromHandle( handle );
    while( !IsDevicePathEnd( dp ) )
    {
        if( DevicePathType( dp )    == MEDIA_DEVICE_PATH &&
            DevicePathSubType( dp ) == MEDIA_HARDDRIVE_DP )
        {
            HARDDRIVE_DEVICE_PATH *hd = (HARDDRIVE_DEVICE_PATH *)dp;
            EFI_GUID *guid;

            if( hd->SignatureType != SIGNATURE_TYPE_GUID )
                break;

            guid = (EFI_GUID *) (&hd->Signature[0]);
            return *guid;
        }

        dp = NextDevicePathNode( dp );
    }

    return NullGuid;
}

// This code compares the _medium_ part of two EFI_DEVICE_PATHS,
// and returns TRUE if they are the same.
//
// It does NOT consider the filesystem-path part of the EFI_DEVICE_PATHS.
//
// Its main use is to determine if two files reside on the same
// filesystem instance (ie same hardware, same partition).
static BOOLEAN device_path_eq (EFI_DEVICE_PATH *a, EFI_DEVICE_PATH *b)
{
    if( !a || !b )
        return FALSE;

    // iterate over all the path components; both devices are located on the
    // same drive only if both components reach hard-drive partitions.
    while( !IsDevicePathEnd( a ) && !IsDevicePathEnd( b ) )
    {
        if( DevicePathNodeLength( a ) != DevicePathNodeLength( b ) ||
            DevicePathType( a )       != DevicePathType( b )       ||
            DevicePathSubType( a )    != DevicePathSubType( b ) )
            return FALSE;

        // both components are hard-drive partitions.
        // if we get this far then our job is done, the two
        // files are on the same device and partition.
        if( DevicePathType( a )    == MEDIA_DEVICE_PATH &&
            DevicePathSubType( a ) == MEDIA_HARDDRIVE_DP )
            return TRUE;

        // These structs use windows style ‘put a pointer to an array
        // at the end of a struct and deliberately overflow it’ storage.
        // (ie allocated storage is larger than the declared struct size).
        // See /usr/include/efi/efidevp.h
        // As such we must trust DevicePathNodeLength and not let the
        // compiler worry about the theoretical length of the struct
        // because that happens to be a lie:
        for( UINT16 x = 0; x < DevicePathNodeLength( a ); x++ )
            if( *((UINT8 *)&(a->Length[ 0 ]) + 2 + x) !=
                *((UINT8 *)&(b->Length[ 0 ]) + 2 + x) )
                return FALSE;

        a = NextDevicePathNode( a );
        b = NextDevicePathNode( b );
    }

    return FALSE;
}

EFI_STATUS set_steamos_loader_criteria (OUT bootloader *loader)
{
    EFI_STATUS res = EFI_SUCCESS;
    EFI_HANDLE dh = NULL;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* fs = NULL;
    EFI_FILE_PROTOCOL *root_dir = NULL;
    EFI_DEVICE_PATH *loader_file = NULL;
    static EFI_GUID fs_guid = SIMPLE_FILE_SYSTEM_PROTOCOL;
    CHAR16 *orig_path = NULL;
    CHAR16 *flag_path = NULL;
    CHAR16 *verb_path = NULL;

    loader_file = get_self_file();
    loader->criteria.is_restricted = 0;
    loader->criteria.device_path = NULL;

    if( !loader_file )
        return EFI_NOT_FOUND;

    // default to being verbose in early setup until we've had a chance
    // to look for FLAGFILE_VERBOSE:
    set_verbosity( 1 );

    orig_path = DevicePathToStr( loader_file );
    flag_path = resolve_path( FLAGFILE_RESTRICT, orig_path, FALSE );
    verb_path = resolve_path( FLAGFILE_VERBOSE , orig_path, FALSE );

    if( !flag_path && !verb_path)
        res = EFI_INVALID_PARAMETER;
    ERROR_JUMP( res, cleanup,
                L"Unable to construct %s and %s paths\n",
                FLAGFILE_RESTRICT, FLAGFILE_VERBOSE );

    dh = get_self_device_handle();
    if( !dh )
        res = EFI_NOT_FOUND;
    ERROR_JUMP( res, cleanup, L"No device handle for running bootloader\n" );

    res = get_handle_protocol( &dh, &fs_guid, (VOID **)&fs );
    ERROR_JUMP( res, cleanup, L"No filesystem associated with bootloader\n" );

    res = efi_mount( fs, &root_dir );
    ERROR_JUMP( res, cleanup, L"Unable to mount bootloader filesystem\n" );

    // note that if we were unable to look for the flag file (verb_path unset)
    // then we will remain in verbose mode (the default set above):
    if( verb_path )
        if( efi_file_exists( root_dir, verb_path ) != EFI_SUCCESS )
            set_verbosity( 0 );

    if( flag_path )
    {
        if( efi_file_exists( root_dir, flag_path ) == EFI_SUCCESS )
        {
            loader->criteria.is_restricted = 1;
            loader->criteria.device_path = get_self_device_path();
        }
    }

    res = EFI_SUCCESS;

cleanup:
    efi_free( orig_path );
    efi_free( flag_path );
    efi_free( verb_path );
    efi_unmount( &root_dir );

    return res;
}

EFI_STATUS console_mode ()
{
    EFI_CONSOLE_CONTROL_SCREEN_MODE mode;
    EFI_CONSOLE_CONTROL_PROTOCOL *ccp;
    EFI_STATUS res;
    BOOLEAN locked;
    BOOLEAN uga;
    EFI_GUID ccp_guid = EFI_CONSOLE_CONTROL_PROTOCOL_GUID;

    res = get_protocol( &ccp_guid, NULL, (VOID **)&ccp );
    if( res == EFI_NOT_FOUND )
        return res;
    ERROR_RETURN( res, res, "Could not get_protocol: %r\n", res );

    res = conctl_get_mode( ccp, &mode, &uga, &locked );
    ERROR_RETURN( res, res, "Could not conctl_get_mode: %r\n", res );

    if( mode == CONCTL_SCREEN_TEXT )
        return EFI_SUCCESS;

    res = conctl_set_mode( ccp, CONCTL_SCREEN_TEXT );
    ERROR_RETURN( res, res, "Could not conctl_set_mode: %r\n", res );

    return EFI_SUCCESS;
}

INTN text_menu_choose_steamos_loader (found_cfg *entries,
                                      INTN entry_count,
                                      INTN entry_default,
                                      UINTN timeout)
{
    UINTN columns, column_offsets[MAX_BOOTCONFS];
    UINTN rows, row_offset;
    INTN i, selected;
    EFI_STATUS res;
    const INTN console_max_mode = con_get_max_output_mode();

    if( !entries || entry_count <= 0 )
        return -1;

    res = console_mode();
    if( EFI_ERROR( res ) && res != EFI_NOT_FOUND )
        return res;

    if( console_max_mode > 0 )
    {
        for( i = console_max_mode - 1; i != 0; i-- )
        {
            res = con_set_output_mode( i );
            if( EFI_ERROR( res ) )
                continue;

            break;
        }
    }

    res = con_output_mode_info( con_get_output_mode(), &columns, &rows);
    if( EFI_ERROR( res ) )
    {
        columns = 80;
        rows = 25;
    }

    selected = entry_default;
    if( selected < 0 || selected >= entry_count )
        selected = 0;

    con_clear_screen();
    con_enable_cursor( FALSE );
    row_offset = (rows - entry_count) / 2;
    for( i = 0; i < entry_count; i++ )
    {
        INTN offset = (columns - StrLen( entries[ i ].title )) / 2;
        if( offset < 0 )
            offset = 0;

        column_offsets[ i ] = offset;

        con_set_cursor_position( column_offsets[ i ], row_offset + i );
        con_set_output_attribute( i == selected ?
                                  SELECTED_ATTRIBUTES :
                                  DEFAULT_ATTRIBUTES );
        con_output_text( entries[ i ].title );
    }

    con_set_output_attribute( DEFAULT_ATTRIBUTES );
    con_reset( FALSE );

    if( timeout )
    {
        EFI_EVENT event;

        event = ST->ConIn->WaitForKey;
        res = WaitForSingleEvent( event, EFI_TIMER_PERIOD_MICROSECONDS( timeout ) );
        if( res == EFI_TIMEOUT )
            goto exit;
        ERROR_JUMP( res, exit, L"Could not WaitForSingleWithTimeout: %r\n", res );
    }

    for( ;; )
    {
        INTN old_selected = selected;
        EFI_INPUT_KEY key;

        con_set_output_attribute( DEFAULT_ATTRIBUTES );

        res = WaitForSingleEvent( ST->ConIn->WaitForKey, 0 );
        ERROR_BREAK( res, L"Could not WaitForSingleEvent: %r\n", res );

        res = con_read_key( &key );
        ERROR_BREAK( res, L"Could not con_read_key: %r\n", res );

        if( ( key.UnicodeChar == CHAR_LINEFEED ) ||
            ( key.UnicodeChar == CHAR_CARRIAGE_RETURN ) )
        {
            break;
        }
        else if( ( key.ScanCode    == SCAN_ESC ) &&
                 ( key.UnicodeChar == 0        ) )
        {
            selected = -1;
            break;
        }
        else if( key.ScanCode == SCAN_UP )
        {
            if( selected > 0 )
                selected--;
            else
                selected = 0;
        }
        else if( key.ScanCode == SCAN_DOWN )
        {
            if( selected < entry_count - 1 )
                selected++;
            else
                selected = 0;
        }

        if( selected == -1 || selected == old_selected )
            continue;

        con_set_cursor_position( column_offsets[ old_selected ],
                                 row_offset + old_selected );
        con_set_output_attribute( DEFAULT_ATTRIBUTES );
        con_output_text( entries[ old_selected ].title );

        con_set_cursor_position( column_offsets[ selected ],
                                 row_offset + selected );
        con_set_output_attribute( SELECTED_ATTRIBUTES );
        con_output_text( entries[ selected ].title );
    }

exit:
    con_clear_screen();

    return selected;
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
    UINT64 flags = 0;
    UINTN j = 0;
    found_cfg found[MAX_BOOTCONFS + 1] = { { NULL } };
    EFI_GUID *found_signatures[MAX_BOOTCONFS + 1] = { NULL };
    EFI_DEVICE_PATH *restricted = NULL;

    if( chosen->criteria.is_restricted )
        restricted = chosen->criteria.device_path;

    chosen->partition = NULL;
    chosen->loader_path = NULL;
    chosen->args = NULL;
    chosen->config = NULL;

    for( UINTN i = 0; i < n_handles && j < MAX_BOOTCONFS; i++ )
    {
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs = NULL;

        efi_unmount( &root_dir );

        res = get_handle_protocol( &handles[ i ], &fs_guid, (VOID **)&fs );
        ERROR_CONTINUE( res, L"handle #%u: no simple file system protocol", i );

        res = efi_mount( fs, &root_dir );
        ERROR_CONTINUE( res, L"partition #%u not opened", i );

        res = get_handle_protocol( &handles[ i ], &dp_guid,
                                   (VOID **)&found[ i ].device_path );
        ERROR_CONTINUE( res, L"partition #%u has no device path (what?)", i );

        if( restricted )
            if( !device_path_eq( restricted, found[ i ].device_path ) )
                continue;

        res = efi_file_exists( root_dir, BOOTCONFPATH );
        if( res != EFI_SUCCESS )
            continue;

        if( parse_config( root_dir, &conf ) != EFI_SUCCESS )
            continue;

        // entry is known-bad. ignore it
        if( get_conf_uint( conf, "image-invalid" ) > 0 )
        {
            v_msg( L"partition #%u has image-invalid set, ignore it...\n", i);
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
        found[ j ].title     = a2u( get_conf_str( conf, "title" ) );
        if( !found[ j ].title )
            found[ j ].title = volume_label( root_dir );
        found[ j ].uuid      = partition_uuid( found[ j ].partition );
        found_signatures[ j ] = &found[ j ].uuid;
        j++;
    }

    found[ j ].cfg = NULL;
    efi_unmount( &root_dir );

    // yes I know, bubble sort is terribly gauche, but we really don't care:
    // usually there will be only two entries (and at most 16, which would be
    // a fairly psychosis-inducing setup):
    UINTN sort = j > 1 ? 1 : 0;
    while( sort )
        for( UINTN i = sort = 0; i < j - 1; i++ )
            if( found[ i ].at > found[ i + 1 ].at  )
                sort += swap_cfgs( &found[ 0 ], i, i + 1 );
    set_loader_entries( &found_signatures[ 0 ] );
    // we now have a sorted (oldest to newest) list of configs
    // and their respective partition handles, none of which are known-bad.

    INTN selected = -1;
    BOOLEAN update = FALSE;
    BOOLEAN boot_other = FALSE;

    // pick the newest entry to start with.
    // if boot-other is set, we need to bounce along to the next entry:
    for( INTN i = (INTN) j - 1; i >= 0; i-- )
    {
        selected = i;

        // if boot-other is set, skip it
        if( get_conf_uint( found[ i ].cfg, "boot-other" ) )
        {
            v_msg( L"entry #%u has boot-other set, skip it...\n", i);
            // if boot-other is set, update should persist until we get to
            // a non-boot-other entry:
            boot_other = TRUE;
            if( !update )
                update = update_scheduled_now( found[ i ].cfg );
            continue;
        }

        // if update is set but update is disabled, skip it
        if( update && get_conf_uint( found[ i ].cfg, "update-disabled" ) )
        {
            v_msg( L"entry #%u has update-disabled set, skip it...\n", i);
            continue;
        }

        // if boot-other is set but other is disabled, skip it
        if( boot_other && get_conf_uint( found[ i ].cfg, "boot-other-disabled" ) )
        {
            v_msg( L"entry #%u has boot-other-disabled set, skip it...\n", i);
            continue;
        }

        // boot other is not set, whatever we found is good
        break;
    }

    EFI_GUID entry = get_loader_entry_oneshot ();
    if( CompareGuid( &entry, &NullGuid ) != 0 )
        for( UINTN i = 0; i < j - 1; i++ )
            if( CompareGuid( &entry, &found[ i ].uuid ) == 0 )
                selected = i;

    BOOLEAN menu = FALSE;
    if( j > 1 && get_chainloader_boot_attempts() >= 3 )
        menu = TRUE;

    BOOLEAN oneshot = is_loader_config_timeout_oneshot_set();
    if( oneshot )
        menu = TRUE;

    EFI_INPUT_KEY key;
    res = con_read_key( &key );
    if( ! EFI_ERROR( res ) && ( key.ScanCode == SCAN_F3 ) )
        menu = TRUE;

    if( menu )
    {
        BOOLEAN unique = TRUE;
        for( UINTN i = 0; i < j; i++ )
            for( UINTN k = i + 1; k < j; k++ )
                if( StrCmp( found[ i ].title, found[ k ].title ) == 0 )
                    unique = FALSE;
        if( !unique )
        {
            for( UINTN i = 0; i < j; i++ )
            {
                CHAR16 *old = found[ i ].title;
                found[ i ].title = PoolPrint( L"%s-%g", found[ i ].title,
                                                        &found[ i ].uuid );
                efi_free( old );
            }
        }

        UINTN timeout = get_loader_config_timeout();
        if( oneshot )
            timeout = get_loader_config_timeout_oneshot();

        selected = text_menu_choose_steamos_loader( found, j, selected, timeout );
        set_loader_time_menu_usec();
    }

    if( selected > -1 )
    {
        chosen->device_path = found[ selected ].device_path;
        chosen->loader_path = found[ selected ].loader;
        chosen->partition   = found[ selected ].partition;
        chosen->config      = found[ selected ].cfg;

        found[ selected ].cfg    = NULL;
        found[ selected ].loader = NULL;

        // we never un-set an update we inherited from boot-other
        // but we might have it set in our own config:
        if( !update )
            update = update_scheduled_now( chosen->config );

        flags = 0;

        if( boot_other )
            flags |= ENTRY_FLAG_BOOT_OTHER;

        if( update )
            flags |= ENTRY_FLAG_UPDATE;

        // free the unused configs:
        for( INTN i = 0; i < (INTN) j; i++ )
        {
            efi_free( found[ i ].loader );
            if( found[ i ].title )
                efi_free( found[ i ].title );
            free_config( &found[ i ].cfg );
        }

        set_chainloader_boot_attempts ();
        set_chainloader_entry_flags( flags );
        set_loader_entry_default( found_signatures[ j - 1 ] );
        set_loader_entry_selected( found_signatures[ selected ] );

        return EFI_SUCCESS;
    }

    return EFI_NOT_FOUND;
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

    res = load_image( dpath, &efi_app );
    ERROR_JUMP( res, unload, L"load-image failed" );

    // TODO: do the self-reload trick to keep shim + EFI happy
    // we don't can't support secureboot yet because of the NVIDIA
    // module/dkms/initrd problem, but if we ever fix that, we'll
    // need to do what refind.main.c@394 does.

    res = set_image_cmdline( &efi_app, boot->args, &child );
    ERROR_JUMP( res, unload, L"command line not set" );

    res = exec_image( efi_app, &esize, &edata );
    WARN_STATUS( res, L"start image returned with exit code: %u; data @ 0x%x",
                 esize, (UINT64) edata );

unload:
    if( efi_app )
    {
        EFI_STATUS r2 = uefi_call_wrapper( BS->UnloadImage, 1, efi_app );
        WARN_STATUS( r2, L"unload of image failed" );
    }

    efi_free( dpath );

    return res;
}

