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
#include "partset.h"
#include "console-ex.h"

// this is the console output attributes for the menu
#define SELECTED_ATTRIBUTES (EFI_MAGENTA   | EFI_BACKGROUND_BLACK)
#define DEFAULT_ATTRIBUTES  (EFI_LIGHTGRAY | EFI_BACKGROUND_BLACK)

// this converts micro-seconds to event timeout in 10ns
#define EFI_TIMER_PERIOD_MICROSECONDS(s) (s * 10)

// this is x86_64 specific
#define EFI_STUB_ARCH 0x8664

static BOOLEAN display_menu = FALSE;

EFI_STATUS EFIAPI
request_menu (IN EFI_KEY_DATA *k opt)
{
    display_menu = TRUE;

    return EFI_SUCCESS;
}

VOID request_boot_menu (VOID)
{
    display_menu = TRUE;
}

BOOLEAN boot_menu_requested (VOID)
{
    return display_menu;
}

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
    CHAR16 *label;
    EFI_GUID uuid;
    UINT64 at;
    UINT64 boot_time;
    BOOLEAN disabled;
} found_cfg;

static found_cfg found[MAX_BOOTCONFS + 1];
static UINTN found_cfg_count;
static EFI_GUID *found_signatures[MAX_BOOTCONFS + 1];

typedef enum
{
    BOOT_NONE,
    BOOT_NORMAL,
    BOOT_VERBOSE,
    BOOT_MENU
} opt_type;

typedef struct
{
    CHAR16   label[80];
    UINTN    config;
    opt_type type;
} menu_option;

#ifdef SHOW_STAGE2_BOOTLOADER_MENU_OPTION
#define BOOT_VARIANTS 3
#else
#define BOOT_VARIANTS 2
#endif

struct
{
    UINTN col_offset;
    UINTN row_offset;
    UINTN menu_width;
    UINTN entries;
    menu_option option[MAX_BOOTCONFS * BOOT_VARIANTS];
} boot_menu;

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
       dst.label       = src.label;       \
       dst.uuid        = src.uuid;        \
       dst.disabled    = src.disabled;    \
       dst.boot_time   = src.boot_time;   \
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
    CHAR16 *vdbg_path = NULL;

    loader_file = get_self_file();
    loader->criteria.is_restricted = 0;
    loader->criteria.device_path = NULL;

    if( !loader_file )
        return EFI_NOT_FOUND;

    // default to being verbose & log to nvram in early setup until we've had
    // a chance to look for FLAGFILE_VERBOSE:
    set_verbosity( 1 );
    set_nvram_debug( 1 );

    orig_path = device_path_string( loader_file );
    flag_path = resolve_path( FLAGFILE_RESTRICT, orig_path, FALSE );
    verb_path = resolve_path( FLAGFILE_VERBOSE , orig_path, FALSE );
    vdbg_path = resolve_path( FLAGFILE_NVDEBUG , orig_path, FALSE );

    if( !flag_path && !verb_path && !vdbg_path)
        res = EFI_INVALID_PARAMETER;
    ERROR_JUMP( res, cleanup,
                L"Unable to construct %s, %s, and %s paths\n",
                FLAGFILE_RESTRICT, FLAGFILE_VERBOSE, FLAGFILE_NVDEBUG );

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

    // likewise we turn nvram debug off if the path is potentially
    // valid but the file definitely is not there:
    if( vdbg_path )
        if( efi_file_exists( root_dir, vdbg_path ) != EFI_SUCCESS )
            set_nvram_debug( 0 );

    if( flag_path && efi_file_exists( root_dir, flag_path ) == EFI_SUCCESS )
        loader->criteria.is_restricted = 1;

    loader->criteria.device_path = get_self_device_path();

    res = EFI_SUCCESS;

cleanup:
    efi_free( orig_path );
    efi_free( flag_path );
    efi_free( verb_path );
    efi_unmount( &root_dir );

    return res;
}

EFI_STATUS console_mode (VOID)
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

static VOID render_menu_option(IN UINTN nth, BOOLEAN on)
{
    con_set_output_attribute( on ? SELECTED_ATTRIBUTES : DEFAULT_ATTRIBUTES );
    con_set_cursor_position( boot_menu.col_offset, boot_menu.row_offset + nth );
    con_output_text( on ? L"> " : L"  " );
    con_output_text( &boot_menu.option[ nth ].label[ 0 ] );
    con_set_cursor_position( boot_menu.col_offset + boot_menu.menu_width + 2,
                             boot_menu.row_offset + nth );
    con_output_text( on ? L" <" : L"  " );
}

// split YYYYMMDDHHmmSS style int into list: YYYY, MM, DD, HH, mm
#define SPLIT_TIME(x) \
    (UINT64)((x % 1000000000000000) - (x % 10000000000)) / 10000000000, \
    (UINT64)((x % 10000000000)      - (x % 100000000))   / 100000000,   \
    (UINT64)((x % 100000000)        - (x % 1000000))     / 1000000,     \
    (UINT64)((x % 1000000)          - (x % 10000))       / 10000,       \
    (UINT64)((x % 10000)            - (x % 100))         / 100

static INTN fill_menu_spec (VOID)
{
    INTN entries = 0;

    if( boot_menu.entries )
        return boot_menu.entries;

    CONST UINT64 llen = sizeof( boot_menu.option[ 0 ].label );

    for( INTN i = 0; i < (INTN)found_cfg_count; i++ )
    {
        UINTN olen = 0;
        CHAR16 *label;
        INTN o = i * BOOT_VARIANTS;
        CHAR16 ui_label[4];

        // ==================================================================
        // UEFI printf doesn't do left align/right pad:
        for( UINTN i = 0; i < ARRAY_SIZE(ui_label); i++ )
            ui_label[ i ] = L' ';

        mem_copy( &ui_label[ 0 ], found[ i ].label,
                  strlen_w( found[ i ].label ) * sizeof( *found[ i ].label ) );

        ui_label[ ARRAY_SIZE(ui_label) - 1 ] = L'\0';

        // ==================================================================
        // basic boot entry
        label = &boot_menu.option[ o ].label[ 0 ];
        boot_menu.option[ o ].type = BOOT_NORMAL;
        boot_menu.option[ o ].config = i;

        if( found[ i ].boot_time )
            SPrint( label, llen,
                    L"%s Last Boot: %04lu-%02lu-%02lu %02lu:%02lu",
                    ui_label, SPLIT_TIME( found[ i ].boot_time ) );
        else
            SPrint( label, llen, L"%s Last Boot: -", ui_label );

        label[ llen - 1 ] = L'\0';

        olen = strlen_w( label );
        if( olen > boot_menu.menu_width )
            boot_menu.menu_width = olen;

        // ==================================================================
        // verbose boot entry

        o++;

        label = &boot_menu.option[ o ].label[ 0 ];
        boot_menu.option[ o ].type = BOOT_VERBOSE;
        boot_menu.option[ o ].config = i;
        SPrint( label, llen, L"%s Verbose Boot", ui_label );
        label[ llen - 1 ] = L'\0';

        olen = strlen_w( label );
        if( olen > boot_menu.menu_width )
            boot_menu.menu_width = olen;

#ifdef SHOW_STAGE2_BOOTLOADER_MENU_OPTION
        // ==================================================================
        // boot to stage 2 loader menu

        o++;

        label = &boot_menu.option[ o ].label[ 0 ];
        boot_menu.option[ o ].type = BOOT_MENU;
        boot_menu.option[ o ].config = i;
        SPrint( label, llen, L"%s OS Boot Menu", ui_label );
        label[ llen - 1 ] = L'\0';

        olen = strlen_w( label );
        if( olen > boot_menu.menu_width )
            boot_menu.menu_width = olen;
#endif

        entries += BOOT_VARIANTS;
    }

    boot_menu.entries = entries;

    return entries;
}

static INTN text_menu_choose_steamos_loader (INTN entry_default,
                                      OUT opt_type *type,
                                      UINTN timeout)
{
    UINTN cols;
    UINTN rows;
    INTN i, selected;
    EFI_STATUS res;
    const INTN opt console_max_mode = con_get_max_output_mode();

    if( fill_menu_spec() <= 0 )
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

    res = con_output_mode_info( con_get_output_mode(), &cols, &rows);

    // fall back to punchard size if we don't know how big the console is:
    if( EFI_ERROR( res ) )
    {
        cols = 80;
        rows = 25;
    }

    selected = entry_default * BOOT_VARIANTS;
    if( selected < 0 || selected >= (INTN)boot_menu.entries )
        selected = 0;

    con_clear_screen();
    con_enable_cursor( FALSE );

    // centre the menu vertically
    boot_menu.row_offset = (rows - boot_menu.entries) / 2;

    // ==================================================================
    // … and horizontally:
    INTN offset = cols / 2;
    for( i = 0; i < (INTN)boot_menu.entries; i++ )
    {
        INTN label_len = strlen_w( boot_menu.option[ i ].label );
        INTN o = ((cols - label_len) / 2) - 2;

        if( o < 0 )
            o = 0;

        if( o < offset )
            offset = o;
    }

    boot_menu.col_offset = offset;
    // ==================================================================

    for( i = 0; i < (INTN)boot_menu.entries; i++ )
        render_menu_option( i, i == selected );

    con_set_output_attribute( DEFAULT_ATTRIBUTES );
    con_reset( FALSE );

    if( timeout )
    {
        EFI_EVENT event;

        event = ST->ConIn->WaitForKey;
        res = WaitForSingleEvent( event, EFI_TIMER_PERIOD_MICROSECONDS( timeout ) );
        if( res == EFI_TIMEOUT )
            goto exit;
        ERROR_JUMP( res, exit, L"Wait for event failed: %r\n", res );
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
            if( selected < (INTN)boot_menu.entries - 1 )
                selected++;
            else
                selected = 0;
        }

        if( selected == -1 || selected == old_selected )
            continue;

        render_menu_option( old_selected, FALSE );
        render_menu_option( selected, TRUE );
    }

exit:
    con_clear_screen();
    display_menu = FALSE;

    if( type )
        *type = boot_menu.option[ selected ].type;

    return boot_menu.option[ selected ].config;
}

// disabled entries are considered older than enabled ones
// this is so they sort as less important when choosing
BOOLEAN earlier_entry_is_newer (found_cfg *a, found_cfg *b)
{
    if( a->disabled && !b->disabled )
        return FALSE;

    if( !a->disabled && b->disabled )
        return TRUE;

    // entries at same level of disabled-flag-ness:
    // pick the most recently boot-requested image.
    if( a->at > b->at )
        return TRUE;

    return FALSE;
}

static CHAR16 * find_image_name_by_partuuid (EFI_FILE_PROTOCOL *root,
                                             CONST CHAR16 *uuid)
{
    EFI_STATUS res;
    EFI_FILE_PROTOCOL *partsets = NULL;
    EFI_FILE_INFO *dirent = NULL;
    UINTN de_size = 0;
    CHAR8 *id = NULL;
    CHAR16 *image_ident = NULL;

    res = efi_file_open( root, &partsets, L"\\SteamOS\\partsets", 0, 0 );
    ERROR_RETURN( res, NULL, L"No \\SteamOS\\partsets found" );

    // narrow and downcase the efi partition uuid we want to match:
    id = strlower( strnarrow( uuid ) );

    if( !id || !*id )
        return NULL;

    while( image_ident == NULL )
    {
        EFI_FILE_PROTOCOL *setdata = NULL;
        CHAR16 *name = NULL;
        res = efi_readdir( partsets, &dirent, &de_size );
        ERROR_CONTINUE( res, L"readdir failed" );

        if( de_size == 0 ) // no more entries
            break;

        name = &dirent->FileName[0];

        // These partsets won't have useful identifying information:
        if( strcmp_w( L"all",    name ) == 0 ||
            strcmp_w( L"self",   name ) == 0 ||
            strcmp_w( L"other",  name ) == 0 ||
            strcmp_w( L"shared", name ) == 0 )
            continue;

        if( efi_file_open( partsets, &setdata, name, 0, 0 ) == EFI_SUCCESS )
        {
            CHAR8 *buf  = NULL;
            UINTN bytes = 0;
            UINTN size  = 0;

            if( efi_file_to_mem( setdata, &buf, &bytes, &size ) == EFI_SUCCESS )
            {
                CONST CHAR8 *partset_efi_uuid = NULL;

                partset_efi_uuid =
                  get_partset_value (buf, size, (CONST CHAR8 *)"efi");

                if (!partset_efi_uuid)
                    continue;

                // does this partset's efi uuid  match the current efi uuid:
                if( strcmpa( partset_efi_uuid, id ) == 0 )
                    image_ident = strdup_w( name );

                efi_free( buf );
            }

            efi_file_close( setdata );
        }
    }

    efi_free( id );
    efi_free( dirent );
    efi_file_close( partsets );

    return image_ident;
}

static EFI_STATUS migrate_conf(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *efi_fs,
                               EFI_GUID *efi_guid,
                               EFI_FILE_PROTOCOL *esp_root,
                               EFI_FILE_PROTOCOL **conf_dir,
                               CHAR16 *conf_path)
{
    EFI_STATUS res = EFI_SUCCESS;
    EFI_FILE_PROTOCOL *efi_root = NULL;
    EFI_FILE_PROTOCOL *conf_file = NULL;
    EFI_FILE_PROTOCOL *new_conf = NULL;
    CHAR16 *efi_label = NULL;
    CHAR16 *os_image_name = NULL;
    CHAR8 *buf = NULL;
    UINTN bytes = 0;
    UINTN alloc = 0;
    CHAR16 new_path[MAXFSNAMLEN] = L"";

    res = efi_mount( efi_fs, &efi_root );
    ERROR_JUMP( res, cleanup, "efi partition not opened\n" );

    // We must have a label and an os_image name to proceed:
    // Absence of either indicates a malformed efi layout
    // (or a non-SteamOS one):
    efi_label = guid_str( efi_guid );
    if( !efi_label || !*efi_label )
        goto cleanup;

    os_image_name = find_image_name_by_partuuid( efi_root, efi_label );
    if( !os_image_name || !*os_image_name )
        goto cleanup;

    res = efi_file_open( efi_root, &conf_file,
                         OLDCONFPATH, EFI_FILE_MODE_READ, 0 );
    switch( res )
    {
      case EFI_SUCCESS:
        break;

      case EFI_NOT_FOUND: // This is actually Ok, no config to migrate.
        res = EFI_SUCCESS;
        // fallthrough, we are done either way.
      default:
        goto cleanup;
    }

    res = efi_file_to_mem( conf_file, &buf, &bytes, &alloc );
    ERROR_JUMP( res, cleanup, "Could not read config file\n" );

    SPrint( &new_path[0], sizeof(new_path),
            L"%s\\%s.conf", conf_path, os_image_name );
    new_path[ (sizeof(new_path) / sizeof(CHAR16)) - 1 ] = (CHAR16)0;

    // If already some NEWER config at the target location, do not overwrite:
    if( efi_file_open( esp_root, &new_conf, &new_path[0],
                       EFI_FILE_MODE_READ, 0) == EFI_SUCCESS )
    {
        INTN age_cmp = 0;

        res = efi_file_xtime_cmp( new_conf, conf_file, &age_cmp );
        WARN_STATUS( res, L"Unable to compare ages of old and new configs\n" );

        efi_file_close( new_conf );
        new_conf = NULL;

        if( age_cmp >= 0 )
        {
            v_msg( L"Target config is newer than old, do not migrate\n" );
            goto cleanup;
        }
    }

    if( !*conf_dir )
    {
        res = efi_mkdir_p( esp_root, conf_dir, conf_path );
        ERROR_JUMP( res, cleanup, L"Unable to create confdir %s", conf_path );
    }

    res = efi_file_open( esp_root, &new_conf, &new_path[0],
                         EFI_FILE_MODE_CREATE|EFI_FILE_MODE_WRITE, 0 );
    ERROR_JUMP( res, cleanup, "Unable to create config at %s", &new_path[0] );

    UINTN written = bytes;
    res = efi_file_write( new_conf, buf, &written );
    ERROR_JUMP( res, cleanup, L"Write %d bytes to %s failed (wrote %d)",
                bytes, &new_path, written );

cleanup:
        efi_free( os_image_name );
        efi_free( efi_label );
        efi_free( buf );
        efi_file_close( new_conf );
        efi_file_close( conf_file );
        efi_unmount( &efi_root );

        return res;
}

// Copy configs from /efi/SteamOS/bootconf to /esp/SteamOS/conf/X.conf
// where X is "A", "B", "dev" etc.
EFI_STATUS migrate_bootconfs (EFI_HANDLE *handles,
                              CONST UINTN n_handles,
                              EFI_DEVICE_PATH *self_dev_path)
{
    EFI_STATUS res = EFI_SUCCESS;
    EFI_HANDLE dh = NULL;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* esp_fs = NULL;
    EFI_FILE_PROTOCOL *esp_root = NULL;
    EFI_DEVICE_PATH *self_file = NULL;
    EFI_DEVICE_PATH *esp_dev = NULL;
    EFI_GUID esp_guid = NULL_GUID;
    static EFI_GUID fs_guid = SIMPLE_FILE_SYSTEM_PROTOCOL;
    static EFI_GUID dp_guid = DEVICE_PATH_PROTOCOL;

    CHAR16 *self_path = NULL;
    CHAR16 *conf_path = NULL;
    EFI_FILE_PROTOCOL *conf_dir = NULL;

    self_file = get_self_file();

    if( !self_file )
        return EFI_NOT_FOUND;

    self_path = device_path_string( self_file );
    conf_path = resolve_path( NEWCONFPATH, self_path, FALSE );

    dh = get_self_device_handle();
    if( !dh )
        res = EFI_NOT_FOUND;
    ERROR_JUMP( res, cleanup,
                L"No device handle for running bootloader 0x%lx", dh );

    res = get_handle_protocol( &dh, &fs_guid, (VOID **)&esp_fs );
    ERROR_JUMP( res, cleanup, L"No filesystem associated with bootloader" );

    res = get_handle_protocol( &dh, &dp_guid, (VOID **)&esp_dev );
    ERROR_JUMP( res, cleanup, L"esp device handle has no device path" );

    esp_guid = device_path_partition_uuid( esp_dev );

    res = efi_mount( esp_fs, &esp_root );
    ERROR_JUMP( res, cleanup, L"Unable to mount bootloader filesystem\n" );

    for( UINTN i = 0; i < n_handles; i++ )
    {
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *efi_fs = NULL;
        EFI_DEVICE_PATH *efi_dev = NULL;
        EFI_GUID efi_guid = NULL_GUID;

        res = get_handle_protocol( &handles[ i ], &fs_guid, (VOID **)&efi_fs );
        ERROR_CONTINUE( res, L"handle #%u: no simple file system", i );

        res = get_handle_protocol( &handles[ i ], &dp_guid, (VOID **)&efi_dev );
        ERROR_CONTINUE( res, L"handle #%u has no device path", i );

        efi_guid = device_path_partition_uuid( efi_dev );

        if( self_dev_path && !on_same_device( self_dev_path, efi_dev ) )
        {
            if( verbose )
            {
                CHAR16 *partuuid = guid_str( &efi_guid );

                v_msg( L"Partition %s on other disk, skip migration\n",
                       partuuid );
                efi_free( partuuid );
            }

            continue;
        }

        // If this is the ESP there's nothing to migrate _from_ here:
        // also some UEFI firmware gets badly broken if we mount an FS
        // that's already mounted, so best not to let that happen:
        if( guid_cmp( &esp_guid, &efi_guid ) == 0 )
            continue;

        res = migrate_conf( efi_fs, &efi_guid, esp_root, &conf_dir, conf_path );
        WARN_STATUS( res, "Config %u not migrated\n", i );
    }

cleanup:
    efi_free( self_path );
    efi_free( conf_path );
    efi_file_close( conf_dir );
    efi_unmount( &esp_root );

    return res;
}

EFI_STATUS find_loaders (EFI_HANDLE *handles,
                         CONST UINTN n_handles,
                         IN OUT bootloader *chosen)
{
    EFI_STATUS res = EFI_SUCCESS;
    EFI_FILE_PROTOCOL *efi_root = NULL;
    static EFI_GUID fs_guid = SIMPLE_FILE_SYSTEM_PROTOCOL;
    static EFI_GUID dp_guid = DEVICE_PATH_PROTOCOL;
    UINTN j = 0;

    EFI_DEVICE_PATH *restricted = NULL;

    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* esp_fs = NULL;
    EFI_FILE_PROTOCOL *esp_root = NULL;
    EFI_DEVICE_PATH *self_file = NULL;
    EFI_DEVICE_PATH *esp_dev = NULL;
    EFI_GUID esp_guid = NULL_GUID;
    CHAR16 *self_path = NULL;
    CHAR16 *conf_path = NULL;
    EFI_HANDLE dh = NULL;

    if( found_cfg_count > 0 )
        return EFI_SUCCESS;

    self_file = get_self_file();

    if( !self_file )
        return EFI_NOT_FOUND;

    self_path = device_path_string( self_file );
    conf_path = resolve_path( NEWCONFPATH, self_path, FALSE );
    efi_free( self_path );

    dh = get_self_device_handle();
    if( !dh )
        res = EFI_NOT_FOUND;
    ERROR_JUMP( res, cleanup,
                L"No device handle for running bootloader 0x%lx\n", dh );

    res = get_handle_protocol( &dh, &fs_guid, (VOID **)&esp_fs );
    ERROR_JUMP( res, cleanup, L"No filesystem associated with bootloader\n" );

    res = get_handle_protocol( &dh, &dp_guid, (VOID **)&esp_dev );
    ERROR_JUMP( res, cleanup, L"esp device handle has no device path" );

    esp_guid = device_path_partition_uuid( esp_dev );

    res = efi_mount( esp_fs, &esp_root );
    ERROR_JUMP( res, cleanup, L"Unable to mount ESP filesystem\n" );

    if( chosen->criteria.is_restricted )
        restricted = chosen->criteria.device_path;

    chosen->partition = NULL;
    chosen->loader_path = NULL;
    chosen->args = NULL;
    chosen->config = NULL;

    for( UINTN i = 0; i < n_handles && j < MAX_BOOTCONFS; i++ )
    {
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *efi_fs = NULL;
        EFI_GUID efi_guid = NULL_GUID;
        CHAR16 *efi_label = NULL;
        CHAR16 *os_image_name = NULL;
        CHAR16 cfg_path[MAXFSNAMLEN] = L"";
        cfg_entry *conf = NULL;

        efi_unmount( &efi_root );

        res = get_handle_protocol( &handles[ i ], &fs_guid, (VOID **)&efi_fs );
        ERROR_CONTINUE( res, L"handle #%u: no simple file system protocol", i );

        res = efi_mount( efi_fs, &efi_root );
        ERROR_CONTINUE( res, L"partition #%u not opened", i );

        res = get_handle_protocol( &handles[ i ], &dp_guid,
                                   (VOID **)&found[ i ].device_path );
        ERROR_CONTINUE( res, L"partition #%u has no device path (what?)", i );

        efi_guid = device_path_partition_uuid( found[ i ].device_path );

        // Don't look at the ESP since we know it can't be a pseudo-EFI
        if( guid_cmp( &esp_guid, &efi_guid ) == 0 )
            continue;

        if( restricted )
            if( !on_same_device( restricted, found[ i ].device_path ) )
                continue;

        efi_label = guid_str( &efi_guid );

        if( efi_label && *efi_label )
        {
            os_image_name = find_image_name_by_partuuid( efi_root, efi_label );
            efi_free( efi_label );
        }

        if( !os_image_name )
            continue;

        // If we got this far then the partsets file gave us an OS image name
        // so this is may be a bootable pseudo-EFI whose config is at:
        SPrint( &cfg_path[0], sizeof(cfg_path),
                L"%s\\%s.conf", conf_path, os_image_name );
        cfg_path[(sizeof(cfg_path)/sizeof(CHAR16)) - 1] = L'\0';
        efi_free( os_image_name );
        os_image_name = NULL;

        // prefer the new config location on /esp
        if( efi_file_exists( esp_root, &cfg_path[0] ) == EFI_SUCCESS )
            res = parse_config( esp_root, &cfg_path[0], &conf );
        else if( efi_file_exists( efi_root, OLDCONFPATH ) == EFI_SUCCESS )
            res = parse_config( efi_root, OLDCONFPATH, &conf );
        else
            res = EFI_NOT_FOUND;

        if( res != EFI_SUCCESS )
            continue;

        // If the config specied an alternate loader path, expand it here:
        CHAR8 *alt_cfg = get_conf_str( conf, "loader" );
        if( alt_cfg && *alt_cfg )
        {
            CHAR16 *alt_ldr = resolve_path( alt_cfg, OLDCONFPATH, 1 );

            if( valid_efi_binary( efi_root, alt_ldr ) == EFI_SUCCESS )
                found[ j ].loader = alt_ldr;
            else
                efi_free( alt_ldr );
        }
        efi_free( alt_cfg );

        // use the default bootloader:
        if( !found[ j ].loader )
            if( valid_efi_binary( efi_root, STEAMOSLDR ) == EFI_SUCCESS )
                found[ j ].loader = strdup_w( STEAMOSLDR );

        if( !found[ j ].loader )
        {
            free_config( &conf );
            continue;
        }

        found[ j ].disabled  = get_conf_uint( conf, "image-invalid" ) > 0;
        found[ j ].cfg       = conf;
        found[ j ].partition = handles[ i ];
        found[ j ].at        = get_conf_uint( conf, "boot-requested-at" );
        found[ j ].boot_time = get_conf_uint( conf, "boot-time" );
        found[ j ].label     = strwiden( get_conf_str( conf, "title" ) );

        if( !found[ j ].label || !found[ j ].label[ 0 ] )
            found[ j ].label = volume_label( efi_root );

        found[ j ].uuid      = efi_guid;
        found_signatures[ j ] = &found[ j ].uuid;
        j++;
    }

    found[ j ].cfg = NULL;
    found_cfg_count = j;
    efi_unmount( &efi_root );

    {
        // yes I know, bubble sort is terribly gauche, but we really don't care:
        // usually there will be only two entries (and at most 16, which would be
        // a fairly psychosis-inducing setup):
        // make sure we exit even if the compare/swap primitives fail somehow// 
        UINTN maxpass = 1024;
        UINTN sort = j > 1 ? 1 : 0;
        while( sort && maxpass )
        {
            maxpass--;
            for( UINTN i = sort = 0; i < j - 1; i++ )
            {
                if( earlier_entry_is_newer( &found[ i ], &found[ i + 1 ] ) )
                    sort += swap_cfgs( &found[ 0 ], i, i + 1 );
            }
        }
    }

    // we now have a sorted (oldest to newest) list of configs
    // and their respective partition handles.
    // NOTE: some of these images may be flagged as invalid.

    if( nvram_debug )
        set_loader_entries( &found_signatures[ 0 ] );

cleanup:
    efi_free( conf_path );
    efi_unmount( &esp_root );

    if( found_cfg_count > 0 )
        return EFI_SUCCESS;

    return EFI_NOT_FOUND;
}

EFI_STATUS choose_steamos_loader (IN OUT bootloader *chosen)
{
    UINT64 flags = 0;
    INTN selected = -1;
    BOOLEAN update = FALSE;
    BOOLEAN boot_other = FALSE;
    EFI_STATUS res = EFI_SUCCESS;

    // pick the newest entry to start with.
    // if boot-other is set, we need to bounce along to the next entry:
    // we walk the above list from newest to oldest, with invalid-flagged
    // images considered older than unflagged ones - so if there is a valid
    // image available, we'll pick it, and failing that resort to an invalid
    // flagged one:
    for( INTN i = (INTN) found_cfg_count - 1; i >= 0; i-- )
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

        // boot other is not set, whatever we found is good
        break;
    }

    BOOLEAN oneshot = is_loader_config_timeout_oneshot_set();

    // we do this after the normal selection process above so that if
    // oneshot fails we have a fallback boot option selected anyway:
    EFI_GUID entry = get_loader_entry_oneshot ();
    if( guid_cmp( &entry, &NULL_GUID ) != 0 )
        for( UINTN i = 0; i < found_cfg_count - 1; i++ )
            if( guid_cmp( &entry, &found[ i ].uuid ) == 0 )
                selected = i;

    // if a oneshot boot was requested from the last OS run or
    // we somehow failed to pick a valid image, display a menu:
    if( oneshot || (selected < 0) )
    {
        display_menu = TRUE;
    }

    opt_type boot_type = BOOT_NORMAL;

    // Let the user pick via menu:
    if( display_menu )
    {
        BOOLEAN unique = TRUE;
        for( UINTN i = 0; i < found_cfg_count; i++ )
            for( UINTN k = i + 1; k < found_cfg_count; k++ )
                if( strcmp_w( found[ i ].label, found[ k ].label ) == 0 )
                    unique = FALSE;

        // if the labels aren't unique, add a differentiator to them:
        if( !unique )
        {
            for( UINTN i = 0; i < found_cfg_count; i++ )
            {
                CHAR16 *old = found[ i ].label;
                found[ i ].label = PoolPrint( L"%s-%g", found[ i ].label,
                                                        &found[ i ].uuid );
                efi_free( old );
            }
        }
#if 0
        UINTN timeout = get_loader_config_timeout();

        if( oneshot )
            timeout = get_loader_config_timeout_oneshot();
#endif

        boot_type = BOOT_NONE;
        selected = text_menu_choose_steamos_loader( selected, &boot_type, 0 );

        if( nvram_debug )
            set_loader_time_menu_usec();
    }

    CHAR16 args[ 1024 ] = L"";

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

        switch( boot_type )
        {
          case BOOT_NONE:
            v_msg( L"ALERT: boot menu type was NONE - should never happen\n" );

          case BOOT_NORMAL:
            break;

          case BOOT_VERBOSE:
            set_verbosity( 1 );
            appendstr_w( &args[ 0 ], sizeof( args ), L" steamos-verbose" );
            break;

          case BOOT_MENU:
            appendstr_w( &args[ 0 ], sizeof( args ), L" steamos-bootmenu" );
            break;
        }

        if( update )
        {
            // Our stage II bootloader looks for this command line string
            // Do not remove it unless you also change stage II
            appendstr_w( &args[ 0 ], sizeof( args ),  L" steamos-update=1" );
            flags |= ENTRY_FLAG_UPDATE;
        }

        // not strictly nvram but let's make sure the stage 2 loader is
        // handling command line args correctly by passing some canaries:
        if( nvram_debug )
        {
            appendstr_w( &args[ 0 ], sizeof( args ), L" steamos-dummy" );
            appendstr_w( &args[ 0 ], sizeof( args ), L" dummy " );
        }

        chosen->args = strdup_w( &args[ 0 ] );

        // free the unused configs:
        for( INTN i = 0; i < (INTN) found_cfg_count; i++ )
        {
            efi_free( found[ i ].loader );
            if( found[ i ].label )
                efi_free( found[ i ].label );
            free_config( &found[ i ].cfg );
        }

        if( nvram_debug )
        {
            set_chainloader_boot_attempts ();
            set_loader_entry_default( found_signatures[ found_cfg_count - 1 ] );
            set_loader_entry_selected( found_signatures[ selected ] );
        }

        // This sets a volatile variable (it is _not_ in NVRAM) which
        // passes the update (or not) flag. This is redundant with
        // the command line update argumant steamos-update=1 above.
        set_chainloader_entry_flags( flags );

        res = EFI_SUCCESS;
    }

    return res;
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

    // WARNING: Do NOT free boot->args. UEFI _must not_ reuse
    // this memory before the next program in the chain gets to it:
    res = set_image_cmdline( &efi_app, boot->args, &child );
    ERROR_JUMP( res, unload, L"command line not set" );

    v_msg( L"Storing chained loader uuid in EFI var\n" );
    set_chainedloader_device_part_uuid( efi_app );

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

