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

#include "chainloader.h"
#include "variable.h"
#include "exec.h"
#include "console-ex.h"
#include "console.h"

static EFI_STATUS reset_system (IN EFI_RESET_TYPE type,
                                IN EFI_STATUS     status,
                                IN UINTN          size,
                                IN CHAR16        *data OPTIONAL)
{
    return uefi_call_wrapper( RT->ResetSystem, 4, type, status, size, data );
}

BOOLEAN reboot_into_firmware_is_supported (VOID)
{
    UINT64 os_indications_supported;
    UINTN size;
    VOID *val;
    EFI_GUID gv_guid = EFI_GLOBAL_VARIABLE_GUID;

    val = get_efivar( L"OsIndicationsSupported", &gv_guid, &size );
    if( !val )
        return FALSE;

    v_msg( L"OsIndicationsSupported: %016x\n", *(UINT64 *)val);
    os_indications_supported = *(UINT64 *)val;
    efi_free( val );

    if( os_indications_supported & EFI_OS_INDICATIONS_BOOT_TO_FW_UI )
        return TRUE;

    return FALSE;
}

EFI_STATUS reboot_into_firmware (VOID)
{
    UINT64 os_indications = EFI_OS_INDICATIONS_BOOT_TO_FW_UI;
    UINTN size, res;
    VOID *val;
    EFI_GUID gv_guid = EFI_GLOBAL_VARIABLE_GUID;

    val = get_efivar( L"OsIndications", &gv_guid, &size );
    if( val )
    {
        v_msg( L"OsIndications: %016x\n", *(UINT64 *)val);
        os_indications |= *(UINT64 *)val;
        efi_free( val );
    }

    if( nvram_debug )
    {
        v_msg( L"OsIndications: %016x\n", os_indications );
        res = set_persistent_efivar( L"OsIndications", &gv_guid,
                                     sizeof(os_indications), &os_indications );
        ERROR_RETURN( res, res,
                      "Failed to set persistent OsIndications variable" );
    }

    res = reset_system( EfiResetCold, EFI_SUCCESS, 0, NULL );
    ERROR_RETURN( res, res, "Failed to reset system" );

    return EFI_SUCCESS;
}

EFI_STATUS
efi_main (EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *sys_table)
{
    EFI_GUID fs_guid = SIMPLE_FILE_SYSTEM_PROTOCOL;
    EFI_HANDLE* filesystems = NULL;
    UINTN count = 0;
    EFI_STATUS res = EFI_SUCCESS;
    bootloader steamos = {0};
    EFI_HANDLE *bound_key = NULL;
    EFI_LOADED_IMAGE *steamcl = NULL;
    CHAR16 *cmdline = NULL;

    initialise( image_handle, sys_table );
    set_steamos_loader_criteria( &steamos );

    steamcl = get_self_loaded_image();

    if( steamcl )
    {
        get_image_cmdline( steamcl, &cmdline );

        if( cmdline && strstr_w( cmdline, L"display-menu" ) )
            request_boot_menu();
    }

    // no need to watch for keys if the command line already asked for a menu
    if( !boot_menu_requested() )
    {
        reset_console();
        bound_key = bind_key( SCAN_NULL, CHAR_TAB, request_menu );
    }

    if( nvram_debug )
    {
        set_loader_time_init_usec();
        set_loader_info();
        set_loader_firmware_info();
        set_loader_firmware_type();
        set_loader_features();
        set_loader_device_part_uuid();
        set_loader_image_identifier();
        set_chainloader_device_part_uuid();
        set_chainloader_image_identifier();
    }

    res = get_protocol_handles( &fs_guid, &filesystems, &count );
    ERROR_JUMP( res, cleanup, L"get_fs_handles" );

    for( int i = 0; i < (int)count; i++ )
    {
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* fs = NULL;

        res = get_handle_protocol( &filesystems[ i ], &fs_guid, (VOID **)&fs );
        ERROR_CONTINUE( res, L"simple fs protocol" );
    }

    // Move the old pseudo-efi bootconf files to the new /esp location
    migrate_bootconfs( filesystems, count, steamos.criteria.device_path );

    // find_loaders is the slowest step, and is not very interruptible
    // so the hotkey registered at the start may not trigger a callback
    // till after it has returned.
    res = find_loaders( filesystems, count, &steamos );
    ERROR_JUMP( res, cleanup, L"no valid steamos loader found" );

    // Was the ⋯ button pressed on boot (ie before the chainloader started)?
    if( get_hw_config_button_state() != 0 )
        request_boot_menu();

    // the menu will be invoked here if it's been requested,
    // either by keypress or by nvram variables set before reboot
    // or by L"display-menu" on the UEFI command line:
    res = choose_steamos_loader( &steamos );

    if( bound_key )
        unbind_key( bound_key );

    if( verbose )
    {
        EFI_GUID part_uuid = device_path_partition_uuid( steamos.device_path );
        CHAR16 *puuid  = guid_str( &part_uuid );
        CHAR16 *device = device_path_string( steamos.device_path );

        v_msg( L"Booting: %s\n  %s\n  %s\n",
               device, puuid, steamos.loader_path );
        v_msg( L"args in : %s\n", cmdline ?: L"NONE" );
        v_msg( L"args out: %s\n", steamos.args );

        efi_free( puuid );
        efi_free( device );
    }

    if( nvram_debug )
        set_loader_time_exec_usec();

    efi_free( cmdline );
    res = exec_bootloader( &steamos );
    ERROR_JUMP( res, cleanup, L"exec failed" );

cleanup:
    efi_free( filesystems );

    if( reboot_into_firmware_is_supported() )
    {
        Print( L"Rebooting into firmware...\n" );
        res = reboot_into_firmware();
        Print( L"Failed to reboot into firmware: %r\n", res );
    }

    Print( L"Boot failed, waiting 5s...\n" );
    uefi_call_wrapper( BS->Stall, 1, 5 * 1000000 );

    return res;
}
