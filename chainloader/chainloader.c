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

    val = LibGetVariableAndSize( L"OsIndicationsSupported",
                                 &gEfiGlobalVariableGuid, &size );
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

    val = LibGetVariableAndSize( L"OsIndications",
                                 &gEfiGlobalVariableGuid, &size );
    if( val )
    {
        v_msg( L"OsIndications: %016x\n", *(UINT64 *)val);
        os_indications |= *(UINT64 *)val;
        efi_free( val );
    }

    v_msg( L"OsIndications: %016x\n", os_indications );
    res = LibSetNVVariable( L"OsIndications", &gEfiGlobalVariableGuid,
                            sizeof(os_indications), &os_indications );
    if( EFI_ERROR( res ) )
    {
        Print( L"Failed to LibSetNVVariable: %r\n", res );
        return res;
    }

    res = reset_system( EfiResetCold, EFI_SUCCESS, 0, NULL );
    if( EFI_ERROR( res ) )
    {
        Print( L"Failed to reset_system: %r\n", res );
        return res;
    }

    return EFI_SUCCESS;
}

EFI_STATUS dump_fs_details (IN EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs)
{
    EFI_STATUS res = EFI_NOT_STARTED;
    EFI_FILE_PROTOCOL *root_dir = NULL;
    EFI_FILE_SYSTEM_VOLUME_LABEL_INFO *volume = NULL;
    UINTN is_esp_ish = 0;

    res = efi_mount( fs, &root_dir );
    ERROR_RETURN( res, res, L"SFSP->open-volume %x failed", (UINT64)fs );

    volume = LibFileSystemVolumeLabelInfo( root_dir );
    res = (volume ? EFI_SUCCESS : EFI_OUT_OF_RESOURCES);
    ERROR_JUMP( res, out, L"Allocating %d bytes",
                SIZE_OF_EFI_FILE_SYSTEM_VOLUME_LABEL_INFO + MAXFSNAMLEN );
    v_msg( L"<<< Volume label: %s >>>\n", volume->VolumeLabel );

    res = efi_file_exists( root_dir, BOOTCONFPATH );

    switch( res )
    {
      case EFI_SUCCESS:
        v_msg(  L"<<< !! SteamOS/bootconf, pseudo-ESP, full listing >>>\n" );
        is_esp_ish = 1;
        break;
      case EFI_NOT_FOUND:
        v_msg(  L"<<< No SteamOS/bootconf, not a pseudo-ESP >>>\n" );
        break;
      default:
        WARN_STATUS( res, L"%s->Open( SteamOS/bootconf )", volume->VolumeLabel );
    }

    if( !is_esp_ish )
        is_esp_ish = ( efi_file_exists( root_dir, EFIDIR ) == EFI_SUCCESS );

    if( is_esp_ish )
    {
        if( efi_file_exists( root_dir, DEFAULTLDR ) == EFI_SUCCESS )
        {
            v_msg( L"Default loader %s exists\n", DEFAULTLDR );
            if( valid_efi_binary( root_dir, DEFAULTLDR ) == EFI_SUCCESS )
                v_msg( L"... and is a PE32 executable for x86_64\n" );
            else
                v_msg( L"... but is NOT a PE32 executable\n" );
        }
        else
        {
            v_msg( L"Default loader %s does NOT exist on this EFI volume\n",
                   DEFAULTLDR );
        }
    }

    if( is_esp_ish )
        ls( root_dir, 0, L"/", 1 );

    res = efi_file_close( root_dir );
    WARN_STATUS( res, L"/->close() failed. what.\n" );

out:
    if( volume ) efi_free( volume );

    return res;
}

EFI_STATUS
EFIAPI
efi_main (EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *sys_table)
{
    EFI_GUID fs_guid = SIMPLE_FILE_SYSTEM_PROTOCOL;
    EFI_HANDLE* filesystems = NULL;
    UINTN count = 0;
    EFI_STATUS res = EFI_SUCCESS;
    bootloader steamos = {0};

    InitializeLib( image_handle, sys_table );
    initialise( image_handle );
    set_steamos_loader_criteria( &steamos );
    set_loader_time_init_usec();
    set_loader_info();
    set_loader_firmware_info();
    set_loader_firmware_type();
    set_loader_features();
    set_loader_device_part_uuid();
    set_loader_image_identifier();
    set_chainloader_device_part_uuid( LibImageHandle );
    set_chainloader_image_identifier( LibImageHandle );

    res = get_protocol_handles( &fs_guid, &filesystems, &count );
    ERROR_JUMP( res, cleanup, L"get_fs_handles" );

    for( int i = 0; i < (int)count; i++ )
    {
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* fs = NULL;

        res = get_handle_protocol( &filesystems[ i ], &fs_guid, (VOID **)&fs );
        ERROR_CONTINUE( res, L"simple fs protocol" );

        if( verbose )
            dump_fs_details( fs );
    }

    res = choose_steamos_loader( filesystems, count, &steamos );
    ERROR_JUMP( res, cleanup, L"no valid steamos loader found" );

    set_loader_time_exec_usec();

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

    Print( L"Rebooting into 5s...\n" );
    sleep( 5 );

    return res;
}
