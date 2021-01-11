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

    res = exec_bootloader( &steamos );
    ERROR_JUMP( res, cleanup, L"exec failed" );

cleanup:
    efi_free( filesystems );

    return res;
}
