// steamos-efi  --  SteamOS EFI Chainloader

// SPDX-License-Identifier: GPL-2.0+
// Copyright © 2021 Collabora Ltd
// Copyright © 2021 Valve Corporation

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
#include "variable.h"

#define LOADER_VARIABLE_GUID \
    { 0x4a67b082, 0x0a4c, 0x41cf, {0xb6, 0xc7, 0x44, 0x0b, 0x29, 0xbb, 0x8c, 0x4f} }

#define CHAINLOADER_VARIABLE_GUID \
    { 0x399abb9b, 0x4bee, 0x4a18, {0xab, 0x5b, 0x45, 0xc6, 0xe0, 0xe8, 0xc7, 0x16} }

#define VARIABLE_STRING(s) (UINTN)( ( StrLen( s ) + 1 ) * sizeof( CHAR16 ) ), (VOID *)( s )
#define VARIABLE_BLOB(s) (UINTN)(sizeof( *s )), (VOID *)( s )

/* Some facilities that does not exist in the efi lib */

static EFI_STATUS
open_protocol (IN EFI_HANDLE handle,
               IN EFI_GUID  *protocol,
               OUT VOID    **interface OPTIONAL,
               IN EFI_HANDLE agent,
               IN EFI_HANDLE controller,
               IN UINT32     attributes)
{
    return uefi_call_wrapper( BS->OpenProtocol, 6,
                              handle, protocol, interface,
                              agent, controller, attributes );
}

static EFI_STATUS
close_protocol (IN EFI_HANDLE handle,
                IN EFI_GUID  *protocol,
                IN EFI_HANDLE agent,
                IN EFI_HANDLE controller)
{
    return uefi_call_wrapper( BS->CloseProtocol, 4,
                              handle, protocol, agent, controller );
}

static EFI_GUID
get_drive_signature (EFI_DEVICE_PATH *device_path)
{
    HARDDRIVE_DEVICE_PATH *harddrive;
    EFI_GUID *guid = &NullGuid;

    while( device_path && !IsDevicePathEnd( device_path ) )
    {
        if( DevicePathType( device_path ) == MEDIA_DEVICE_PATH &&
            DevicePathSubType( device_path ) == MEDIA_HARDDRIVE_DP )
        {
            harddrive = (HARDDRIVE_DEVICE_PATH *)device_path;
            if( harddrive->SignatureType != SIGNATURE_TYPE_GUID )
                break;

            guid = (EFI_GUID *)&harddrive->Signature[0];
            break;
        }

        device_path = NextDevicePathNode( device_path );
    }

    return *guid;
}

static const CHAR16 *loader_info = L"steamcl " RELEASE_VERSION;
static const UINT64 loader_features = 0;

EFI_STATUS set_loader_time_init_usec ()
{
    EFI_GUID guid = LOADER_VARIABLE_GUID;
    EFI_STATUS res = EFI_SUCCESS;
    CHAR16 *str = NULL;
    UINT64 usec;

    usec = time_usec();
    str = PoolPrint( L"%u", usec );
    WARN_STATUS( ( str == NULL ), L"Failed to PoolPrint()" );

    if( !str )
        return EFI_OUT_OF_RESOURCES;

    v_msg( L"LoaderTimeInitUSec: %s\n", str );
    res = LibSetVariable( L"LoaderTimeInitUSec", &guid,
                          VARIABLE_STRING( str ) );
    WARN_STATUS( res, L"Failed to SetVariable()" );

    efi_free( str );

    return res;
}

EFI_STATUS set_loader_time_exec_usec ()
{
    EFI_GUID guid = LOADER_VARIABLE_GUID;
    EFI_STATUS res = EFI_SUCCESS;
    CHAR16 *str = NULL;
    UINT64 usec;

    usec = time_usec();
    str = PoolPrint( L"%u", usec );
    WARN_STATUS( ( str == NULL ), L"Failed to PoolPrint()" );

    if( !str )
        return EFI_OUT_OF_RESOURCES;

    v_msg( L"LoaderTimeExecUSec: %s\n", str );
    res = LibSetVariable( L"LoaderTimeExecUSec", &guid,
                          VARIABLE_STRING( str ) );
    WARN_STATUS( res, L"Failed to SetVariable()" );

    efi_free( str );

    return res;
}

EFI_STATUS set_loader_info ()
{
    EFI_GUID guid = LOADER_VARIABLE_GUID;
    EFI_STATUS res = EFI_SUCCESS;

    v_msg( L"LoaderInfo: %s\n", loader_info );
    res = LibSetVariable( L"LoaderInfo", &guid,
                          VARIABLE_STRING( loader_info ) );
    WARN_STATUS( res, L"Failed to SetVariable()" );

    return res;
}

EFI_STATUS set_loader_firmware_info ()
{
    EFI_GUID guid = LOADER_VARIABLE_GUID;
    EFI_STATUS res = EFI_SUCCESS;
    CHAR16 *str = NULL;

    str = PoolPrint( L"%s %d.%02d",
                     ST->FirmwareVendor,
                     ST->FirmwareRevision >> 16,
                     ST->FirmwareRevision & 0xffff );
    WARN_STATUS( ( str == NULL ), L"Failed to PoolPrint()" );

    if( !str )
        return EFI_OUT_OF_RESOURCES;

    v_msg( L"LoaderFirmwareInfo: %s\n", str );
    res = LibSetVariable( L"LoaderFirmwareInfo", &guid,
                          VARIABLE_STRING( str ) );
    WARN_STATUS( res, L"Failed to SetVariable()" );

    efi_free( str );

    return res;
}

EFI_STATUS set_loader_firmware_type ()
{
    EFI_GUID guid = LOADER_VARIABLE_GUID;
    EFI_STATUS res = EFI_SUCCESS;
    CHAR16 *str = NULL;

    str = PoolPrint( L"UEFI %d.%02d",
                     ST->Hdr.Revision >> 16,
                     ST->Hdr.Revision & 0xffff );
    WARN_STATUS( ( str == NULL ), L"Failed to PoolPrint()" );

    if( !str )
        return EFI_OUT_OF_RESOURCES;

    v_msg( L"LoaderFirmwareType: %s\n", str );
    res = LibSetVariable( L"LoaderFirmwareType", &guid,
                          VARIABLE_STRING( str ) );
    WARN_STATUS( res, L"Failed to SetVariable()" );

    efi_free( str );

    return res;
}

EFI_STATUS set_loader_features ()
{
    EFI_GUID guid = LOADER_VARIABLE_GUID;
    EFI_STATUS res = EFI_SUCCESS;

    v_msg( L"LoaderFeatures: 0x%016x\n", loader_features );
    res = LibSetVariable( L"LoaderFeatures", &guid,
                          VARIABLE_BLOB( &loader_features ) );
    WARN_STATUS( res, L"Failed to SetVariable()" );

    return res;
}

EFI_STATUS set_loader_device_part_uuid ()
{
    EFI_GUID guid = LOADER_VARIABLE_GUID;
    EFI_LOADED_IMAGE *loaded_image;
    EFI_DEVICE_PATH *device_path;
    EFI_STATUS res = EFI_SUCCESS;
    EFI_GUID signature;
    CHAR16 *str = NULL;
    EFI_GUID lip_guid = LOADED_IMAGE_PROTOCOL;

    if( !LibImageHandle )
        return EFI_INVALID_PARAMETER;

    res = open_protocol( LibImageHandle, &lip_guid,
                         (VOID **)&loaded_image, LibImageHandle, NULL,
                         EFI_OPEN_PROTOCOL_GET_PROTOCOL );
    WARN_STATUS( res, L"Failed to open_protocol()" );

    device_path = DevicePathFromHandle( loaded_image->DeviceHandle );
    WARN_STATUS( res, L"Failed to DevicePathFromHandle()" );

    signature = get_drive_signature( device_path );
    WARN_STATUS( ( CompareMem( &signature, &NullGuid, sizeof (EFI_GUID) ) == 0 ),
                 L"Failed to get_drive_signature" );

    str = PoolPrint( L"%g", &signature );
    WARN_STATUS( ( str == NULL ), L"Failed to PoolPrint()" );

    if( !str )
    {
        res = EFI_OUT_OF_RESOURCES;
        goto exit;
    }

    v_msg( L"LoaderDevicePartUUID: %s\n", str );
    res = LibSetVariable( L"LoaderDevicePartUUID", &guid,
                          VARIABLE_STRING( str ) );
    WARN_STATUS( res, L"Failed to SetVariable()" );

    efi_free( str );

exit:
    close_protocol( LibImageHandle, &lip_guid, LibImageHandle, NULL );
    return res;
}

EFI_STATUS set_loader_entries (EFI_GUID **signatures)
{
    EFI_GUID guid = LOADER_VARIABLE_GUID;
    EFI_STATUS res = EFI_SUCCESS;
    CHAR16 data[2048];
    int len = 0;

    if( !signatures )
        return EFI_INVALID_PARAMETER;

    while( *signatures )
    {
        len += SPrint( &data[ len ], sizeof( data ) - len, L"auto-bootconf-%g",
                       *signatures++ );
        data[ len - 1 ] = 0;
    }

    v_msg( L"LoaderEntries:\n" );
    v_hex( 1, 0, len * sizeof( CHAR16 ), data );
    res = LibSetVariable( L"LoaderEntries", &guid, len * sizeof( CHAR16 ),
                          data );
    WARN_STATUS( res, L"Failed to SetVariable()" );

    return res;
}

EFI_STATUS set_loader_entry_default (EFI_GUID *signature)
{
    EFI_GUID guid = LOADER_VARIABLE_GUID;
    EFI_STATUS res = EFI_SUCCESS;
    CHAR16 *str = NULL;

    if( !signature )
        return EFI_INVALID_PARAMETER;

    str = PoolPrint( L"auto-bootconf-%g", signature );
    WARN_STATUS( ( str == NULL ), L"Failed to PoolPrint()" );

    if( !str )
        return EFI_OUT_OF_RESOURCES;

    v_msg( L"LoaderEntryDefault: %s\n", str );
    res = LibSetVariable( L"LoaderEntryDefault", &guid,
                          VARIABLE_STRING( str ) );
    WARN_STATUS( res, L"Failed to SetVariable()" );

    efi_free( str );

    return res;
}

EFI_STATUS set_loader_entry_selected (EFI_GUID *signature)
{
    EFI_GUID guid = LOADER_VARIABLE_GUID;
    EFI_STATUS res = EFI_SUCCESS;
    CHAR16 *str = NULL;

    if( !signature )
        return EFI_INVALID_PARAMETER;

    str = PoolPrint( L"auto-bootconf-%g", signature );
    WARN_STATUS( ( str == NULL ), L"Failed to PoolPrint()" );

    if( !str )
        return EFI_OUT_OF_RESOURCES;

    v_msg( L"LoaderEntrySelected: %s\n", str );
    res = LibSetVariable( L"LoaderEntrySelected", &guid,
                          VARIABLE_STRING( str ) );
    WARN_STATUS( res, L"Failed to SetVariable()" );

    efi_free( str );

    return res;
}

EFI_STATUS set_loader_image_identifier ()
{
    EFI_GUID guid = LOADER_VARIABLE_GUID;
    EFI_LOADED_IMAGE *loaded_image;
    EFI_STATUS res = EFI_SUCCESS;
    CHAR16 *str = NULL;
    EFI_GUID lip_guid = LOADED_IMAGE_PROTOCOL;

    if( !LibImageHandle )
        return EFI_INVALID_PARAMETER;

    res = open_protocol( LibImageHandle, &lip_guid,
                         (VOID **)&loaded_image, LibImageHandle, NULL,
                         EFI_OPEN_PROTOCOL_GET_PROTOCOL );
    WARN_STATUS( res, L"Failed to open_protocol()" );

    str = DevicePathToStr(loaded_image->FilePath);
    WARN_STATUS( ( str == NULL ), L"Failed to DevicePathToStr()" );

    if( !str )
    {
        res = EFI_OUT_OF_RESOURCES;
        goto exit;
    }

    v_msg( L"LoaderImageIdentifier: %s\n", str );
    res = LibSetVariable( L"LoaderImageIdentifier", &guid,
                          VARIABLE_STRING( str ) );
    WARN_STATUS( res, L"Failed to SetVariable()" );

    efi_free( str );

exit:
    close_protocol( LibImageHandle, &lip_guid, LibImageHandle, NULL );
    return res;
}

EFI_STATUS set_chainloader_device_part_uuid (EFI_HANDLE image_handle)
{
    EFI_GUID guid = LOADER_VARIABLE_GUID;
    EFI_LOADED_IMAGE *loaded_image;
    EFI_DEVICE_PATH *device_path;
    EFI_STATUS res = EFI_SUCCESS;
    EFI_GUID signature;
    CHAR16 *str = NULL;
    EFI_GUID lip_guid = LOADED_IMAGE_PROTOCOL;

    if( !image_handle )
        return EFI_INVALID_PARAMETER;

    res = open_protocol( image_handle, &lip_guid,
                         (VOID **)&loaded_image, image_handle, NULL,
                         EFI_OPEN_PROTOCOL_GET_PROTOCOL );
    WARN_STATUS( res, L"Failed to open_protocol()" );

    device_path = DevicePathFromHandle( loaded_image->DeviceHandle );
    WARN_STATUS( res, L"Failed to DevicePathFromHandle()" );

    signature = get_drive_signature( device_path );
    WARN_STATUS( ( CompareMem( &signature, &NullGuid, sizeof (EFI_GUID) ) == 0 ),
                 L"Failed to get_drive_signature" );

    str = PoolPrint( L"%g", &signature );
    WARN_STATUS( ( str == NULL ), L"Failed to PoolPrint()" );

    if( !str )
    {
        res = EFI_OUT_OF_RESOURCES;
        goto exit;
    }

    v_msg( L"ChainLoaderDevicePartUUID: %s\n", str );
    res = LibSetVariable( L"ChainLoaderDevicePartUUID", &guid,
                          VARIABLE_STRING( str ) );
    WARN_STATUS( res, L"Failed to SetVariable()" );

    efi_free( str );

exit:
    close_protocol( image_handle, &lip_guid, image_handle, NULL );
    return res;
}

EFI_STATUS set_chainloader_image_identifier (EFI_HANDLE image_handle)
{
    EFI_GUID guid = LOADER_VARIABLE_GUID;
    EFI_LOADED_IMAGE *loaded_image;
    EFI_STATUS res = EFI_SUCCESS;
    CHAR16 *str = NULL;
    EFI_GUID lip_guid = LOADED_IMAGE_PROTOCOL;

    if( !image_handle )
        return EFI_INVALID_PARAMETER;

    res = open_protocol( image_handle, &lip_guid,
                         (VOID **)&loaded_image, image_handle, NULL,
                         EFI_OPEN_PROTOCOL_GET_PROTOCOL );
    WARN_STATUS( res, L"Failed to open_protocol()" );

    str = DevicePathToStr( loaded_image->FilePath );
    WARN_STATUS( ( str == NULL ), L"Failed to DevicePathToStr()" );

    if( !str )
    {
        res = EFI_OUT_OF_RESOURCES;
        goto exit;
    }

    v_msg( L"ChainLoaderImageIdentifier: %s\n", str );
    res = LibSetVariable( L"ChainLoaderImageIdentifier", &guid,
                          VARIABLE_STRING( str ) );
    WARN_STATUS( res, L"Failed to SetVariable()" );

    efi_free( str );

exit:
    close_protocol( image_handle, &lip_guid, image_handle, NULL );
    return res;
}

EFI_STATUS set_chainloader_entry_flags (UINT64 flags)
{
    EFI_GUID guid = CHAINLOADER_VARIABLE_GUID;
    EFI_STATUS res = EFI_SUCCESS;

    v_msg( L"ChainLoaderEntryFlags: 0x%016x\n", flags );
    res = LibSetVariable( L"ChainLoaderEntryFlags", &guid,
                          VARIABLE_BLOB( &flags ) );
    WARN_STATUS( res, L"Failed to SetVariable()" );

    return res;
}
