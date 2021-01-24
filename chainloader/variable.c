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

extern EFI_HANDLE LibImageHandle;

#define LOADER_VARIABLE_GUID \
    { 0x4a67b082, 0x0a4c, 0x41cf, {0xb6, 0xc7, 0x44, 0x0b, 0x29, 0xbb, 0x8c, 0x4f} }

#define VARIABLE_STRING(s) (UINTN)( ( StrLen( s ) + 1 ) * sizeof( CHAR16 ) ), (VOID *)( s )
#define VARIABLE_BLOB(s) (UINTN)(sizeof( *s )), (VOID *)( s )

/* Some facilities that does not exist in the efi lib */

static EFI_STATUS
OpenProtocol (
    IN EFI_HANDLE Handle,
    IN EFI_GUID *Protocol,
    OUT VOID **Interface OPTIONAL,
    IN EFI_HANDLE AgentHandle,
    IN EFI_HANDLE ControllerHandle,
    IN UINT32 Attributes
    )
{
    return uefi_call_wrapper( BS->OpenProtocol, 6, Handle, Protocol, Interface,
                              AgentHandle, ControllerHandle, Attributes );
}

static EFI_STATUS
CloseProtocol(
    IN EFI_HANDLE Handle,
    IN EFI_GUID *Protocol,
    IN EFI_HANDLE AgentHandle,
    IN EFI_HANDLE ControllerHandle
    )
{
    return uefi_call_wrapper( BS->CloseProtocol, 4, Handle, Protocol, AgentHandle,
                              ControllerHandle );
}

static EFI_GUID
GetMediaHardDriveSignature( EFI_DEVICE_PATH *device_path )
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

    FreePool( str );

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

    FreePool( str );

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

    FreePool( str );

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

    FreePool( str );

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

    if( !LibImageHandle )
        return EFI_INVALID_PARAMETER;

    res = OpenProtocol( LibImageHandle, &LoadedImageProtocol,
                        (VOID **)&loaded_image, LibImageHandle, NULL,
                        EFI_OPEN_PROTOCOL_GET_PROTOCOL );
    WARN_STATUS( res, L"Failed to OpenProtocol()" );

    device_path = DevicePathFromHandle( loaded_image->DeviceHandle );
    WARN_STATUS( res, L"Failed to DevicePathFromHandle()" );

    signature = GetMediaHardDriveSignature( device_path );
    WARN_STATUS( ( CompareMem( &signature, &NullGuid, sizeof (EFI_GUID) ) == 0 ),
                 L"Failed to GetMediaHardDriveSignature" );

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

    FreePool( str );

exit:
    CloseProtocol( LibImageHandle, &LoadedImageProtocol, LibImageHandle, NULL );
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

    FreePool( str );

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

    FreePool( str );

    return res;
}

EFI_STATUS set_loader_image_identifier ()
{
    EFI_GUID guid = LOADER_VARIABLE_GUID;
    EFI_LOADED_IMAGE *loaded_image;
    EFI_STATUS res = EFI_SUCCESS;
    CHAR16 *str = NULL;

    if( !LibImageHandle )
        return EFI_INVALID_PARAMETER;

    res = OpenProtocol( LibImageHandle, &LoadedImageProtocol,
                        (VOID **)&loaded_image, LibImageHandle, NULL,
                        EFI_OPEN_PROTOCOL_GET_PROTOCOL );
    WARN_STATUS( res, L"Failed to OpenProtocol()" );

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

    FreePool( str );

exit:
    CloseProtocol( LibImageHandle, &LoadedImageProtocol, LibImageHandle, NULL );
    return res;
}
