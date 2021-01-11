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

VOID * efi_alloc (UINTN s) { return AllocateZeroPool( s ); }
VOID   efi_free  (VOID *p) { if( p ) FreePool( p); }

EFI_HANDLE self_image;

CONST CHAR16 * efi_statstr (EFI_STATUS s)
{
    switch( s )
    {
      case EFI_SUCCESS:              return L"EFI_SUCCESS";
      case EFI_LOAD_ERROR:           return L"EFI_LOAD_ERROR";
      case EFI_INVALID_PARAMETER:    return L"EFI_INVALID_PARAMETER";
      case EFI_UNSUPPORTED:          return L"EFI_UNSUPPORTED";
      case EFI_BAD_BUFFER_SIZE:      return L"EFI_BAD_BUFFER_SIZE";
      case EFI_BUFFER_TOO_SMALL:     return L"EFI_BUFFER_TOO_SMALL";
      case EFI_NOT_READY:            return L"EFI_NOT_READY";
      case EFI_DEVICE_ERROR:         return L"EFI_DEVICE_ERROR";
      case EFI_WRITE_PROTECTED:      return L"EFI_WRITE_PROTECTED";
      case EFI_OUT_OF_RESOURCES:     return L"EFI_OUT_OF_RESOURCES";
      case EFI_VOLUME_CORRUPTED:     return L"EFI_VOLUME_CORRUPTED";
      case EFI_VOLUME_FULL:          return L"EFI_VOLUME_FULL";
      case EFI_NO_MEDIA:             return L"EFI_NO_MEDIA";
      case EFI_MEDIA_CHANGED:        return L"EFI_MEDIA_CHANGED";
      case EFI_NOT_FOUND:            return L"EFI_NOT_FOUND";
      case EFI_ACCESS_DENIED:        return L"EFI_ACCESS_DENIED";
      case EFI_NO_RESPONSE:          return L"EFI_NO_RESPONSE";
      case EFI_NO_MAPPING:           return L"EFI_NO_MAPPING";
      case EFI_TIMEOUT:              return L"EFI_TIMEOUT";
      case EFI_NOT_STARTED:          return L"EFI_NOT_STARTED";
      case EFI_ALREADY_STARTED:      return L"EFI_ALREADY_STARTED";
      case EFI_ABORTED:              return L"EFI_ABORTED";
      case EFI_ICMP_ERROR:           return L"EFI_ICMP_ERROR";
      case EFI_TFTP_ERROR:           return L"EFI_TFTP_ERROR";
      case EFI_PROTOCOL_ERROR:       return L"EFI_PROTOCOL_ERROR";
      case EFI_INCOMPATIBLE_VERSION: return L"EFI_INCOMPATIBLE_VERSION";
      case EFI_SECURITY_VIOLATION:   return L"EFI_SECURITY_VIOLATION";
      case EFI_CRC_ERROR:            return L"EFI_CRC_ERROR";
      case EFI_END_OF_MEDIA:         return L"EFI_END_OF_MEDIA";
      case EFI_END_OF_FILE:          return L"EFI_END_OF_FILE";
      case EFI_INVALID_LANGUAGE:     return L"EFI_INVALID_LANGUAGE";
      case EFI_COMPROMISED_DATA:     return L"EFI_COMPROMISED_DATA";
      default:
        return L"-UNKNOWN-";
    }
}

CONST CHAR16 *efi_memtypestr (EFI_MEMORY_TYPE m)
{
    switch( m )
    {
      case EfiReservedMemoryType:      return L"Reserved";
      case EfiLoaderCode:              return L"Loader Code";
      case EfiLoaderData:              return L"Loader Data";
      case EfiBootServicesCode:        return L"Boot Services Code";
      case EfiBootServicesData:        return L"Boot Services Data";
      case EfiRuntimeServicesCode:     return L"Runtime Services Code";
      case EfiRuntimeServicesData:     return L"Runtime Services Data";
      case EfiConventionalMemory:      return L"Conventional Memory";
      case EfiUnusableMemory:          return L"Unusable Memory";
      case EfiACPIReclaimMemory:       return L"ACPI Reclaim Memory";
      case EfiACPIMemoryNVS:           return L"ACPI Memory NVS";
      case EfiMemoryMappedIO:          return L"Memory Mapped IO";
      case EfiMemoryMappedIOPortSpace: return L"Memory Mapped IO Port Space";
      case EfiPalCode:                 return L"Pal Code";
      case EfiMaxMemoryType:           return L"(INVALID)";
      default:
        return L"(OUT OF RANGE)";
    }
}

VOID sleep (UINTN seconds)
{
    // sleep for at most 1 minute
    if( seconds && (seconds < 60) )
    {
        UINTN musec = 1000000 * seconds;
        uefi_call_wrapper( BS->Stall, 1, musec );
    }
}

EFI_STATUS get_handle_protocol (EFI_HANDLE *handle,
                                EFI_GUID *id,
                                OUT VOID **protocol)
{
    return uefi_call_wrapper( BS->HandleProtocol, 3, *handle, id, protocol );
}

EFI_STATUS get_protocol_handles (EFI_GUID *guid,
                                 OUT EFI_HANDLE **handles,
                                 OUT UINTN *count)
{
    return LibLocateHandle(ByProtocol, guid, NULL, count, handles);
}

EFI_STATUS get_protocol_instance_handle (EFI_GUID *id,
                                         VOID *protocol_instance,
                                         OUT EFI_HANDLE *handle)
{
    EFI_HANDLE *handles = NULL;
    UINTN max = 0;
    EFI_STATUS res;

    *handle = NULL;

    res = get_protocol_handles( id, &handles, &max );
    ERROR_RETURN( res, res, "", (UINT64)id );

    for( UINTN i = 0; !*handle && (i < max); i++ )
    {
        VOID *found = NULL;
        res = get_handle_protocol( &handles[ i ], id, &found );
        ERROR_CONTINUE( res, L"handle %x does not support protocol %x. what.",
                        (UINT64) handles[ i ], (UINT64) id );

        if( found == protocol_instance )
            *handle = handles[ i ];
    }

    efi_free( handles );

    return EFI_SUCCESS;
}

EFI_STATUS get_protocol (EFI_GUID *id,
                         VOID *registration,
                         OUT VOID **protocol)
{
    return uefi_call_wrapper( BS->LocateProtocol, 3, id, registration, protocol );
}

EFI_HANDLE get_self_handle (VOID)
{
    return self_image;
}

static EFI_HANDLE get_self_loaded_image (VOID)
{
    EFI_STATUS res;
    EFI_GUID lip_guid  = LOADED_IMAGE_PROTOCOL;
    EFI_LOADED_IMAGE *li = NULL;

    if( !self_image )
        ERROR_RETURN( EFI_NOT_STARTED, NULL,
                      L"Chainloader is not initialised yet\n" );

    res = get_handle_protocol( &self_image, &lip_guid, (VOID **) &li );
    ERROR_RETURN( res, NULL, L"No loaded image protocol on %x\n", self_image );

    return li;
}

EFI_HANDLE get_self_device_handle (VOID)
{
    EFI_LOADED_IMAGE *li = get_self_loaded_image();

    return li ? li->DeviceHandle : NULL;
}


EFI_DEVICE_PATH * get_self_device_path (VOID)
{
    EFI_STATUS res;
    EFI_GUID dp_guid   = DEVICE_PATH_PROTOCOL;
    EFI_GUID lidp_guid = EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL_GUID;
    EFI_DEVICE_PATH *lpath = NULL;
    EFI_DEVICE_PATH *dpath = NULL;
    EFI_HANDLE dh = get_self_device_handle();

    if( !dh )
        return NULL;

    res = get_handle_protocol( &dh, &lidp_guid, (VOID **)&lpath );
    if( res != EFI_SUCCESS )
        res = get_handle_protocol( &dh, &dp_guid, (VOID **)&dpath );

    WARN_STATUS( res, L"No DEVICE PATH type protos on self device handle\n" );

    return dpath ?: lpath;
}

EFI_DEVICE_PATH * get_self_file (VOID)
{
    EFI_LOADED_IMAGE *li = get_self_loaded_image();

    return li ? li->FilePath : NULL;
}


VOID initialise (EFI_HANDLE image)
{
    self_image = image;
}

EFI_DEVICE_PATH *
make_absolute_device_path (EFI_HANDLE device, CHAR16 *path)
{
    return FileDevicePath( device, path );
}

CHAR16 *
strwiden (CHAR8 *narrow)
{
    if( !narrow )
        return NULL;

    UINTN l = strlena( narrow ) + 1;
    CHAR16 *wide = ALLOC_OR_GOTO( l * sizeof(CHAR16), allocfail );

    for( UINTN i = 0; i < l; i++ )
        wide[ i ] = (CHAR16) narrow[ i ];
    return wide;

allocfail:
    return NULL;
}

CHAR8 *
strnarrow (CHAR16 *wide)
{
    if( !wide )
        return NULL;

    UINTN l = StrLen( wide ) + 1;
    CHAR8 *narrow = ALLOC_OR_GOTO( l, allocfail );

    // if any high bit is set, set the 8th bit in the narrow character:
    for( UINTN i = 0; i < l; i++ )
        narrow[ i ] = (CHAR8)
          (0xff & ((wide[ i ] & 0xff80) ? (wide[ i ] | 0x80) : wide[ i ]));
    return narrow;

allocfail:
    return NULL;
}

CHAR16 *resolve_path (CONST VOID *path, CONST CHAR16* relative_to, UINTN widen)
{
    UINTN plen;
    UINTN rlen;
    CHAR16 *wide = NULL;
    CHAR16 *rel  = NULL;
    CHAR16 *abs  = NULL;

    if( !path )
        return NULL;

    // make sure wide is a wide copy of path
    wide = widen ? strwiden( (CHAR8 *)path ): StrDuplicate( (CHAR16 *)path );

    if( !wide )
        return NULL;

    // unset or zero-length relative path treated as / (root):
    if( relative_to && (StrLen( relative_to ) > 0) )
        rel = (CHAR16 *) relative_to;
    else
        rel = L"\\";

    plen = StrLen( wide );
    rlen = StrLen( rel  );

    // empty path, we don't want to resolve anything:
    if( plen == 0 )
    {
        efi_free( wide );
        return NULL;
    }

    // path separators flipped:
    for( UINTN i = 0; i < plen; i++ )
        if( wide[ i ] == (CHAR16)'/' )
            wide[ i ] = (CHAR16)'\\';

    // apth is absolute, we're good to go:
    if( wide[ 0 ] == (CHAR16)'\\' )
        return wide;

    rel = StrDuplicate( rel );

    // path separators flipped:
    for( UINTN i = 0; i < rlen; i++ )
        if( rel[ i ] == (CHAR16)'/' )
            rel[ i ] = (CHAR16)'\\';

    // We strip the path element after the last /
    for( INTN i = (INTN) rlen - 1; i >= 0; i-- )
        if( rel[ i ] == (CHAR16)'\\' )
        {
            rel[ i ] = (CHAR16)0;
            rlen = i;
            break;
        }

    // add a / at the start (maybe); and in between; plus a trailing NUL
    abs = ALLOC_OR_GOTO( (plen + rlen + 3) * sizeof(CHAR16), allocfail );
    abs[ 0 ] = (CHAR16) 0;

    if( rel[ 0 ] != (CHAR16)'\\' )
        StrCat( abs, L"\\");
    StrCat( abs, rel );
    StrCat( abs, L"\\" );
    StrCat( abs, wide );

    efi_free( rel  );
    efi_free( wide );

    return abs;

allocfail:
    efi_free( rel  );
    efi_free( abs  );
    efi_free( wide );
    return NULL;
}
// ============================================================================
// EFI sadly has no UTC support so we need to roll our own:

static UINT8 max_month_day (EFI_TIME *time)
{
    UINT16 y;

    switch( time->Month )
    {
      case 1:  /* Jan */
      case 3:  /* Mar */
      case 5:  /* May */
      case 7:  /* Jul */
      case 8:  /* Aug */
      case 10: /* Oct */
      case 12: /* Dec */
        return 31;

      case 4:  /* Apr */
      case 6:  /* Jun */
      case 9:  /* Sep */
      case 11: /* Nov */
        return 30;

      case 2:  /* Feb */
        y = time->Year;
        // leap years divisible by 4 BUT centuries must also be div by 400:
        //       not-div-100  not-div-4             not-div-400
        return ( (y % 100) ? ((y % 4) ? 28 : 29) : ((y % 400) ? 28 : 29) );

      default:
        return 0;
    }
}

static inline void incr_month (EFI_TIME *time)
{
    if( time->Month == 12 )
    {
        time->Month = 1;
        time->Year++;
        return;
    }

    time->Month++;
}

static inline void incr_day (EFI_TIME *time)
{
    if( time->Day == max_month_day( time ) )
    {
        time->Day = 1;
        incr_month( time );
        return;
    }

    time->Day++;
}

static inline void incr_hour (EFI_TIME *time)
{
    if( time->Hour == 23 )
    {
        time->Hour = 0;
        incr_day( time );
        return;
    }

    time->Hour++;
}

static inline void incr_minute (EFI_TIME *time)
{
    if( time->Minute == 59 )
    {
        time->Minute = 0;
        incr_hour( time );
        return;
    }

    time->Minute++;
}

static inline void decr_month (EFI_TIME *time)
{
    if( time->Month == 1 )
    {
        time->Month = 12;
        time->Year--;
        return;
    }

    time->Month--;
}

static inline void decr_day (EFI_TIME *time)
{
    if( time->Day == 1 )
    {
        decr_month( time );
        time->Day = max_month_day( time );
        return;
    }

    time->Day--;
}

static inline void decr_hour (EFI_TIME *time)
{
    if( time->Hour == 0 )
    {
        time->Hour = 23;
        decr_day( time );
        return;
    }

    time->Hour--;
}

static inline void decr_minute (EFI_TIME *time)
{
    if( time->Minute == 0 )
    {
        time->Minute = 59;
        decr_hour( time );
        return;
    }

    time->Minute--;
}

// UTC = now + now.zone
// now.zoneis ± 24 hours (1440 minutes)
static VOID efi_time_to_utc (EFI_TIME *time)
{

    if( time->TimeZone == EFI_UNSPECIFIED_TIMEZONE )
        return;

    if( time->TimeZone > 0 )
        for( ; time->TimeZone; time->TimeZone-- )
            incr_minute( time );
    else if( time->TimeZone < 0 )
        for( ; time->TimeZone; time->TimeZone++ )
            decr_minute( time );
}

UINT64 local_datestamp (VOID)
{
    EFI_TIME now = { 0 };
    EFI_STATUS res = uefi_call_wrapper( RT->GetTime, 2, &now, NULL );

    if( res != EFI_SUCCESS )
        return 0;

    // number of form: YYYY mm DD HH MM SS
    return ( now.Second                 +
             (now.Minute * 100)         +
             (now.Hour   * 10000)       +
             (now.Day    * 1000000)     +
             (now.Month  * 100000000)   +
             (now.Year   * 10000000000) );
}

UINT64 utc_datestamp (VOID)
{
    EFI_TIME now = { 0 };
    EFI_STATUS res = uefi_call_wrapper( RT->GetTime, 2, &now, NULL );

    if( res != EFI_SUCCESS )
        return 0;

    efi_time_to_utc( &now );

    // number of form: YYYY mm DD HH MM SS
    return ( now.Second                 +
             (now.Minute * 100)         +
             (now.Hour   * 10000)       +
             (now.Day    * 1000000)     +
             (now.Month  * 100000000)   +
             (now.Year   * 10000000000) );
}

UINT64 local_timestamp (VOID)
{
    EFI_TIME now = { 0 };
    EFI_STATUS res = uefi_call_wrapper( RT->GetTime, 2, &now, NULL );

    if( res != EFI_SUCCESS )
        return 0;

    // number of form: YYYY mm DD HH MM SS
    return ( now.Second           +
             (now.Minute * 100)   +
             (now.Hour   * 10000) );
}

UINT64 utc_timestamp (VOID)
{
    EFI_TIME now = { 0 };
    EFI_STATUS res = uefi_call_wrapper( RT->GetTime, 2, &now, NULL );

    if( res != EFI_SUCCESS )
        return 0;

    efi_time_to_utc( &now );

    // number of form: YYYY mm DD HH MM SS
    return ( now.Second           +
             (now.Minute * 100)   +
             (now.Hour   * 10000) );
}
