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
    switch (s)
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
    switch (m)
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
        res = get_handle_protocol( &handles[i], id, &found );
        ERROR_CONTINUE( res, L"handle %x does not support protocol %x. what.",
                        (UINT64) handles[i], (UINT64) id );

        if( found == protocol_instance )
            *handle = handles[i];
    }

    efi_free( handles );

    return EFI_SUCCESS;
}

EFI_HANDLE get_self_handle (VOID)
{
    return self_image;
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
        narrow[i] =
          (CHAR8) (0xff & ((wide[i] & 0xff80) ? (wide[i] | 0x80) : wide[i]));
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

    // empty path, just return the relative_to path
    // not 100% convinced this shouldn't be an error, but whatever.
    if( plen == 0 )
    {
        efi_free( wide );
        return StrDuplicate( rel );
    }

    // path separators flipped:
    for( UINTN i = 0; i < plen; i++ )
        if( wide[ i ] == (CHAR16)'/' )
            wide[ i ] = (CHAR16)'\\';

    // apth is absolute, we're good to go:
    if( wide[0] == (CHAR16)'\\' )
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
    abs[0] = (CHAR16) 0;

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
