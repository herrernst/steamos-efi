#include <efi.h>
#include <efilib.h>
#include <efiprot.h>

#include "err.h"
#include "util.h"

VOID * efi_alloc (IN UINTN s) { return AllocateZeroPool( s ); }
VOID   efi_free  (IN VOID *p) { FreePool( p); }

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

EFI_STATUS get_handle_protocol (IN EFI_HANDLE *handle,
                                IN EFI_GUID *id,
                                OUT VOID **protocol)
{
    return uefi_call_wrapper( BS->HandleProtocol, 3, *handle, id, protocol );
}

EFI_STATUS get_protocol_handles (IN EFI_GUID *guid,
                                 OUT EFI_HANDLE **handles,
                                 IN OUT UINTN *count)
{
    return LibLocateHandle(ByProtocol, guid, NULL, count, handles);
}

EFI_STATUS get_protocol_instance_handle (IN EFI_GUID *id,
                                         IN VOID *protocol_instance,
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
