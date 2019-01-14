#include <efi.h>
#include <efilib.h>

#include "util.h"
#include "exec.h"
#include "err.h"

EFI_STATUS load_image (EFI_DEVICE_PATH *path, EFI_HANDLE *image)
{
    EFI_HANDLE current = get_self_handle();

    return
      uefi_call_wrapper( BS->LoadImage, 6, FALSE, current, path,
                         NULL, 0, image );
}

EFI_STATUS exec_image (EFI_HANDLE image, UINTN *code, CHAR16 **data)
{
    return uefi_call_wrapper( BS->StartImage, 3, image, code, data );
}

EFI_STATUS set_image_cmdline (EFI_HANDLE *image, CONST CHAR16 *cmdline,
                              EFI_LOADED_IMAGE **child)
{
    EFI_STATUS res;
    EFI_GUID load_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID;

    res = get_handle_protocol( image, &load_guid, (VOID **) child );
    ERROR_RETURN( res, res, L"" );

    if( cmdline )
    {
        (*child)->LoadOptions = (CHAR16 *)cmdline;
        (*child)->LoadOptionsSize = StrLen( cmdline );
    }
    else
    {
        (*child)->LoadOptions = L"";
        (*child)->LoadOptionsSize = 0;
    }

    return EFI_SUCCESS;
}
