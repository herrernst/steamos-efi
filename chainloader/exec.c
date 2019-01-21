// steamos-efi  --  SteamOS EFI Chainloader

// SPDX-License-Identifier: GPL-2.0+
// Copyright © 2018,2019 Collabora Ltd
// Copyright © 2018,2019 Valve Corporation
// Copyright © 2018,2019 Vivek Das Mohapatra <vivek@etla.org>

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
