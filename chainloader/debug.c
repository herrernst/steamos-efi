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
#include <efiprot.h>

#include "util.h"

VOID dump_loaded_image (EFI_LOADED_IMAGE *image)
{
    EFI_HANDLE current = get_self_handle();

    Print( L"\n\
typedef struct {                                               \n\
    UINT32                          Revision;         %u       \n\
    EFI_HANDLE                      ParentHandle;     %x %s    \n\
    struct _EFI_SYSTEM_TABLE        *SystemTable;     %x       \n\
                                                               \n\
    // Source location of image                                \n\
    EFI_HANDLE                      DeviceHandle;     %x       \n\
    EFI_DEVICE_PATH                 *FilePath;        %s       \n\
    VOID                            *Reserved;        %x       \n\
                                                               \n\
    // Images load options                                     \n\
    UINT32                          LoadOptionsSize;  %u       \n\
    VOID                            *LoadOptions;   \"%s\"     \n\
                                                               \n\
    // Location of where image was loaded                      \n\
    VOID                            *ImageBase;       %x       \n\
    UINT64                          ImageSize;        %lu      \n\
    EFI_MEMORY_TYPE                 ImageCodeType;    %s       \n\
    EFI_MEMORY_TYPE                 ImageDataType;    %s       \n\
                                                               \n\
    // If the driver image supports a dynamic unload request   \n\
    EFI_IMAGE_UNLOAD                Unload;           %x       \n\
} EFI_LOADED_IMAGE_PROTOCOL;                                   \n",
           image->Revision,
           image->ParentHandle,
           (current ?
            ((current == image->ParentHandle)? L"OK": L"MISMATCH") :
            L"Existential error: No self image" ),
           (UINT64) image->SystemTable,
           image->DeviceHandle,
           DevicePathToStr( image->FilePath ),
           image->Reserved,
           image->LoadOptionsSize,
           (CHAR16 *)image->LoadOptions,
           (UINT64)image->ImageBase,
           image->ImageSize,
           efi_memtypestr( image->ImageCodeType ),
           efi_memtypestr( image->ImageDataType ),
           (UINT64) image->Unload );
}
