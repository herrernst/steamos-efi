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

#pragma once

#ifndef NO_EFI_TYPES
#include <efi.h>
#else
#include "bootconf/efi.h"
#endif

#ifndef EFI_FILE_RESERVED
#ifdef  EFI_FILE_RESERVIED
#define EFI_FILE_RESERVED EFI_FILE_RESERVIED
#endif
#endif

#define MAXFSNAMLEN 200
#define BOOTCONFPATH L"SteamOS\\bootconf"
#define EFIDIR       L"\\EFI"
#define GRUBLDR     EFIDIR L"\\steamos\\grubx64.efi"
#define SYSTEMDLDR  EFIDIR L"\\SYSTEMD\\SYSTEMD-BOOTX64.EFI"
#define DEFAULTLDR  EFIDIR L"\\Boot\\bootx64.efi"
#define STEAMOSLDR  GRUBLDR
#define CHAINLDR    EFIDIR L"\\Shell\\steamcl.efi"

#ifndef NO_EFI_TYPES
VOID * efi_alloc (IN UINTN s);
VOID   efi_free  (IN VOID *p);

CONST CHAR16 * efi_statstr (EFI_STATUS s);
CONST CHAR16 * efi_memtypestr (EFI_MEMORY_TYPE m);

EFI_STATUS get_handle_protocol (EFI_HANDLE *handle,
                                EFI_GUID *id,
                                OUT VOID **protocol);

EFI_STATUS get_protocol_handles (EFI_GUID *guid,
                                 OUT EFI_HANDLE **handles,
                                 OUT UINTN *count);

EFI_STATUS get_protocol_instance_handle (EFI_GUID *id,
                                         VOID *protocol,
                                         OUT EFI_HANDLE *handle);

EFI_DEVICE_PATH * make_absolute_device_path (EFI_HANDLE device, CHAR16 *path);
EFI_HANDLE get_self_handle (VOID);
VOID initialise (EFI_HANDLE image, UINTN verbose);
#endif

CHAR16 *strwiden (CHAR8 *narrow);
CHAR8  *strnarrow (CHAR16 *wide);

CHAR16 *resolve_path (CONST VOID *path, CONST CHAR16* relative_to, UINTN widen);

VOID sleep (UINTN seconds);

UINT64 local_datestamp (VOID);
UINT64 utc_datestamp (VOID);
UINT64 local_timestamp (VOID);
UINT64 utc_timestamp (VOID);
