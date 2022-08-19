#pragma once

// steamos-efi  --  SteamOS EFI Chainloader

// SPDX-License-Identifier: GPL-2.0+
// Copyright © 2022 Collabora Ltd
// Copyright © 2022 Valve Corporation

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

// ============================================================================

#include <efi.h>
#include "usb.h"

#define EFI_USBFN_IO_PROTOCOL_GUID \
    { 0x32d2963a, 0xfe5d, 0x4f30,  \
      { 0xb6, 0x33, 0x6e, 0x5d, 0xc5, 0x58, 0x3, 0xcc } };

typedef struct _EFI_USBFN_IO_PROTOCOL EFI_USBFN_IO_PROTOCOL;


