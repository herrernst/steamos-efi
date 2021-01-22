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

#pragma once

EFI_STATUS set_loader_time_init_usec ();
EFI_STATUS set_loader_time_exec_usec ();
EFI_STATUS set_loader_info ();
EFI_STATUS set_loader_firmware_info ();
EFI_STATUS set_loader_firmware_type ();
EFI_STATUS set_loader_features ();
EFI_STATUS set_loader_device_part_uuid ();
EFI_STATUS set_loader_image_identifier ();
