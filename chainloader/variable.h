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

#define ENTRY_FLAG_INVALID    1UL << 0
#define ENTRY_FLAG_BOOT_OTHER 1UL << 1
#define ENTRY_FLAG_UPDATE     1UL << 2

#define EFI_GLOBAL_VARIABLE_GUID                                \
    { 0x8BE4DF61, 0x93CA, 0x11d2,                               \
      { 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C } }

#define DECK_FIRMWARE_GUID                                      \
    { 0xf0393d2c, 0x78a4, 0x4bb9,                               \
      { 0xaf, 0x08, 0x29, 0x32, 0xca, 0x0d, 0xc1, 0x1e } }

void *get_efivar (CHAR16 *name, EFI_GUID *ns, UINTN *size);
EFI_STATUS del_efivar (CHAR16 *name, EFI_GUID *ns);
EFI_STATUS set_volatile_efivar   (CHAR16 *name, EFI_GUID *ns, UINTN len, void *d);
EFI_STATUS set_persistent_efivar (CHAR16 *name, EFI_GUID *ns, UINTN len, void *d);

EFI_STATUS set_loader_time_init_usec ();
EFI_STATUS set_loader_time_menu_usec ();
EFI_STATUS set_loader_time_exec_usec ();
EFI_STATUS set_loader_info ();
EFI_STATUS set_loader_firmware_info ();
EFI_STATUS set_loader_firmware_type ();
EFI_STATUS set_loader_features ();
EFI_STATUS set_loader_device_part_uuid ();
EFI_STATUS set_loader_image_identifier ();
EFI_GUID get_loader_entry_oneshot ();
EFI_STATUS set_loader_entries ( EFI_GUID **signatures);
EFI_STATUS set_loader_entry_default (EFI_GUID *signature);
EFI_STATUS set_loader_entry_selected (EFI_GUID *signature);
EFI_STATUS set_chainloader_device_part_uuid ();
EFI_STATUS set_chainloader_image_identifier ();
EFI_STATUS set_chainedloader_device_part_uuid (EFI_HANDLE image_handle);
EFI_STATUS set_chainloader_entry_flags (UINT64 flags);
INTN get_loader_config_timeout ();
BOOLEAN is_loader_config_timeout_oneshot_set ();
INTN get_loader_config_timeout_oneshot ();
UINTN get_chainloader_boot_attempts ();
UINTN get_hw_config_button_state (void);
EFI_STATUS set_chainloader_boot_attempts ();
