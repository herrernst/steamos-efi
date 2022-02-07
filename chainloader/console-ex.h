#pragma once

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

// ============================================================================
// SIMPLE_TEXT_INPUT_EX_PROTOCOL

#define EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL_GUID \
    { 0xdd9e7534, 0x7762, 0x4698, \
      { 0x8c, 0x14, 0xf5, 0x85, 0x17, 0xa6, 0x25, 0xaa } }

INTERFACE_DECL (_EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL);

typedef UINT8 EFI_KEY_TOGGLE_STATE;

#define EFI_TOGGLE_STATE_VALID 0x80
#define EFI_KEY_STATE_EXPOSED  0x40
#define EFI_SCROLL_LOCK_ACTIVE 0x01
#define EFI_NUM_LOCK_ACTIVE    0x02
#define EFI_SYSRQ_PRESSED      0x04

#define EFI_SHIFT_STATE_VALID 0x80000000

typedef struct
{
    UINT32 shift;
    EFI_KEY_TOGGLE_STATE toggle;
} EFI_KEY_STATE;

typedef struct
{
    EFI_INPUT_KEY key;
    EFI_KEY_STATE state;
} EFI_KEY_DATA;

typedef EFI_STATUS
(EFIAPI *EFI_INPUT_RESET_EX)
    (IN struct _EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *this,
     IN BOOLEAN verify);

typedef EFI_STATUS
(EFIAPI *EFI_INPUT_READ_KEY_EX)
    (IN struct _EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *this,
     OUT EFI_KEY_DATA *key);

typedef EFI_STATUS
(EFIAPI *EFI_INPUT_SET_STATE)
    (IN struct _EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *this,
     IN EFI_KEY_TOGGLE_STATE);

typedef EFI_STATUS (EFIAPI *EFI_KEY_HANDLER) (IN EFI_KEY_DATA *key);

typedef EFI_STATUS
(EFIAPI *EFI_INPUT_UNREGISTER_KEY)
    (IN struct _EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *this,
     IN VOID *registered);

typedef EFI_STATUS
(EFIAPI *EFI_INPUT_REGISTER_KEY)
    (IN struct _EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *this,
     IN EFI_KEY_DATA *key,
     IN EFI_KEY_HANDLER handler,
     OUT VOID **registered);

typedef struct _EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL
{
    EFI_INPUT_RESET_EX       reset;
    EFI_INPUT_READ_KEY_EX    read_key;
    EFI_EVENT                wait_for_key;
    EFI_INPUT_SET_STATE      set_state;
    EFI_INPUT_REGISTER_KEY   register_key;
    EFI_INPUT_UNREGISTER_KEY unregister_key;
} EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL;

// ============================================================================
EFI_HANDLE *bind_key (UINT16 scan, CHAR16 chr, IN EFI_KEY_HANDLER handler);
EFI_STATUS unbind_key (EFI_HANDLE *binding);