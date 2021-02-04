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

typedef struct _SIMPLE_INPUT_INTERFACE INPUT_INTERFACE;
typedef struct _SIMPLE_TEXT_OUTPUT_INTERFACE OUTPUT_INTERFACE;

//
// Console control protocol (deprecated)
//

#define EFI_CONSOLE_CONTROL_PROTOCOL_GUID \
        { 0xf42f7782, 0x012e, 0x4c12, { 0x99, 0x56, 0x49, 0xf9, 0x43, 0x04, 0xf7, 0x21 } }
#define CONSOLE_CONTROL_PROTOCOL_GUID EFI_CONSOLE_CONTROL_PROTOCOL_GUID

struct _CONSOLE_CONTROL_PROTOCOL;

INTERFACE_DECL(_CONSOLE_CONTROL_PROTOCOL_GUID);

typedef enum
{
    CONCTL_SCREEN_TEXT,
    CONCTL_SCREEN_GRAPHICS,
    CONCTL_SCREEN_MAX,
} EFI_CONSOLE_CONTROL_SCREEN_MODE;

typedef EFI_STATUS
(EFIAPI *EFI_CONSOLE_CONTROL_PROTOCOL_GET_MODE)
    (struct _CONSOLE_CONTROL_PROTOCOL *ctl,
     EFI_CONSOLE_CONTROL_SCREEN_MODE  *mode,
     BOOLEAN                          *have_uga,
     BOOLEAN                          *stdin_locked);

typedef EFI_STATUS
(EFIAPI *EFI_CONSOLE_CONTROL_PROTOCOL_SET_MODE)
    (struct _CONSOLE_CONTROL_PROTOCOL *ctl,
     EFI_CONSOLE_CONTROL_SCREEN_MODE mode);

typedef EFI_STATUS
(EFIAPI *EFI_CONSOLE_CONTROL_PROTOCOL_LOCK_STDIN)
    (struct _CONSOLE_CONTROL_PROTOCOL         *ctl,
     CHAR16                                   *passphrase);

typedef struct _CONSOLE_CONTROL_PROTOCOL
{
    EFI_CONSOLE_CONTROL_PROTOCOL_GET_MODE   get_mode;
    EFI_CONSOLE_CONTROL_PROTOCOL_SET_MODE   set_mode;
    EFI_CONSOLE_CONTROL_PROTOCOL_LOCK_STDIN lock_stdin;
} EFI_CONSOLE_CONTROL_PROTOCOL;

EFI_STATUS
conctl_get_mode (EFI_CONSOLE_CONTROL_PROTOCOL    *ctl,
                 EFI_CONSOLE_CONTROL_SCREEN_MODE *mode,
                 BOOLEAN                         *have_uga,
                 BOOLEAN                         *stdin_locked);

EFI_STATUS
conctl_set_mode (EFI_CONSOLE_CONTROL_PROTOCOL    *ctl,
                 EFI_CONSOLE_CONTROL_SCREEN_MODE  mode);
EFI_STATUS
conctl_lock_stdin (EFI_CONSOLE_CONTROL_PROTOCOL *ctl,
                   CHAR16                       *passphrase);

//
// Text input protocol
//

EFI_STATUS
input_reset (IN INPUT_INTERFACE *io,
             IN BOOLEAN          verify);

EFI_STATUS
read_key (IN INPUT_INTERFACE *io,
          OUT EFI_INPUT_KEY  *key);

EFI_STATUS
wait_key (IN INPUT_INTERFACE *io,
          IN UINTN            event_count,
          OUT UINTN          *index);

//
// Input console
//

EFI_STATUS con_reset (IN BOOLEAN verify);
EFI_STATUS con_read_key (OUT EFI_INPUT_KEY *key);
EFI_STATUS con_wait_key (IN UINTN event_count, OUT UINTN *index);

//
// Simple text output protocol
//

EFI_STATUS output_text (IN OUTPUT_INTERFACE *io, IN CHAR16 *str);

EFI_STATUS output_mode_info (IN OUTPUT_INTERFACE *io,
                             IN UINTN             mode,
                             OUT UINTN           *cols,
                             OUT UINTN           *rows);

EFI_STATUS set_output_mode (IN OUTPUT_INTERFACE *io, IN UINTN mode);
EFI_STATUS set_output_attribute (IN OUTPUT_INTERFACE *io, IN UINTN attr);
EFI_STATUS clear_screen (IN OUTPUT_INTERFACE *io);
EFI_STATUS set_cursor_position (IN OUTPUT_INTERFACE *io, IN UINTN col, IN UINTN row);
EFI_STATUS enable_cursor (IN OUTPUT_INTERFACE *io, IN BOOLEAN enable);

//
// Output console
//

INTN con_get_max_output_mode ();
INTN con_get_output_mode ();
EFI_STATUS con_output_text (IN CHAR16 *str);
EFI_STATUS con_output_mode_info (IN UINTN mode, OUT UINTN *cols, OUT UINTN *rows);
EFI_STATUS con_set_output_mode (IN UINTN mode);
EFI_STATUS con_set_output_attribute (IN UINTN attribute);
EFI_STATUS con_clear_screen ();
EFI_STATUS con_set_cursor_position (IN UINTN col, IN UINTN row);
EFI_STATUS con_enable_cursor (IN BOOLEAN enable);
