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

//
// Console control protocol (deprecated)
//

#define EFI_CONSOLE_CONTROL_PROTOCOL_GUID \
        { 0xf42f7782, 0x012e, 0x4c12, { 0x99, 0x56, 0x49, 0xf9, 0x43, 0x04, 0xf7, 0x21 } }
#define CONSOLE_CONTROL_PROTOCOL_GUID EFI_CONSOLE_CONTROL_PROTOCOL_GUID

struct _CONSOLE_CONTROL_PROTOCOL;

INTERFACE_DECL(_CONSOLE_CONTROL_PROTOCOL_GUID);

typedef enum {
    EfiConsoleControlScreenText,
    EfiConsoleControlScreenGraphics,
    EfiConsoleControlScreenMaxValue,
} EFI_CONSOLE_CONTROL_SCREEN_MODE;

typedef EFI_STATUS
(EFIAPI *EFI_CONSOLE_CONTROL_PROTOCOL_GET_MODE) (
    struct _CONSOLE_CONTROL_PROTOCOL         *This,
    EFI_CONSOLE_CONTROL_SCREEN_MODE          *Mode,
    BOOLEAN                                  *UgaExists,
    BOOLEAN                                  *StdInLocked
);

typedef EFI_STATUS
(EFIAPI *EFI_CONSOLE_CONTROL_PROTOCOL_SET_MODE) (
    struct _CONSOLE_CONTROL_PROTOCOL         *This,
    EFI_CONSOLE_CONTROL_SCREEN_MODE          Mode
);

typedef EFI_STATUS
(EFIAPI *EFI_CONSOLE_CONTROL_PROTOCOL_LOCK_STD_IN) (
    struct _CONSOLE_CONTROL_PROTOCOL         *This,
    CHAR16                                   *Password
);

typedef struct _CONSOLE_CONTROL_PROTOCOL {
    EFI_CONSOLE_CONTROL_PROTOCOL_GET_MODE    GetMode;
    EFI_CONSOLE_CONTROL_PROTOCOL_SET_MODE    SetMode;
    EFI_CONSOLE_CONTROL_PROTOCOL_LOCK_STD_IN LockStdIn;
} EFI_CONSOLE_CONTROL_PROTOCOL;

EFI_STATUS
ConsoleControlGetMode (
    struct _CONSOLE_CONTROL_PROTOCOL         *This,
    EFI_CONSOLE_CONTROL_SCREEN_MODE          *Mode,
    BOOLEAN                                  *UgaExists,
    BOOLEAN                                  *StdInLocked
    );

EFI_STATUS
ConsoleControlSetMode (
    struct _CONSOLE_CONTROL_PROTOCOL         *This,
    EFI_CONSOLE_CONTROL_SCREEN_MODE          Mode
    );

EFI_STATUS
ConsoleControlLockStdIn (
    struct _CONSOLE_CONTROL_PROTOCOL         *This,
    CHAR16                                   *Password
    );

extern EFI_GUID gEfiConsoleControlProtocolGuid;

//
// Text input protocol
//

EFI_STATUS
SimpleInputReset(
    IN struct _SIMPLE_INPUT_INTERFACE *This,
    IN BOOLEAN                        ExtendedVerification
    );

EFI_STATUS
SimpleInputReadKeyStroke(
    IN struct _SIMPLE_INPUT_INTERFACE *This,
    OUT EFI_INPUT_KEY                 *Key
    );

EFI_STATUS
SimpleInputWaitForKey(
    IN struct _SIMPLE_INPUT_INTERFACE *This,
    IN UINTN                          NumberOfEvents,
    OUT UINTN                         *Index
    );

//
// Input console
//

EFI_STATUS
ConInReset(
    IN BOOLEAN                        ExtendedVerification
    );

EFI_STATUS
ConInReadKeyStroke(
    OUT EFI_INPUT_KEY                 *Key
    );

EFI_STATUS
ConInWaitForKey(
    IN UINTN                          NumberOfEvents,
    OUT UINTN                         *Index
    );

//
// Simple text output protocol
//

EFI_STATUS
SimpleTextOutputString(
    IN struct _SIMPLE_TEXT_OUTPUT_INTERFACE *This,
    IN CHAR16                               *String
    );

EFI_STATUS
SimpleTextOutputQueryMode(
    IN struct _SIMPLE_TEXT_OUTPUT_INTERFACE *This,
    IN UINTN                                ModeNumber,
    OUT UINTN                               *Columns,
    OUT UINTN                               *Rows
    );

EFI_STATUS
SimpleTextOutputSetMode(
    IN struct _SIMPLE_TEXT_OUTPUT_INTERFACE *This,
    IN UINTN                                ModeNumber
    );

EFI_STATUS
SimpleTextOutputSetAttribute(
    IN struct _SIMPLE_TEXT_OUTPUT_INTERFACE *This,
    IN UINTN                                Attribute
    );

EFI_STATUS
SimpleTextOutputClearScreen(
    IN struct _SIMPLE_TEXT_OUTPUT_INTERFACE *This
    );

EFI_STATUS
SimpleTextOutputSetCursorPosition(
    IN struct _SIMPLE_TEXT_OUTPUT_INTERFACE *This,
    IN UINTN                                Column,
    IN UINTN                                Row
    );

EFI_STATUS
SimpleTextOutputEnableCursor(
    IN struct _SIMPLE_TEXT_OUTPUT_INTERFACE *This,
    IN BOOLEAN                              Enable
    );

//
// Output console
//

EFI_STATUS
ConOutOutputString(
    IN CHAR16 *String
    );

EFI_STATUS
ConOutQueryMode(
    IN UINTN  ModeNumber,
    OUT UINTN *Columns,
    OUT UINTN *Rows
    );

EFI_STATUS
ConOutSetMode(
    IN UINTN ModeNumber
    );

EFI_STATUS
ConOutSetAttribute(
    IN UINTN Attribute
    );

EFI_STATUS
ConOutClearScreen();

EFI_STATUS
ConOutSetCursorPosition(
    IN UINTN Column,
    IN UINTN Row
    );

EFI_STATUS
ConOutEnableCursor(
    IN BOOLEAN Enable
    );
