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
