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

#include <efi.h>
#include <efilib.h>
#include <efiprot.h>
#include <eficon.h>

#include "console.h"

//
// Console control protocol (deprecated)
//

EFI_STATUS
ConsoleControlGetMode (
    struct _CONSOLE_CONTROL_PROTOCOL         *This,
    EFI_CONSOLE_CONTROL_SCREEN_MODE          *Mode,
    BOOLEAN                                  *UgaExists,
    BOOLEAN                                  *StdInLocked
    )
{
    return uefi_call_wrapper( This->GetMode, 4, This, Mode, UgaExists,
                              StdInLocked );
}

EFI_STATUS
ConsoleControlSetMode (
    struct _CONSOLE_CONTROL_PROTOCOL         *This,
    EFI_CONSOLE_CONTROL_SCREEN_MODE          Mode
    )
{
    return uefi_call_wrapper( This->SetMode, 2, This, Mode );
}

EFI_STATUS
ConsoleControlLockStdIn (
    struct _CONSOLE_CONTROL_PROTOCOL         *This,
    CHAR16                                   *Password
    )
{
    return uefi_call_wrapper( This->LockStdIn, 2, This, Password );
}

EFI_GUID gEfiConsoleControlProtocolGuid = EFI_CONSOLE_CONTROL_PROTOCOL_GUID;

//
// Text input protocol
//

EFI_STATUS
SimpleInputReset(
    IN struct _SIMPLE_INPUT_INTERFACE *This,
    IN BOOLEAN                        ExtendedVerification
    )
{
    return uefi_call_wrapper( This->Reset, 2, This, ExtendedVerification );
}

EFI_STATUS
SimpleInputReadKeyStroke(
    IN struct _SIMPLE_INPUT_INTERFACE *This,
    OUT EFI_INPUT_KEY                 *Key
    )
{
    return uefi_call_wrapper( This->ReadKeyStroke, 2, This, Key );
}

EFI_STATUS
SimpleInputWaitForKey(
    IN struct _SIMPLE_INPUT_INTERFACE *This,
    IN UINTN                          NumberOfEvents,
    OUT UINTN                         *Index
    )
{
    return uefi_call_wrapper( BS->WaitForEvent, 3, NumberOfEvents,
                              &This->WaitForKey, Index );
}

//
// Input console
//

EFI_STATUS
ConInReset(
    IN BOOLEAN                        ExtendedVerification
    )
{
    return SimpleInputReset( ST->ConIn, ExtendedVerification );
}

EFI_STATUS
ConInReadKeyStroke(
    OUT EFI_INPUT_KEY                 *Key
    )
{
    return SimpleInputReadKeyStroke( ST->ConIn, Key );
}

EFI_STATUS
ConInWaitForKey(
    IN UINTN                          NumberOfEvents,
    OUT UINTN                         *Index
    )
{
    return SimpleInputWaitForKey( ST->ConIn, NumberOfEvents, Index );
}

//
// Simple text output protocol
//

EFI_STATUS
SimpleTextOutputString(
    IN struct _SIMPLE_TEXT_OUTPUT_INTERFACE *This,
    IN CHAR16                               *String
    )
{
    return uefi_call_wrapper( This->OutputString, 2, This, String );
}

EFI_STATUS
SimpleTextOutputQueryMode(
    IN struct _SIMPLE_TEXT_OUTPUT_INTERFACE *This,
    IN UINTN                                ModeNumber,
    OUT UINTN                               *Columns,
    OUT UINTN                               *Rows
    )
{
    return uefi_call_wrapper( This->QueryMode, 4, This, ModeNumber, Columns,
                              Rows );
}

EFI_STATUS
SimpleTextOutputSetMode(
    IN struct _SIMPLE_TEXT_OUTPUT_INTERFACE *This,
    IN UINTN                                ModeNumber
    )
{
    return uefi_call_wrapper( This->SetMode, 1, This, ModeNumber );
}

EFI_STATUS
SimpleTextOutputSetAttribute(
    IN struct _SIMPLE_TEXT_OUTPUT_INTERFACE *This,
    IN UINTN                                Attribute
    )
{
    return uefi_call_wrapper( This->SetAttribute, 2, This, Attribute );
}

EFI_STATUS
SimpleTextOutputClearScreen(
    IN struct _SIMPLE_TEXT_OUTPUT_INTERFACE *This
    )
{
    return uefi_call_wrapper( This->ClearScreen, 1, This );
}

EFI_STATUS
SimpleTextOutputSetCursorPosition(
    IN struct _SIMPLE_TEXT_OUTPUT_INTERFACE *This,
    IN UINTN                                Column,
    IN UINTN                                Row
    )
{
    return uefi_call_wrapper( This->SetCursorPosition, 2, This, Column, Row );
}

EFI_STATUS
SimpleTextOutputEnableCursor(
    IN struct _SIMPLE_TEXT_OUTPUT_INTERFACE *This,
    IN BOOLEAN                              Enable
    )
{
    return uefi_call_wrapper( This->EnableCursor, 2, This, Enable);
}

//
// Output console
//

EFI_STATUS
ConOutOutputString(
    IN CHAR16 *String
    )
{
    return SimpleTextOutputString( ST->ConOut, String );
}

EFI_STATUS
ConOutQueryMode(
    IN UINTN  ModeNumber,
    OUT UINTN *Columns,
    OUT UINTN *Rows
    )
{
    return SimpleTextOutputQueryMode( ST->ConOut, ModeNumber, Columns, Rows );
}

EFI_STATUS
ConOutSetMode(
    IN UINTN ModeNumber
    )
{
    return SimpleTextOutputSetMode( ST->ConOut, ModeNumber );
}

EFI_STATUS
ConOutSetAttribute(
    IN UINTN Attribute
    )
{
    return SimpleTextOutputSetAttribute( ST->ConOut, Attribute );
}

EFI_STATUS
ConOutClearScreen()
{
    return SimpleTextOutputClearScreen( ST->ConOut );
}

EFI_STATUS
ConOutSetCursorPosition(
    IN UINTN Column,
    IN UINTN Row
    )
{
    return SimpleTextOutputSetCursorPosition( ST->ConOut, Column, Row );
}

EFI_STATUS
ConOutEnableCursor(
    IN BOOLEAN Enable
    )
{
    return SimpleTextOutputEnableCursor( ST->ConOut, Enable );
}
