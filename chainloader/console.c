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
// Text input protocol
//

EFI_STATUS
input_reset (IN INPUT_INTERFACE *io,
             IN BOOLEAN          verify)
{
    return uefi_call_wrapper( io->Reset, 2, io, verify );
}

EFI_STATUS
read_key (IN INPUT_INTERFACE *io,
          OUT EFI_INPUT_KEY  *key)
{
    return uefi_call_wrapper( io->ReadKeyStroke, 2, io, key );
}

EFI_STATUS
wait_key (IN INPUT_INTERFACE *io,
          IN UINTN            event_count,
          OUT UINTN          *index)
{
    return uefi_call_wrapper( BS->WaitForEvent, 3,
                              event_count, &io->WaitForKey, index );
}

//
// Input console
//

EFI_STATUS
con_reset (IN BOOLEAN verify)
{
    return input_reset( ST->ConIn, verify );
}

EFI_STATUS
con_read_key (OUT EFI_INPUT_KEY *key)
{
    return read_key( ST->ConIn, key );
}

EFI_STATUS
con_wait_key (IN UINTN   event_count,
              OUT UINTN *index)
{
    return wait_key( ST->ConIn, event_count, index );
}

//
// Simple text output protocol
//

EFI_STATUS
output_text (IN OUTPUT_INTERFACE *io,
             IN CHAR16           *str)
{
    return uefi_call_wrapper( io->OutputString, 2, io, str );
}

EFI_STATUS
output_mode_info (IN OUTPUT_INTERFACE *io,
                  IN UINTN             mode,
                  OUT UINTN           *cols,
                  OUT UINTN           *rows)
{
    return uefi_call_wrapper( io->QueryMode, 4, io, mode, cols, rows );
}

EFI_STATUS
set_output_mode (IN OUTPUT_INTERFACE *io,
                 IN UINTN             mode)
{
    return uefi_call_wrapper( io->SetMode, 1, io, mode );
}

EFI_STATUS
set_output_attribute (IN OUTPUT_INTERFACE *io,
                      IN UINTN             attr)
{
    return uefi_call_wrapper( io->SetAttribute, 2, io, attr );
}

EFI_STATUS
clear_screen (IN OUTPUT_INTERFACE *io)
{
    return uefi_call_wrapper( io->ClearScreen, 1, io );
}

EFI_STATUS
set_cursor_position (IN OUTPUT_INTERFACE *io,
                     IN UINTN             col,
                     IN UINTN             row)
{
    return uefi_call_wrapper( io->SetCursorPosition, 3, io, col, row );
}

EFI_STATUS
enable_cursor (IN OUTPUT_INTERFACE *io,
               IN BOOLEAN           enable)
{
    return uefi_call_wrapper( io->EnableCursor, 2, io, enable );
}

//
// Output console
//

INTN
con_get_max_output_mode ()
{
    return ST->ConOut->Mode->MaxMode;
}

EFI_STATUS
con_output_text (IN CHAR16 *str)
{
    return output_text( ST->ConOut, str );
}

EFI_STATUS
con_output_mode_info (IN UINTN  mode,
                      OUT UINTN *cols,
                      OUT UINTN *rows)
{
    return output_mode_info( ST->ConOut, mode, cols, rows );
}

INTN
con_get_output_mode ()
{
    return ST->ConOut->Mode->Mode;
}

EFI_STATUS
con_set_output_mode (IN UINTN mode)
{
    return set_output_mode( ST->ConOut, mode );
}

EFI_STATUS
con_set_output_attribute (IN UINTN attribute)
{
    return set_output_attribute( ST->ConOut, attribute );
}

EFI_STATUS
con_clear_screen ()
{
    return clear_screen( ST->ConOut );
}

EFI_STATUS
con_set_cursor_position (IN UINTN col, IN UINTN row)
{
    return set_cursor_position( ST->ConOut, col, row );
}

EFI_STATUS
con_enable_cursor (IN BOOLEAN enable)
{
    return enable_cursor( ST->ConOut, enable );
}
