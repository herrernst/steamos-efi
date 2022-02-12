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

#include "err.h"
#include "util.h"
#include "console-ex.h"

static EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *console;

static BOOLEAN
init_console_ex (void)
{
    EFI_STATUS res;
    static EFI_GUID input_guid = EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL_GUID;

    if( !console )
    {
        EFI_KEY_TOGGLE_STATE state = EFI_KEY_STATE_EXPOSED;

        res = get_handle_protocol( &ST->ConsoleInHandle, &input_guid,
                                   (VOID **)&console );
        ERROR_RETURN( res, FALSE, L"console-ex init failed" );

        // clear out any buffered keys etc
        reset_console();

        // In theory this allows things like incomplete keypresses
        // (possibly key-press but no key-release yet? - docs unclear)
        // to be detected but not all UEFI firmware supports this
        // (The deck, at least as of VANGOGH 101, does not):
        res = uefi_call_wrapper( console->SetState, 2, console, &state );

        if( EFI_ERROR(res) && verbose )
            v_msg( L"console-ex set_state error: %d (likely harmless)\n", res );
    }

    if( console )
        return TRUE;

    return FALSE;
}

EFI_STATUS reset_console (VOID)
{
    if( !init_console_ex() )
        return EFI_NOT_READY;

    return uefi_call_wrapper( console->Reset, 2, console, FALSE );
}

EFI_HANDLE *
bind_key (UINT16 scan, CHAR16 chr, IN EFI_KEY_NOTIFY_FUNCTION handler)
{
    EFI_STATUS res;
    EFI_HANDLE *binding;
    EFI_KEY_DATA key = { { SCAN_NULL, CHAR_NULL },
                         { 0, 0 } };

    key.Key.ScanCode = scan;
    key.Key.UnicodeChar = chr;

    if( !init_console_ex() )
        return NULL;

    res = uefi_call_wrapper( console->RegisterKeyNotify, 4, console,
                             &key, handler, (VOID **)&binding );

    ERROR_RETURN( res, NULL,
                  L"Cannot bind key {%u, 0x%04x} to callback\n", scan, chr );

    return binding;
}

EFI_STATUS
unbind_key (EFI_HANDLE *binding)
{
    if( !console )
        return EFI_NOT_READY;

    return uefi_call_wrapper( console->UnregisterKeyNotify, 2,
                              console, binding );
}
