// steamos-efi  --  SteamOS EFI Chainloader

// SPDX-License-Identifier: GPL-2.0+
// Copyright © 2018,2021 Collabora Ltd
// Copyright © 2018,2021 Valve Corporation
// Copyright © 2018,2020 Vivek Das Mohapatra <vivek@etla.org>

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

#include "err.h"
#include "util.h"
#include "console.h"
#include "console-ex.h"

#define SELECTED_ATTRIBUTES (EFI_MAGENTA   | EFI_BACKGROUND_BLACK)
#define DEFAULT_ATTRIBUTES  (EFI_LIGHTGRAY | EFI_BACKGROUND_BLACK)

static EFI_STATUS console_mode ()
{
    EFI_CONSOLE_CONTROL_SCREEN_MODE mode;
    EFI_CONSOLE_CONTROL_PROTOCOL *ccp;
    EFI_STATUS res;
    BOOLEAN locked;
    BOOLEAN uga;
    EFI_GUID ccp_guid = EFI_CONSOLE_CONTROL_PROTOCOL_GUID;

    res = get_protocol( &ccp_guid, NULL, (VOID **)&ccp );
    if( res == EFI_NOT_FOUND )
        return res;
    ERROR_RETURN( res, res, "Could not get_protocol: %r\n", res );

    res = conctl_get_mode( ccp, &mode, &uga, &locked );
    ERROR_RETURN( res, res, "Could not conctl_get_mode: %r\n", res );

    if( mode == CONCTL_SCREEN_TEXT )
        return EFI_SUCCESS;

    res = conctl_set_mode( ccp, CONCTL_SCREEN_TEXT );
    ERROR_RETURN( res, res, "Could not conctl_set_mode: %r\n", res );

    return EFI_SUCCESS;
}

//static EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *io_ex;
static EFI_HANDLE *key_binding;

static EFI_STATUS
EFIAPI
clicked (IN EFI_KEY_DATA *key)
{
    v_msg( L"Clicked: %u.%u :: %u.%u\n",
           key->Key.ScanCode,
           key->Key.UnicodeChar,
           key->KeyState.KeyShiftState,
           key->KeyState.KeyToggleState);

    return EFI_SUCCESS;
}

EFI_STATUS
efi_main (EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *sys_table)
{
    INTN i;
    UINTN rows, cols;
    EFI_STATUS res = EFI_SUCCESS;
    INTN console_max_mode;

    initialise( image_handle, sys_table );
    set_verbosity( 1 );

    v_msg( L"\n\n\n\nKEY LOGGER\n" );

    console_max_mode = con_get_max_output_mode();

    res = console_mode();
    if( res == EFI_NOT_FOUND ) res = EFI_SUCCESS;
    ERROR_RETURN( res, res, L"Console not initialised" );

    v_msg( L"Console initialised\n" );

    if( console_max_mode > 0 )
    {
        for( i = console_max_mode - 1; i != 0; i-- )
        {
            res = con_set_output_mode( i );
            if( EFI_ERROR( res ) ) continue;
            v_msg( L"  mode: %ld\n", i  );
            break;
        }
    }

    res = con_output_mode_info( con_get_output_mode(), &cols, &rows);
    if( EFI_ERROR( res ) )
    {
        cols = 80;
        rows = 25;
    }

    v_msg( L"  area: %ld x %ld\n", rows, cols );

    // con_clear_screen();
    con_enable_cursor( FALSE );

    if( !EFI_ERROR( res ) )
    {
        key_binding = bind_key( SCAN_NULL, CHAR_TAB, clicked );
        v_msg( L"registering handler: 0x%lx\n", key_binding );
    }

    v_msg( L"Starting key log loop\n" );

    for( ;; )
    {
        EFI_INPUT_KEY key;
        BOOLEAN logged = FALSE;

        con_set_output_attribute( DEFAULT_ATTRIBUTES );

        res = WaitForSingleEvent( ST->ConIn->WaitForKey, 0 );
        ERROR_BREAK( res, L"Could not wait (single event): %r\n", res );

        res = con_read_key( &key );
        ERROR_BREAK( res, L"Could not con_read_key: %r\n", res );

        if( logged ) continue;

        logged = TRUE;
        switch( key.UnicodeChar )
        {
          case CHAR_LINEFEED:        Print( L"key { %d LF }\n", key.ScanCode ); break;
          case CHAR_CARRIAGE_RETURN: Print( L"key { %d CR }\n", key.ScanCode ); break;
          case CHAR_BACKSPACE:       Print( L"key { %d BS }\n", key.ScanCode ); break;
          case CHAR_TAB:             Print( L"key { %d HT }\n", key.ScanCode ); break;

          default:
            logged = FALSE;
        }

        if( logged ) continue;

        logged = TRUE;
        switch ( key.ScanCode )
        {
          case SCAN_UP        : Print( L"key { <UP>     %d }\n", key.UnicodeChar ); break;
          case SCAN_DOWN      : Print( L"key { <DOWN>   %d }\n", key.UnicodeChar ); break;
          case SCAN_RIGHT     : Print( L"key { <RIGHT>  %d }\n", key.UnicodeChar ); break;
          case SCAN_LEFT      : Print( L"key { <LEFT>   %d }\n", key.UnicodeChar ); break;
          case SCAN_HOME      : Print( L"key { <HOME>   %d }\n", key.UnicodeChar ); break;
          case SCAN_END       : Print( L"key { <END>    %d }\n", key.UnicodeChar ); break;
          case SCAN_INSERT    : Print( L"key { <INSERT> %d }\n", key.UnicodeChar ); break;
          case SCAN_DELETE    : Print( L"key { <DELETE> %d }\n", key.UnicodeChar ); break;
          case SCAN_PAGE_UP   : Print( L"key { <PG_UP>  %d }\n", key.UnicodeChar ); break;
          case SCAN_PAGE_DOWN : Print( L"key { <PG_DN>  %d }\n", key.UnicodeChar ); break;
          case SCAN_F1        : Print( L"key { <F1>     %d }\n", key.UnicodeChar ); break;
          case SCAN_F2        : Print( L"key { <F2>     %d }\n", key.UnicodeChar ); break;
          case SCAN_F3        : Print( L"key { <F3>     %d }\n", key.UnicodeChar ); break;
          case SCAN_F4        : Print( L"key { <F4>     %d }\n", key.UnicodeChar ); break;
          case SCAN_F5        : Print( L"key { <F5>     %d }\n", key.UnicodeChar ); break;
          case SCAN_F6        : Print( L"key { <F6>     %d }\n", key.UnicodeChar ); break;
          case SCAN_F7        : Print( L"key { <F7>     %d }\n", key.UnicodeChar ); break;
          case SCAN_F8        : Print( L"key { <F8>     %d }\n", key.UnicodeChar ); break;
          case SCAN_F9        : Print( L"key { <F9>     %d }\n", key.UnicodeChar ); break;
          case SCAN_F10       : Print( L"key { <F10>    %d }\n", key.UnicodeChar ); break;
          case SCAN_F11       : Print( L"key { <F11>    %d }\n", key.UnicodeChar ); break;
          case SCAN_F12       : Print( L"key { <F12>    %d }\n", key.UnicodeChar ); break;
          case SCAN_ESC       : Print( L"key { <ESC>    %d }\n", key.UnicodeChar ); break;

          default:
            logged = FALSE;
        }

        if( logged ) continue;

        Print( L"key { %d %lu }\n", key.ScanCode, key.UnicodeChar );
    }

    return res;
}
