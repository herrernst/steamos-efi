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
#include "console.h"

//
// Console control protocol (deprecated)
//

EFI_STATUS
conctl_get_mode (EFI_CONSOLE_CONTROL_PROTOCOL     *ctl,
                 EFI_CONSOLE_CONTROL_SCREEN_MODE  *mode,
                 BOOLEAN                          *have_uga,
                 BOOLEAN                          *stdin_locked)
{
    return uefi_call_wrapper( ctl->get_mode, 4, ctl, mode, have_uga, stdin_locked );
}

EFI_STATUS
conctl_set_mode (EFI_CONSOLE_CONTROL_PROTOCOL    *ctl,
                 EFI_CONSOLE_CONTROL_SCREEN_MODE  mode)
{
    return uefi_call_wrapper( ctl->set_mode, 2, ctl, mode );
}

EFI_STATUS
conctl_lock_stdin (EFI_CONSOLE_CONTROL_PROTOCOL *ctl,
                   CHAR16                       *passphrase)
{
    return uefi_call_wrapper( ctl->lock_stdin, 2, ctl, passphrase );
}

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

// ==========================================================================
// Menu support
static EFI_STATUS console_mode (VOID)
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


// this is the console output attributes for the menu
#define SELECTED_ATTRIBUTES (EFI_MAGENTA   | EFI_BACKGROUND_BLACK)
#define DEFAULT_ATTRIBUTES  (EFI_LIGHTGRAY | EFI_BACKGROUND_BLACK)
#define TITLE_ATTRIBUTES    (EFI_WHITE     | EFI_BACKGROUND_BLACK)

con_menu *
con_menu_alloc (INTN entries, CONST CHAR16 *title)
{
    con_menu *menu = efi_alloc( sizeof(con_menu) );

    menu->title   = strdup_w( title ?: L"-" );
    menu->option  = efi_alloc( entries * sizeof(con_menu_option) );
    menu->entries = entries;

    return menu;
}

VOID
con_menu_free (con_menu *menu)
{
    for( UINTN i = 0; i < menu->entries; i++ )
        efi_free( menu->option[ i ].data );

    efi_free( menu->title );
    efi_free( menu->option );
    efi_free( menu );
}

typedef enum
{
    NONE    = 0x00,
} dummy;

static VOID render_menu_option(con_menu *menu, IN UINTN nth, BOOLEAN on)
{
    con_set_output_attribute( on ? SELECTED_ATTRIBUTES : DEFAULT_ATTRIBUTES );
    con_set_cursor_position( menu->offset.col, menu->offset.row + nth );
    con_output_text( on ? L"> " : L"  " );
    con_output_text( &menu->option[ nth ].label[ 0 ] );
    con_set_cursor_position( menu->offset.col + menu->width + 2,
                             menu->offset.row + nth );
    con_output_text( on ? L" <" : L"  " );
}

static VOID calculate_menu_layout (con_menu *menu)
{
    EFI_STATUS res;
    UINTN cols;
    UINTN rows;

    menu->width = 0;

    for( INTN i = 0; i < (INTN)menu->entries; i++ )
    {
        UINTN olen = strlen_w( &menu->option[ i ].label[ 0 ] );
        if( olen > menu->width )
            menu->width = olen;
    }

    res = con_output_mode_info( con_get_output_mode(), &cols, &rows);

    // fall back to punchard size if we don't know how big the console is:
    if( EFI_ERROR( res ) )
    {
        cols = 80;
        rows = 25;
    }

    menu->screen.col = cols;
    menu->screen.row = rows;

    // centre the menu vertically
    menu->offset.row = (rows - menu->entries) / 2;

    // ==================================================================
    // … and horizontally:
    INTN offset = cols / 2;
    for( INTN i = 0; i < (INTN)menu->entries; i++ )
    {
        INTN label_len = strlen_w( &menu->option[ i ].label[ 0 ] );
        INTN o = ((cols - label_len) / 2) - 2;

        if( o < 0 )
            o = 0;

        if( o < offset )
            offset = o;
    }

    menu->offset.col = offset;
}

static VOID render_menu (con_menu *menu, UINTN selected)
{
    calculate_menu_layout( menu );

    // If we have room for the title:
    if( menu->offset.row >= 1 )
    {
        UINTN t_yoff = menu->offset.row - 1;
        UINTN t_len  = strlen_w( menu->title );
        UINTN t_xoff = ( menu->offset.col + 2 +
                         (((INTN)(menu->width - t_len)) / 2) );

        con_set_cursor_position( t_xoff, t_yoff );
        con_set_output_attribute( TITLE_ATTRIBUTES );
        con_output_text( menu->title );
    }

    for( INTN i = 0; i < (INTN)menu->entries; i++ )
        render_menu_option( menu, i, i == (INTN)selected );
}

INTN
con_run_menu (con_menu *menu, UINTN start, OUT VOID **chosen)
{
    INTN i, selected;
    EFI_STATUS res;
    const INTN opt console_max_mode = con_get_max_output_mode();

    res = console_mode();
    if( EFI_ERROR( res ) && res != EFI_NOT_FOUND )
       return res;

    if( console_max_mode > 0 )
    {
        for( i = console_max_mode - 1; i != 0; i-- )
        {
            res = con_set_output_mode( i );
            if( EFI_ERROR( res ) )
                continue;

            break;
        }
    }

    con_clear_screen();
    con_enable_cursor( FALSE );

    if( start >= menu->entries )
        selected = 0;
    else
        selected = start;

    render_menu( menu, selected );

    con_set_output_attribute( DEFAULT_ATTRIBUTES );
    con_reset( FALSE );

    for( ;; )
    {
        INTN old_selected = selected;
        EFI_INPUT_KEY key;

        con_set_output_attribute( DEFAULT_ATTRIBUTES );

        res = WaitForSingleEvent( ST->ConIn->WaitForKey, 0 );
        ERROR_BREAK( res, L"Could not WaitForSingleEvent: %r\n", res );

        res = con_read_key( &key );
        ERROR_BREAK( res, L"Could not con_read_key: %r\n", res );

        if( ( key.UnicodeChar == CHAR_LINEFEED ) ||
            ( key.UnicodeChar == CHAR_CARRIAGE_RETURN ) )
        {
            break;
        }
        else if( ( key.ScanCode    == SCAN_ESC ) &&
                 ( key.UnicodeChar == 0        ) )
        {
            selected = -1;
            break;
        }
        else if( key.ScanCode == SCAN_UP )
        {
            if( selected > 0 )
                selected--;
            else
                selected = 0;
        }
        else if( key.ScanCode == SCAN_DOWN )
        {
            if( selected < (INTN)menu->entries - 1 )
                selected++;
            else
                selected = 0;
        }

        if( selected == -1 || selected == old_selected )
            continue;

        render_menu_option( menu, old_selected, FALSE );
        render_menu_option( menu, selected, TRUE );
    }

    if( chosen )
        *chosen = menu->option[ selected ].data;

    con_clear_screen();

    return selected;
}

BOOLEAN
con_confirm (CONST CHAR16 *question, BOOLEAN default_answer)
{
    BOOLEAN answer = default_answer;
    con_menu *yn = con_menu_alloc( 2, question );
    const UINT64 llen = sizeof( yn->option[ 0 ].label );

    SPrint( &yn->option[ 0 ].label[ 0 ], llen, L"Yes" );
    SPrint( &yn->option[ 1 ].label[ 0 ], llen, L"No"  );

    answer = con_run_menu( yn, default_answer ? 0 : 1, NULL );

    con_menu_free( yn );

    return answer == 0;
}
