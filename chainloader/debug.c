// steamos-efi  --  SteamOS EFI Chainloader

// SPDX-License-Identifier: GPL-2.0+
// Copyright © 2022 Collabora Ltd
// Copyright © 2022 Valve Corporation

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

#include "err.h"
#include "util.h"
#include "fileio.h"

CHAR8 log_stamp[64];
EFI_FILE_PROTOCOL *debug_log;
UINT64 debug_message_count;

static UINT64 debug_offset;
static UINT64 debug_bufsize;
static CHAR8  *debug_abuf;
static CHAR16 *debug_wbuf;

#define PREALLOC_DEBUGLOG L"steamcl-debug.log"

static VOID debug_sync( UINT64 from, UINT64 size )
{
    if( debug_log == NULL )
        return;

    if( efi_file_seek( debug_log, from ) == EFI_SUCCESS )
        efi_file_write( debug_log, debug_abuf + from, &size );
}

VOID update_logstamp (VOID)
{
    EFI_TIME now = { 0 };
    EFI_STATUS res = uefi_call_wrapper( RT->GetTime, 2, &now, NULL );

    if( res != EFI_SUCCESS )
        return;

    efi_time_to_utc( &now );

    // all we have is 1 second resolution, so don't bother
    // with the nanosecond field:
    sprintf_a( &log_stamp[0], sizeof(log_stamp),
               "%04d-%02d-%02d %02d:%02d:%02d",
               now.Year, now.Month, now.Day,
               now.Hour, now.Minute, now.Second );
}

VOID debug_log_init (EFI_FILE_PROTOCOL *dir, CHAR16 *path_rel)
{
    UINTN info_size = 0;
    EFI_FILE_INFO *logstat = NULL;
    EFI_STATUS res = EFI_SUCCESS;
    CHAR16 *log_path = NULL;

    // debug logfile already opened:
    if( debug_log != NULL )
        return;

    debug_offset = 0;

    log_path = resolve_path( PREALLOC_DEBUGLOG, path_rel, FALSE );

    // Could not figure out where the debug file would be - give up.
    if( log_path == NULL )
        return;

    // No error message since the debug file is optional:
    res = efi_file_open( dir, &debug_log, log_path, EFI_FILE_MODE_WRITE, 0 );
    if( res != EFI_SUCCESS )
        goto cleanup;

    // stat the logfile and prep a wchar buffer and a char buffer big enough
    // to hold as many wchar and char respectively as the file can hold char
    // (we only have wchar sprintf available to us so we use both):
    res = efi_file_stat( debug_log, &logstat, &info_size );
    ERROR_JUMP( res, cleanup, L"DEBUG: Unable to stat logfile %s", log_path );

    debug_bufsize = logstat->FileSize;
    efi_free( logstat );

    // if we don't even have 1 terminal line's worth of space, don't bother
    if( debug_bufsize < 80 )
        goto cleanup;

    debug_abuf = efi_alloc( debug_bufsize );
    // max size of a debug message can be the size of the preallocated
    // file, so allocate enough space for the char16 -> char8 munge buffer:
    debug_wbuf = efi_alloc( debug_bufsize * sizeof(CHAR16) );

    // couldn't allocate the debug buffers - bail out.
    if( debug_abuf == NULL || debug_wbuf == NULL )
        goto cleanup;

    debug_message_count = 0;

    // zero out the log so we wipe any existing contents
    debug_sync( 0, debug_bufsize );

    return;

cleanup:
    if( debug_log != NULL )
    {
        efi_file_close( debug_log );
        debug_log = NULL;
    }

    efi_free( debug_abuf );
    debug_abuf = NULL;
}

VOID debug_log_close (VOID)
{
    if( debug_log == NULL )
        return;

    debug_sync( 0, debug_bufsize );

    // close implicitly does a flush
    // NOTE: we flush after each message so the file is always up to date
    efi_file_close( debug_log );
    debug_log = NULL;
    debug_offset = 0;
}

VOID debug_log_printf (const char *fmt, ...)
{
    UINTN wrote = 0;
    CHAR8 *astart = debug_abuf + debug_offset;
    UINTN space = debug_bufsize - debug_offset;
    va_list args;

    va_start( args, fmt );
    wrote  = vsprintf_a( astart, space, (const char *)fmt, args );
    va_end( args );

    // ran out of space (efi sprintf-alikes enforce requiring space
    // for a trailing NUL, hence the "- 1")
    if( debug_offset + wrote >= debug_bufsize - 1 )
    {
        // rewind:
        debug_offset = 0;
        astart = debug_abuf;
        space = debug_bufsize;

        va_start( args, fmt );
        wrote = vsprintf_a( astart, space, (const char *)fmt, args );
        va_end( args );
    }

    debug_sync( debug_offset, wrote );
    debug_offset += wrote;
}

VOID debug_log_wprintf (const CHAR16 *fmt, ...)
{
    UINTN wrote = 0;
    UINTN space = debug_bufsize * sizeof(CHAR16);
    CHAR8 *str  = NULL;
    va_list args;

    if( debug_wbuf == NULL )
        return;

    va_start( args, fmt );
    wrote = vsprintf_w( debug_wbuf, space, fmt, args );
    va_end( args );

    // not enough room for this log message:
    if( wrote >= space )
        return;

    str = strnarrow( debug_wbuf );
    debug_log_printf( "%a", str );
    efi_free( str );
}
