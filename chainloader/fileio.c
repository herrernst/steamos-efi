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
#include <sys/param.h>

#include "err.h"
#include "util.h"
#include "fileio.h"

EFI_STATUS efi_file_open (EFI_FILE_PROTOCOL *dir,
                          OUT EFI_FILE_PROTOCOL **opened,
                          CONST CHAR16 *path,
                          UINT64 mode,
                          UINT64 attr)
{
    // FIXME: audit users to explicitly pass EFI_FILE_MODE_READ
    if( !mode )
    {
        mode = EFI_FILE_MODE_READ;
    }
    else
    {
        // Make sure we're using a permitted mode combination (see below):
        if (mode & EFI_FILE_MODE_CREATE)
            mode |= EFI_FILE_MODE_WRITE;

        if (mode & EFI_FILE_MODE_WRITE)
            mode |= EFI_FILE_MODE_READ;
    }

    // These are the only mode combinations allowed by the UEFI spec:
    // Protocols - Media Access; EFI_FILE_PROTOCOL.Open
    // (pg 604 in the May 2017 edition, v2.7)
    // OPenMode:   «… the only valid combinations
    //              … are Read,Read/Write,Read/Write/Create»
    switch (mode)
    {
      case EFI_FILE_MODE_CREATE|EFI_FILE_MODE_WRITE|EFI_FILE_MODE_READ:
      case EFI_FILE_MODE_WRITE|EFI_FILE_MODE_READ:
      case EFI_FILE_MODE_READ:
        break;
      default:
        *opened = NULL;
        return EFI_INVALID_PARAMETER;
    }

    return uefi_call_wrapper( dir->Open, 5, dir, opened, (CHAR16 *)path, mode, attr );
}

EFI_STATUS efi_file_close (IN EFI_FILE_PROTOCOL *file)
{
    if( file )
        return uefi_call_wrapper( file->Close, 1, file );

    return EFI_SUCCESS;
}

EFI_STATUS efi_file_seek (EFI_FILE_PROTOCOL *file, UINT64 pos)
{
    return uefi_call_wrapper( file->SetPosition, 2, file, pos );
}

EFI_STATUS efi_file_exists (EFI_FILE_PROTOCOL *dir, CONST CHAR16 *path)
{
    EFI_FILE_PROTOCOL *target;
    EFI_STATUS res = EFI_SUCCESS;
    EFI_STATUS r2;

    res = efi_file_open( dir, &target, path, 0, 0 );

    switch( res )
    {
      case EFI_SUCCESS:
        r2 = efi_file_close( target );
        WARN_STATUS( r2, L"/->close() failed. what.\n" );
        break;
      case EFI_NOT_FOUND:
        break;
      default:
        WARN_STATUS( res, L"->Open( %s )", path );
    }

    return res;
}

// emulate mkdir -p
EFI_STATUS efi_mkdir_p (EFI_FILE_PROTOCOL *parent,
                        OUT EFI_FILE_PROTOCOL **dir,
                        CONST CHAR16 *name)
{
    UINTN i = 1;
    UINTN x = 0;
    CHAR16 *partial = NULL;
    UINTN len = strlen_w( name );
    EFI_STATUS res = EFI_INVALID_PARAMETER;
    // UEFI spec only allows CREATE if you specify WRITE and READ
    // See efi_file_open for details:
    static const UINT64 mode = ( EFI_FILE_MODE_WRITE  |
                                 EFI_FILE_MODE_READ   |
                                 EFI_FILE_MODE_CREATE );

    partial = ALLOC_OR_GOTO ( (len + 1) * sizeof(CHAR16), allocfail );

    // Drop/ignore any trailing backslashes
    while( len && *(name + len - 1) == L'\\' )
        len--;

    // skipping \ at start of path
    for( i = 1; i < len; i++ )
    {
        EFI_FILE_PROTOCOL *tmp = NULL;
        // every time we encounter a \ we create the next segment
        if( *(name + i) == L'\\' )
        {
            x = i;
            mem_copy( partial, name, i * sizeof(CHAR16) );
            partial[ i + 1 ] = L'\0';
            res =
              efi_file_open( parent, &tmp, partial, mode, EFI_FILE_DIRECTORY );
            ERROR_JUMP( res, mkdir_done, L"Create dir %s failed", partial );
            efi_file_close( tmp );
        }
    }

    if( len - x > 1 || *(name + i - 1) != L'\\' )
    {
        mem_copy( partial, name, len * sizeof(CHAR16) );
        partial[ len + i ] = L'\0';
        res = efi_file_open( parent, dir, partial, mode, EFI_FILE_DIRECTORY );
    }

mkdir_done:
    efi_free( partial );
    return res;

allocfail:
    return EFI_OUT_OF_RESOURCES;
}

EFI_STATUS efi_readdir (EFI_FILE_PROTOCOL *dir,
                        IN OUT EFI_FILE_INFO **dirent,
                        IN OUT UINTN *dirent_size)
{
    CONST UINTN bufsize = EFI_FILE_INFO_SAFE_SIZE;
    UINTN allocated;
    EFI_STATUS res;

    if( *dirent_size == 0 )
        *dirent_size = bufsize;

    if( *dirent == NULL )
        *dirent = ALLOC_OR_GOTO( *dirent_size, allocfail );

    allocated = *dirent_size;

    res = uefi_call_wrapper( dir->Read, 3, dir, dirent_size, *dirent );

    // we return what was actually allocated so the user can loop
    // without copying the allocated value back into *dirent_size:
    if( *dirent_size > 0 )
        *dirent_size = allocated;

    return res;

allocfail:
    return EFI_OUT_OF_RESOURCES;
}

EFI_STATUS efi_file_read (EFI_FILE_PROTOCOL *fh,
                          IN OUT CHAR8 *buf,
                          IN OUT UINTN *bytes)
{
    return uefi_call_wrapper( fh->Read, 3, fh, bytes, buf );
}

EFI_STATUS efi_file_write (EFI_FILE_PROTOCOL *fh,
                           IN CHAR8 *buf,
                           IN OUT UINTN *bytes)
{
    return uefi_call_wrapper( fh->Write, 3, fh, bytes, buf );
}

EFI_STATUS efi_mount (EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *part,
                      OUT EFI_FILE_PROTOCOL **root)
{
    *root = NULL;
    return uefi_call_wrapper( part->OpenVolume, 2, part, root );
}

EFI_STATUS efi_unmount (IN OUT EFI_FILE_PROTOCOL **root)
{
    EFI_STATUS res = EFI_SUCCESS;

    if( root && *root )
    {
        res = efi_file_close( *root );
        *root = NULL;
    }

    return res;
}

VOID ls (EFI_FILE_PROTOCOL *dir, UINTN indent, CONST CHAR16 *name, UINTN recurse)
{
    EFI_FILE_INFO *dirent = NULL;
    UINTN buf_size = 0;
    CHAR16 prefix[256] = { '/', 0 };
    UINTN pad_to = (indent * 2) + 1;
    CONST UINTN max_pfx = 255;
    UINTN i = 1;
    EFI_STATUS res = EFI_SUCCESS;
    CONST UINTN unset = EFI_FILE_SYSTEM | EFI_FILE_ARCHIVE | EFI_FILE_RESERVED;

    if( indent )
        for( i = 0; (i < max_pfx) && (i < pad_to); i++ )
            prefix[ i ] = (CHAR16)' ';
    prefix[ i ] = (CHAR16)0;

    while( ((res = efi_readdir( dir, &dirent, &buf_size )) == EFI_SUCCESS) &&
           buf_size )
    {
        // skip the pseudo dirents for self and parent:
        if( !strcmp_w( dirent->FileName, L"."  ) ||
            !strcmp_w( dirent->FileName, L".." ) )
            continue;

        Print( L"%s%s %lu bytes %cr%c- [%c%c%c%c]\n",
               prefix, dirent->FileName, dirent->FileSize,
               ( dirent->Attribute & EFI_FILE_DIRECTORY ) ? 'd' : '-' ,
               ( dirent->Attribute & EFI_FILE_READ_ONLY ) ? '-' : 'w' ,
               ( dirent->Attribute & EFI_FILE_SYSTEM    ) ? 'S' : ' ' ,
               ( dirent->Attribute & EFI_FILE_RESERVED  ) ? 'R' : ' ' ,
               ( dirent->Attribute & EFI_FILE_ARCHIVE   ) ? 'A' : ' ' ,
               ( dirent->Attribute & EFI_FILE_HIDDEN    ) ? 'h' : ' ' );

        if( (dirent->Attribute & EFI_FILE_DIRECTORY) &&
            !(dirent->Attribute & unset)             )
        {
            EFI_FILE_PROTOCOL *subdir;
            res = efi_file_open( dir, &subdir, dirent->FileName, 0, 0 );
            ERROR_JUMP( res, out, L"%s->open(%s)", name, dirent->FileName );

            if( recurse )
                ls( subdir, indent + 1, dirent->FileName, recurse );

            res = efi_file_close( subdir );
            WARN_STATUS( res, L"->close() failed. what.\n" );
        }
    }

    ERROR_JUMP( res, out, L"%s->Read failed", name );

out:
    if( dirent ) efi_free( dirent );
}

EFI_STATUS efi_file_stat (EFI_FILE_PROTOCOL *fh,
                          IN OUT EFI_FILE_INFO **info,
                          IN OUT UINTN *bufsize)
{
    CONST UINTN size = EFI_FILE_INFO_SAFE_SIZE;
    UINTN allocated;
    EFI_STATUS res = EFI_SUCCESS;
    EFI_GUID info_guid = EFI_FILE_INFO_ID;

    if( *info && !*bufsize )
        res = EFI_INVALID_PARAMETER;
    ERROR_RETURN( res, res,
                  L"user must provide buffer size with preallocated buffer" );

    if( *bufsize == 0 )
        *bufsize = size;

    allocated = *bufsize;

    if( *info == NULL )
        *info = ALLOC_OR_GOTO( *bufsize, allocfail );

    res = uefi_call_wrapper( fh->GetInfo, 4, fh, &info_guid, bufsize, *info );
    *bufsize = allocated;

    return res;

allocfail:
    return EFI_OUT_OF_RESOURCES;
}

// compare the newest of { ctime, mtime } for two files
// return -1 if file a is older,
// 0 if the same age,
// and 1 if file a is newer:
EFI_STATUS efi_file_xtime_cmp (EFI_FILE_PROTOCOL *a,
                               EFI_FILE_PROTOCOL *b,
                               INTN *result)
{
    EFI_STATUS res;
    UINTN bufsize = 0;
    EFI_FILE_INFO *info = NULL;
    UINT64 stamp_a = 0;
    UINT64 stamp_b = 0;
    UINT64 ctime = 0;
    UINT64 mtime = 0;

    if( !result )
        return EFI_INVALID_PARAMETER;

    *result = 0;

    if( !a && !b )
        return EFI_SUCCESS;

    if( !a || !b )
        return EFI_NOT_FOUND;

    info = ALLOC_OR_GOTO( EFI_FILE_INFO_SAFE_SIZE, allocfail );
    bufsize = EFI_FILE_INFO_SAFE_SIZE;

    res = efi_file_stat( a, &info, &bufsize );
    ERROR_JUMP( res, cleanup, L"stat of file A failed\n" );

    ctime = efi_time_to_timestamp( &info->CreateTime );
    mtime = efi_time_to_timestamp( &info->ModificationTime );
    stamp_a = MAX( ctime, mtime );

    res = efi_file_stat( b, &info, &bufsize );
    ERROR_JUMP( res, cleanup, L"stat of file B failed\n" );

    ctime = efi_time_to_timestamp( &info->CreateTime );
    mtime = efi_time_to_timestamp( &info->ModificationTime );
    stamp_b = MAX( ctime, mtime );

    if( stamp_a < stamp_b )
        *result = -1;
    else if( stamp_a > stamp_b )
        *result = 1;

cleanup:
    efi_free( info );
    return res;

allocfail:
    return EFI_OUT_OF_RESOURCES;

}

// Returns a buffer of n+1 bytes, where n is the file size,
// with the final (extra) byte guaranteed to be (CHAR8)0
EFI_STATUS efi_file_to_mem (EFI_FILE_PROTOCOL *fh,
                            OUT CHAR8 **buf,
                            OUT UINTN *bytes,
                            OUT UINTN *alloc)
{
    EFI_STATUS res = EFI_SUCCESS;
    EFI_FILE_INFO *info = NULL;
    UINTN ialloc = 0;
    UINT64 dalloc = 0;

    res = efi_file_stat( fh, &info, &ialloc );
    ERROR_JUMP( res, out, L"file_to_mem: stat" );

    dalloc = info->FileSize;
    *buf   = ALLOC_OR_GOTO( dalloc + 1, out );
    *bytes = dalloc;
    *alloc = dalloc + 1;
    (*buf)[ dalloc ] = (CHAR8) 0;

    res = efi_file_read( fh, *buf, bytes );
    ERROR_JUMP( res, out, L"file_to_mem: read" );
    (*buf)[ dalloc ] = (CHAR8) 0;

out:
    efi_free( info );
    return res;
}
