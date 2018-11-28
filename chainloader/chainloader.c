#include <efi.h>
#include <efilib.h>
#include <efiprot.h>

#define MAXFSNAMLEN 200
#define BOOTCONFPATH L"SteamOS\\bootconf"
#define EFIDIR       L"EFI"

#define ERROR_RETURN(s, fmt, ...) \
    if( s != EFI_SUCCESS )                                              \
    {                                                                   \
        Print( fmt L": %s (%d)\n", ##__VA_ARGS__, efi_statstr(s), s );  \
        return s;                                                       \
    }

#define WARN_STATUS(s, fmt, ...) \
    if( s != EFI_SUCCESS )                                              \
    {                                                                   \
        Print( fmt L": %s (%d)\n", ##__VA_ARGS__, efi_statstr(s), s );  \
    }


#define ERROR_JUMP(s, target, fmt, ...) \
    if( s != EFI_SUCCESS )                                              \
    {                                                                   \
        Print( fmt L": %s (%d)\n", ##__VA_ARGS__, efi_statstr(s), s );  \
        goto target;                                                    \
    }

#define ALLOC_OR_JUMP(s, tgt) \
    ({ VOID *x = efi_alloc( s ); \
       EFI_STATUS stat = (x ? EFI_SUCCESS : EFI_OUT_OF_RESOURCES); \
       ERROR_JUMP( stat, tgt, L"Allocating %d bytes", s );          \
       x; })


VOID * efi_alloc (IN UINTN s) { return AllocateZeroPool( s ); }
VOID   efi_free  (IN VOID *p) { FreePool( p); }

CHAR16 * efi_statstr (EFI_STATUS s)
{
    switch (s)
    {
      case EFI_SUCCESS:              return L"EFI_SUCCESS";
      case EFI_LOAD_ERROR:           return L"EFI_LOAD_ERROR";
      case EFI_INVALID_PARAMETER:    return L"EFI_INVALID_PARAMETER";
      case EFI_UNSUPPORTED:          return L"EFI_UNSUPPORTED";
      case EFI_BAD_BUFFER_SIZE:      return L"EFI_BAD_BUFFER_SIZE";
      case EFI_BUFFER_TOO_SMALL:     return L"EFI_BUFFER_TOO_SMALL";
      case EFI_NOT_READY:            return L"EFI_NOT_READY";
      case EFI_DEVICE_ERROR:         return L"EFI_DEVICE_ERROR";
      case EFI_WRITE_PROTECTED:      return L"EFI_WRITE_PROTECTED";
      case EFI_OUT_OF_RESOURCES:     return L"EFI_OUT_OF_RESOURCES";
      case EFI_VOLUME_CORRUPTED:     return L"EFI_VOLUME_CORRUPTED";
      case EFI_VOLUME_FULL:          return L"EFI_VOLUME_FULL";
      case EFI_NO_MEDIA:             return L"EFI_NO_MEDIA";
      case EFI_MEDIA_CHANGED:        return L"EFI_MEDIA_CHANGED";
      case EFI_NOT_FOUND:            return L"EFI_NOT_FOUND";
      case EFI_ACCESS_DENIED:        return L"EFI_ACCESS_DENIED";
      case EFI_NO_RESPONSE:          return L"EFI_NO_RESPONSE";
      case EFI_NO_MAPPING:           return L"EFI_NO_MAPPING";
      case EFI_TIMEOUT:              return L"EFI_TIMEOUT";
      case EFI_NOT_STARTED:          return L"EFI_NOT_STARTED";
      case EFI_ALREADY_STARTED:      return L"EFI_ALREADY_STARTED";
      case EFI_ABORTED:              return L"EFI_ABORTED";
      case EFI_ICMP_ERROR:           return L"EFI_ICMP_ERROR";
      case EFI_TFTP_ERROR:           return L"EFI_TFTP_ERROR";
      case EFI_PROTOCOL_ERROR:       return L"EFI_PROTOCOL_ERROR";
      case EFI_INCOMPATIBLE_VERSION: return L"EFI_INCOMPATIBLE_VERSION";
      case EFI_SECURITY_VIOLATION:   return L"EFI_SECURITY_VIOLATION";
      case EFI_CRC_ERROR:            return L"EFI_CRC_ERROR";
      case EFI_END_OF_MEDIA:         return L"EFI_END_OF_MEDIA";
      case EFI_END_OF_FILE:          return L"EFI_END_OF_FILE";
      case EFI_INVALID_LANGUAGE:     return L"EFI_INVALID_LANGUAGE";
      case EFI_COMPROMISED_DATA:     return L"EFI_COMPROMISED_DATA";
      default:
        return L"-UNKNOWN-";
    }

}

EFI_STATUS get_fs_handles (IN EFI_GUID *fs_id,
                           OUT EFI_HANDLE **handles,
                           IN OUT UINTN *count)
{
    return LibLocateHandle(ByProtocol, fs_id, NULL, count, handles);
}

EFI_STATUS get_fs_protocol (IN EFI_HANDLE *handle,
                            IN EFI_GUID *fs_id,
                            OUT VOID **fs)
{
    return uefi_call_wrapper(BS->HandleProtocol, 3, *handle, fs_id, fs );
}

VOID ls (EFI_FILE_PROTOCOL *dir, UINTN indent, CONST CHAR16 *name, UINTN recurse)
{
    EFI_FILE_INFO *dirent = NULL;
    CONST UINTN in_bufs = SIZE_OF_EFI_FILE_INFO + MAXFSNAMLEN;
    UINTN out_bufs = in_bufs;
    VOID *readdir;
    VOID *opendir;
    CHAR16 prefix[256] = { '/', 0 };
    UINTN pad_to = (indent * 2) + 1;
    CONST UINTN max_pfx = 255;
    UINTN i = 1;
    EFI_STATUS res = EFI_SUCCESS;
    CONST UINTN unset = EFI_FILE_SYSTEM | EFI_FILE_ARCHIVE | EFI_FILE_RESERVED;

    // Print( L"Recursing into %s @ %u\n", name, indent );
    dirent  = ALLOC_OR_JUMP( in_bufs, out );
    readdir = dir->Read;
    opendir = dir->Open;

    if( indent )
        for( i = 0; (i < max_pfx) && (i < pad_to); i++ )
            prefix[i] = (CHAR16)' ';
    prefix[i] = (CHAR16) 0;

    while( 1 )
    {
        out_bufs = in_bufs;
        res = uefi_call_wrapper( readdir, 3, dir, &out_bufs, dirent );
        ERROR_JUMP( res, out, L"%s->Read failed", name );

        if( out_bufs == 0 ) // End of directory
            break;

        // skip the pseudo dirents for self and parent:
        if( !StrCmp( dirent->FileName, L"."  ) ||
            !StrCmp( dirent->FileName, L".." ) )
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
            res = uefi_call_wrapper( opendir, 5,
                                     dir, &subdir, dirent->FileName,
                                     EFI_FILE_MODE_READ, 0 );
            ERROR_JUMP( res, out, L"%s->open(%s)", name, dirent->FileName );

            if( recurse )
                ls( subdir, indent + 1, dirent->FileName, recurse );

            res = uefi_call_wrapper( subdir->Close, 1, subdir );
            WARN_STATUS( res, L"->close() failed. what.\n" );
        }
    }

out:
    if( dirent ) efi_free( dirent );
}

EFI_STATUS file_exists (EFI_FILE_PROTOCOL *dir, CHAR16 *path)
{
    EFI_FILE_PROTOCOL *target;
    EFI_STATUS res = EFI_SUCCESS;
    EFI_STATUS r2;

    res = uefi_call_wrapper( dir->Open, 5, dir,
                             &target, path, EFI_FILE_MODE_READ, 0 );

    switch (res)
    {
      case EFI_SUCCESS:
        r2 = uefi_call_wrapper( target->Close, 1, target );
        WARN_STATUS( r2, L"/->close() failed. what.\n" );
        break;
      case EFI_NOT_FOUND:
        break;
      default:
        WARN_STATUS( res, L"->Open( %s )", path );
    }

    return res;
}

EFI_STATUS dump_fs_details (IN EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs)
{
    EFI_STATUS res = EFI_NOT_STARTED;
    EFI_FILE_PROTOCOL *root_dir = NULL;
    EFI_FILE_SYSTEM_VOLUME_LABEL_INFO *volume = NULL;
    UINTN recurse = 0;

    res = uefi_call_wrapper( fs->OpenVolume, 2, fs, &root_dir );

    ERROR_RETURN( res, L"SFSP->open-volume %p failed", fs );

    volume = LibFileSystemVolumeLabelInfo( root_dir );
    res = (volume ? EFI_SUCCESS : EFI_OUT_OF_RESOURCES);

    ERROR_JUMP( res, out, L"Allocating %d bytes",
                SIZE_OF_EFI_FILE_SYSTEM_VOLUME_LABEL_INFO + MAXFSNAMLEN );

    Print( L"<<< Volume label: %s>>>\n", volume->VolumeLabel );

    res = file_exists( root_dir, BOOTCONFPATH );

    switch (res)
    {
      case EFI_SUCCESS:
        Print(  L"<<< !! SteamOS/bootconf, pseudo-ESP, full listing >>>\n" );
        recurse = 1;
        break;
      case EFI_NOT_FOUND:
        Print(  L"<<< No SteamOS/bootconf, not a pseudo-ESP >>>\n" );
        break;
      default:
        WARN_STATUS( res, L"%s->Open( SteamOS/bootconf )", volume->VolumeLabel );
    }

    if( !recurse )
        recurse = ( file_exists( root_dir, EFIDIR ) == EFI_SUCCESS );

    if( recurse )
        ls( root_dir , 0, L"/", recurse );

    res = uefi_call_wrapper( root_dir->Close, 1, root_dir );
    WARN_STATUS( res, L"/->close() failed. what.\n" );

out:
    if( volume ) efi_free( volume );

    return res;
}


EFI_STATUS
EFIAPI
efi_main (EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *sys_table)
{
    EFI_GUID fs_guid = SIMPLE_FILE_SYSTEM_PROTOCOL;
    EFI_HANDLE* handles = NULL;
    UINTN count = 0;
    EFI_STATUS res;

    InitializeLib( image_handle, sys_table );
    Print( L"Chainloader starting\n" );

    res = get_fs_handles( &fs_guid, &handles, &count );

    ERROR_RETURN( res, L"get_fs_handles" );

    for ( int i = 0; i < (int)count; i++ )
    {
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* fs = NULL;
        res = get_fs_protocol( &handles[i], &fs_guid, (VOID **)&fs );

        if ( res != EFI_SUCCESS )
        {
            Print( L"get_fs_protocol: %s (%d)\n", efi_statstr(res), res);
            continue;
        }

        dump_fs_details( fs );
    }
    return EFI_SUCCESS;
}
