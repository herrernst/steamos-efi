#include <efi.h>
#include <efilib.h>
#include <efiprot.h>

#include "chainloader.h"

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
    UINTN buf_size = 0;
    CHAR16 prefix[256] = { '/', 0 };
    UINTN pad_to = (indent * 2) + 1;
    CONST UINTN max_pfx = 255;
    UINTN i = 1;
    EFI_STATUS res = EFI_SUCCESS;
    CONST UINTN unset = EFI_FILE_SYSTEM | EFI_FILE_ARCHIVE | EFI_FILE_RESERVED;


    if( indent )
        for( i = 0; (i < max_pfx) && (i < pad_to); i++ )
            prefix[i] = (CHAR16)' ';
    prefix[i] = (CHAR16) 0;

    while( ((res = efi_readdir( dir, &dirent, &buf_size )) == EFI_SUCCESS) &&
           buf_size )
    {
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

EFI_STATUS dump_fs_details (IN EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs)
{
    EFI_STATUS res = EFI_NOT_STARTED;
    EFI_FILE_PROTOCOL *root_dir = NULL;
    EFI_FILE_SYSTEM_VOLUME_LABEL_INFO *volume = NULL;
    UINTN is_esp_ish = 0;

    res = uefi_call_wrapper( fs->OpenVolume, 2, fs, &root_dir );

    ERROR_RETURN( res, res, L"SFSP->open-volume %x failed", (UINT64)fs );

    volume = LibFileSystemVolumeLabelInfo( root_dir );
    res = (volume ? EFI_SUCCESS : EFI_OUT_OF_RESOURCES);

    ERROR_JUMP( res, out, L"Allocating %d bytes",
                SIZE_OF_EFI_FILE_SYSTEM_VOLUME_LABEL_INFO + MAXFSNAMLEN );

    Print( L"<<< Volume label: %s>>>\n", volume->VolumeLabel );

    res = efi_file_exists( root_dir, BOOTCONFPATH );

    switch (res)
    {
      case EFI_SUCCESS:
        Print(  L"<<< !! SteamOS/bootconf, pseudo-ESP, full listing >>>\n" );
        is_esp_ish = 1;
        break;
      case EFI_NOT_FOUND:
        Print(  L"<<< No SteamOS/bootconf, not a pseudo-ESP >>>\n" );
        break;
      default:
        WARN_STATUS( res, L"%s->Open( SteamOS/bootconf )", volume->VolumeLabel );
    }

    if( !is_esp_ish )
        is_esp_ish = ( efi_file_exists( root_dir, EFIDIR ) == EFI_SUCCESS );

    if( is_esp_ish )
    {
        if( efi_file_exists( root_dir, DEFAULTLDR ) == EFI_SUCCESS )
        {
            Print( L"Default loader %s exists\n", DEFAULTLDR );
            if( valid_efi_binary( root_dir, DEFAULTLDR ) == EFI_SUCCESS )
                Print( L"... and is a PE32 executable for x86_64\n" );
            else
                Print( L"... but is NOT a PE32 executable\n" );
        }
        else
        {
            Print( L"Default loader %s does NOT exist on this EFI volume\n",
                   DEFAULTLDR );
        }
    }

    if( is_esp_ish )
        ls( root_dir , 0, L"/", 1 );

    res = efi_file_close( root_dir );
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

    ERROR_RETURN( res, res, L"get_fs_handles" );

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
