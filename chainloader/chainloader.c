#include <efi.h>
#include <efilib.h>
#include <efiprot.h>

#include "chainloader.h"


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
    UINTN debug = 1;
    bootloader steamos;

    InitializeLib( image_handle, sys_table );
    Print( L"Chainloader starting\n" );

    res = get_protocol_handles( &fs_guid, &handles, &count );

    ERROR_RETURN( res, res, L"get_fs_handles" );

    for ( int i = 0; i < (int)count; i++ )
    {
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* fs = NULL;

        res = get_handle_protocol( &handles[i], &fs_guid, (VOID **)&fs );
        ERROR_CONTINUE( res, L"simple fs protocol" );

        if( debug )
            dump_fs_details( fs );
    }

    choose_steamos_loader( handles, count, &steamos );

    efi_free( handles );

    return EFI_SUCCESS;
}
