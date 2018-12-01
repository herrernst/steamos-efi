#include <efi.h>
#include <efilib.h>
#include <efiprot.h>

#include "err.h"
#include "util.h"
#include "fileio.h"
#include "bootload.h"

// this is x86_64 specific
#define EFI_STUB_ARCH 0x8664

EFI_STATUS valid_efi_binary (IN EFI_FILE_PROTOCOL *dir, CONST IN CHAR16 *path)
{
    EFI_STATUS res;
    EFI_FILE_PROTOCOL *bin = NULL;
    CHAR8 header[512] = { '0','x','d','e','a','d','b','e','e','f', 0, 0 };
    CONST UINTN hsize = sizeof(header);
    UINTN bytes = hsize;
    UINTN s;
    UINT16 arch;

    res = efi_file_open( dir, &bin, path, 0, 0 );
    ERROR_RETURN( res, res, L"open( %s )", path );

    res = efi_file_read( bin, (CHAR8 *)header, &bytes );
    ERROR_RETURN( res, res, L"read( %s, %u )", path, hsize );

    efi_file_close( bin );

    if( bytes < hsize )
        return EFI_END_OF_FILE;

    if( header[0] != 'M' || header[1] != 'Z' )
        return EFI_LOAD_ERROR;

    // The uint32 starting at offset 0x3c
    s = * (UINT32 *) &header[ 0x3c ];

    if( s >=  0x180 ||
        header[ s   ] != 'P' ||
        header[ s+1 ] != 'E' ||
        header[ s+2 ] != 0   ||
        header[ s+3 ] != 0   )
        return EFI_LOAD_ERROR;

    arch = * (UINT16 *) &header[ s+4 ];

    if( arch != EFI_STUB_ARCH )
        return EFI_LOAD_ERROR;

    return EFI_SUCCESS;
}

EFI_STATUS choose_steamos_loader (IN EFI_HANDLE *handles,
                                  CONST IN UINTN n_handles,
                                  IN OUT bootloader *chosen)
{
    EFI_STATUS res;
    EFI_FILE_PROTOCOL *root_dir = NULL;
    static EFI_GUID fs_guid = SIMPLE_FILE_SYSTEM_PROTOCOL;
    static EFI_GUID dp_guid = DEVICE_PATH_PROTOCOL;

    chosen->partition = NULL;
    chosen->loader_path = NULL;

    for ( UINTN i = 0; i < n_handles; i++ )
    {
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs = NULL;

        efi_unmount( &root_dir );

        res = get_handle_protocol( &handles[i], &fs_guid, (VOID **)&fs );
        ERROR_CONTINUE( res, L"handle #%u: no simple file system protocol", i );

        res = efi_mount( fs, &root_dir );
        ERROR_CONTINUE( res, L"partition #%u not opened", i );

        res = efi_file_exists( root_dir, BOOTCONFPATH );
        if( res != EFI_SUCCESS )
            continue;

        res = get_handle_protocol( &handles[i], &dp_guid,
                                   (VOID **) &chosen->device_path );
        ERROR_CONTINUE( res, L"Unable to get device path for partition #%u", 1 );
        chosen->partition = handles[i];
        chosen->loader_path = BOOTCONFPATH;
        break;
    }

    efi_unmount( &root_dir );

    return chosen->partition ? EFI_SUCCESS : EFI_NOT_FOUND;
}

#ifdef WIP
EFI_STATUS efi_execute (EFI_FILE_HANDLE bin)
{
    EFI_HANDLE efiapp;
    EFI_DEVICE_PATH *dpath = NULL;

    return
      uefi_call_wrapper(BS->LoadImage, 6, FALSE, SIH, dpath, NULL, 0, &efiapp);
}
#endif
