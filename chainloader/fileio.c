#include <efi.h>
#include <efilib.h>
#include <efiprot.h>

#include "err.h"
#include "util.h"

EFI_STATUS efi_file_open (IN EFI_FILE_PROTOCOL *dir,
                          OUT EFI_FILE_PROTOCOL **opened,
                          CONST IN CHAR16 *path,
                          UINT64 mode,
                          UINT64 attr)
{
    if (!mode)
        mode = EFI_FILE_MODE_READ;

    return uefi_call_wrapper( dir->Open, 5, dir, opened, path, mode, attr );
}

EFI_STATUS efi_file_close (IN EFI_FILE_PROTOCOL *file)
{
    return uefi_call_wrapper( file->Close, 1, file );
}

EFI_STATUS efi_file_exists (IN EFI_FILE_PROTOCOL *dir, CONST IN CHAR16 *path)
{
    EFI_FILE_PROTOCOL *target;
    EFI_STATUS res = EFI_SUCCESS;
    EFI_STATUS r2;

    res = efi_file_open( dir, &target, path, 0, 0 );

    switch (res)
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

EFI_STATUS efi_readdir (IN EFI_FILE_PROTOCOL *dir,
                        IN OUT EFI_FILE_INFO **dirent,
                        IN OUT UINTN *dirent_size)
{
    CONST UINTN bufsize = SIZE_OF_EFI_FILE_INFO + MAXFSNAMLEN;
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

EFI_STATUS efi_file_read (IN EFI_FILE_PROTOCOL *fh,
                          IN OUT CHAR8 *buf,
                          OUT UINTN *bytes)
{
    return uefi_call_wrapper( fh->Read, 3, fh, bytes, buf );
}
