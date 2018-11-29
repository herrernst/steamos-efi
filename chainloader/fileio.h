#pragma once

EFI_STATUS efi_file_exists (IN EFI_FILE_PROTOCOL *dir, CONST IN CHAR16 *path);

EFI_STATUS efi_file_open (IN EFI_FILE_PROTOCOL *dir,
                          OUT EFI_FILE_PROTOCOL **opened,
                          CONST IN CHAR16 *path,
                          UINT64 mode,
                          UINT64 attr);

EFI_STATUS efi_file_close (IN EFI_FILE_PROTOCOL *file);

EFI_STATUS efi_readdir (IN EFI_FILE_PROTOCOL *dir,
                        IN OUT EFI_FILE_INFO **dirent,
                        IN OUT UINTN *dirent_size);

EFI_STATUS efi_file_read (IN EFI_FILE_PROTOCOL *fh,
                          IN OUT CHAR8 *buf,
                          IN OUT UINTN *bytes);
