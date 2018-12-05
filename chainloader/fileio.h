#pragma once

#include <efi.h>

EFI_STATUS efi_file_exists (EFI_FILE_PROTOCOL *dir, CONST CHAR16 *path);

EFI_STATUS efi_file_open (EFI_FILE_PROTOCOL *dir,
                          OUT EFI_FILE_PROTOCOL **opened,
                          CONST CHAR16 *path,
                          UINT64 mode,
                          UINT64 attr);

EFI_STATUS efi_file_close (EFI_FILE_PROTOCOL *file);

EFI_STATUS efi_readdir (EFI_FILE_PROTOCOL *dir,
                        IN OUT EFI_FILE_INFO **dirent,
                        IN OUT UINTN *dirent_size);

EFI_STATUS efi_file_read (EFI_FILE_PROTOCOL *fh,
                          IN OUT CHAR8 *buf,
                          IN OUT UINTN *bytes);

EFI_STATUS efi_mount (EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *part,
                      OUT EFI_FILE_PROTOCOL **root);

EFI_STATUS efi_unmount (IN OUT EFI_FILE_PROTOCOL **root);

VOID ls (EFI_FILE_PROTOCOL *dir,
         UINTN indent,
         CONST CHAR16 *name,
         UINTN recurse);

EFI_STATUS efi_file_stat (EFI_FILE_PROTOCOL *fh,
                          IN OUT EFI_FILE_INFO **info,
                          IN OUT UINTN *bufsize);

EFI_STATUS efi_file_to_mem (EFI_FILE_PROTOCOL *fh,
                            OUT CHAR8 **buf,
                            OUT UINTN *bytes,
                            OUT UINTN *alloc);
