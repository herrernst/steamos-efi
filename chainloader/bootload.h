#pragma once

typedef struct
{
    EFI_HANDLE partition;
    EFI_DEVICE_PATH device_path;
    CHAR16 *loader_path;
} bootloader;

EFI_STATUS valid_efi_binary (IN EFI_FILE_PROTOCOL *dir, CONST IN CHAR16 *path);
EFI_STATUS choose_steamos_loader (IN EFI_HANDLE *handles,
                                  CONST IN UINTN n_handles,
                                  IN OUT bootloader *chosen);
EFI_STATUS exec_bootloader (EFI_HANDLE *current_image, bootloader *boot);
