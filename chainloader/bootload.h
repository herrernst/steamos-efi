#pragma once

typedef struct
{
    EFI_HANDLE partition;
    EFI_DEVICE_PATH device_path;
    CHAR16 *loader_path;
} bootloader;

EFI_STATUS valid_efi_binary (EFI_FILE_PROTOCOL *dir, CONST CHAR16 *path);
EFI_STATUS choose_steamos_loader (EFI_HANDLE *handles,
                                  CONST UINTN n_handles,
                                  OUT bootloader *chosen);
EFI_STATUS exec_bootloader (bootloader *boot);
