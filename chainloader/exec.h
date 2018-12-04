#pragma once

EFI_STATUS load_image (EFI_DEVICE_PATH *path, EFI_HANDLE *image);

EFI_STATUS exec_image (EFI_HANDLE image, UINTN *code, CHAR16 **data);

EFI_STATUS set_image_cmdline (EFI_HANDLE *image, CHAR16 *cmdline,
                              EFI_LOADED_IMAGE **child);
