#pragma once

#define MAXFSNAMLEN 200
#define BOOTCONFPATH L"SteamOS\\bootconf"
#define EFIDIR       L"EFI"
#define DEFAULTLDR   L"EFI\\Boot\\bootx64.efi"

extern VOID * efi_alloc (IN UINTN s);
extern VOID   efi_free  (IN VOID *p);

CONST CHAR16 * efi_statstr (EFI_STATUS s);

EFI_STATUS get_handle_protocol (IN EFI_HANDLE *handle,
                                IN EFI_GUID *id,
                                OUT VOID **protocol);

EFI_STATUS get_protocol_handles (IN EFI_GUID *guid,
                                 OUT EFI_HANDLE **handles,
                                 IN OUT UINTN *count);

EFI_STATUS get_protocol_instance_handle (IN EFI_GUID *id,
                                         IN VOID *protocol,
                                         OUT EFI_HANDLE *handle);
