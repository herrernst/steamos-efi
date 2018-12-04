#pragma once

#include <efi.h>

#define MAXFSNAMLEN 200
#define BOOTCONFPATH L"SteamOS\\bootconf"
#define EFIDIR       L"\\EFI"
#define SYSTEMDLDR  EFIDIR L"\\SYSTEMD\\SYSTEMD-BOOTX64.EFI"
#define DEFAULTLDR  EFIDIR L"\\Boot\\bootx64.efi"
#define STEAMOSLDR  SYSTEMDLDR
#define CHAINLDR    EFIDIR L"\\Shell\\steamcl.efi"

VOID * efi_alloc (IN UINTN s);
VOID   efi_free  (IN VOID *p);

CONST CHAR16 * efi_statstr (EFI_STATUS s);
CONST CHAR16 * efi_memtypestr (EFI_MEMORY_TYPE m);

EFI_STATUS get_handle_protocol (EFI_HANDLE *handle,
                                EFI_GUID *id,
                                OUT VOID **protocol);

EFI_STATUS get_protocol_handles (EFI_GUID *guid,
                                 OUT EFI_HANDLE **handles,
                                 OUT UINTN *count);

EFI_STATUS get_protocol_instance_handle (EFI_GUID *id,
                                         VOID *protocol,
                                         OUT EFI_HANDLE *handle);

EFI_HANDLE get_self_handle (VOID);
VOID initialise (EFI_HANDLE image);
