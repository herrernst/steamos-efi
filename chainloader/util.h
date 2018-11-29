#pragma once

#define MAXFSNAMLEN 200
#define BOOTCONFPATH L"SteamOS\\bootconf"
#define EFIDIR       L"EFI"
#define DEFAULTLDR   L"EFI\\Boot\\bootx64.efi"

extern VOID * efi_alloc (IN UINTN s);
extern VOID   efi_free  (IN VOID *p);

CONST CHAR16 * efi_statstr (EFI_STATUS s);

