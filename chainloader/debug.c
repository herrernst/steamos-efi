#include <efi.h>
#include <efilib.h>
#include <efiprot.h>

#include "util.h"

VOID dump_loaded_image (EFI_LOADED_IMAGE *image)
{
    EFI_HANDLE current = get_self_handle();

    Print( L"\n\
typedef struct {                                               \n\
    UINT32                          Revision;         %u       \n\
    EFI_HANDLE                      ParentHandle;     %x %s    \n\
    struct _EFI_SYSTEM_TABLE        *SystemTable;     %x       \n\
                                                               \n\
    // Source location of image                                \n\
    EFI_HANDLE                      DeviceHandle;     %x       \n\
    EFI_DEVICE_PATH                 *FilePath;        %s       \n\
    VOID                            *Reserved;        %x       \n\
                                                               \n\
    // Images load options                                     \n\
    UINT32                          LoadOptionsSize;  %u       \n\
    VOID                            *LoadOptions;   \"%s\"     \n\
                                                               \n\
    // Location of where image was loaded                      \n\
    VOID                            *ImageBase;       %x       \n\
    UINT64                          ImageSize;        %lu      \n\
    EFI_MEMORY_TYPE                 ImageCodeType;    %s       \n\
    EFI_MEMORY_TYPE                 ImageDataType;    %s       \n\
                                                               \n\
    // If the driver image supports a dynamic unload request   \n\
    EFI_IMAGE_UNLOAD                Unload;           %x       \n\
} EFI_LOADED_IMAGE_PROTOCOL;                                   \n",
           image->Revision,
           image->ParentHandle,
           (current ?
            ((current == image->ParentHandle)? L"OK": L"MISMATCH") :
            L"Existential error: No self image" ),
           (UINT64) image->SystemTable,
           image->DeviceHandle,
           DevicePathToStr( image->FilePath ),
           image->Reserved,
           image->LoadOptionsSize,
           (CHAR16 *)image->LoadOptions,
           (UINT64)image->ImageBase,
           image->ImageSize,
           efi_memtypestr( image->ImageCodeType ),
           efi_memtypestr( image->ImageDataType ),
           (UINT64) image->Unload );
}
