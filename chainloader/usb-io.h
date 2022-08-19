#pragma once

// steamos-efi  --  SteamOS EFI Chainloader

// SPDX-License-Identifier: GPL-2.0+
// Copyright © 2022 Collabora Ltd
// Copyright © 2022 Valve Corporation

// steamos-efi is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 2.0 of the License, or
// (at your option) any later version.

// steamos-efi is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with steamos-efi.  If not, see <http://www.gnu.org/licenses/>.

// ============================================================================

#include <efi.h>
#include "usb.h"

#define EFI_USB_IO_PROTOCOL_GUID  \
    { 0x2b2f68d6, 0x0cd2, 0x44cf, \
      { 0x8e, 0x8b, 0xbb, 0xa2, 0x0b, 0x1b, 0x5b, 0x75 } }

typedef struct _EFI_USB_IO_PROTOCOL EFI_USB_IO_PROTOCOL;

typedef EFI_STATUS (EFIAPI *EFI_USB_IO_CONTROL_TRANSFER)
    (IN EFI_USB_IO_PROTOCOL *this,
     IN EFI_USB_DEVICE_REQUEST *request,
     IN EFI_USB_DATA_DIRECTION direction,
     IN UINT32 timeout,
     IN OUT VOID *data,
     IN UINTN size,
     OUT UINT32 *status);

typedef EFI_STATUS
(EFIAPI *EFI_USB_IO_BULK_TRANSFER)
    (IN EFI_USB_IO_PROTOCOL *this,
     IN UINT8 endpoint,
     IN OUT VOID *data,
     IN OUT UINTN *size,
     IN UINTN timeout,
     OUT UINT32 *status);

typedef EFI_STATUS
(EFIAPI *EFI_USB_IO_ASYNC_INTERRUPT_TRANSFER)
    (IN EFI_USB_IO_PROTOCOL *this,
     IN UINT8 endpoint,
     IN BOOLEAN new_xfer,
     IN UINTN poll_interval,
     IN UINTN size,
     IN EFI_ASYNC_USB_TRANSFER_CALLBACK callback,
     IN VOID *context);

typedef EFI_STATUS
(EFIAPI *EFI_USB_IO_SYNC_INTERRUPT_TRANSFER)
    (IN EFI_USB_IO_PROTOCOL *this,
     IN UINT8 endpoint,
     IN OUT VOID *data,
     IN OUT UINTN *size,
     IN UINTN timeout,
     OUT UINT32 *status);

typedef EFI_STATUS
(EFIAPI *EFI_USB_IO_ISOCHRONOUS_TRANSFER)
    (IN EFI_USB_IO_PROTOCOL *this,
     IN UINT8 endpoint,
     IN OUT VOID *data,
     IN UINTN size,
     OUT UINT32 *status);

typedef EFI_STATUS
(EFIAPI *EFI_USB_IO_ASYNC_ISOCHRONOUS_TRANSFER)
    (IN EFI_USB_IO_PROTOCOL *this,
     IN UINT8 endpoint,
     IN OUT VOID *data,
     IN UINTN size,
     IN EFI_ASYNC_USB_TRANSFER_CALLBACK callback,
     IN VOID *context);


typedef EFI_STATUS
(EFIAPI *EFI_USB_IO_GET_DEVICE_DESCRIPTOR)
    (IN EFI_USB_IO_PROTOCOL *this,
     OUT EFI_USB_DEVICE_DESCRIPTOR *descriptor);

typedef
EFI_STATUS
(EFIAPI *EFI_USB_IO_GET_CONFIG_DESCRIPTOR)
    (IN EFI_USB_IO_PROTOCOL *this,
     OUT EFI_USB_CONFIG_DESCRIPTOR *descriptor);

typedef EFI_STATUS
(EFIAPI *EFI_USB_IO_GET_INTERFACE_DESCRIPTOR)
    (IN EFI_USB_IO_PROTOCOL *this,
     OUT EFI_USB_INTERFACE_DESCRIPTOR *descriptor);

typedef EFI_STATUS
(EFIAPI *EFI_USB_IO_GET_ENDPOINT_DESCRIPTOR)
    (IN EFI_USB_IO_PROTOCOL *this,
     IN UINT8 index,
     OUT EFI_USB_ENDPOINT_DESCRIPTOR *descriptor);

typedef EFI_STATUS
(EFIAPI *EFI_USB_IO_GET_STRING_DESCRIPTOR)
    (IN EFI_USB_IO_PROTOCOL *this,
     IN UINT16 lang_id,
     IN UINT8 string_id,
     OUT CHAR16 **string);

typedef EFI_STATUS
(EFIAPI *EFI_USB_IO_GET_SUPPORTED_LANGUAGES)
    (IN EFI_USB_IO_PROTOCOL *this,
     OUT UINT16 **lang_ids,
     OUT UINT16 *lang_count);

typedef EFI_STATUS
(EFIAPI *EFI_USB_IO_PORT_RESET)
    (IN EFI_USB_IO_PROTOCOL *this);

typedef struct _EFI_USB_IO_PROTOCOL
{
    EFI_USB_IO_CONTROL_TRANSFER UsbControlTransfer;
    EFI_USB_IO_BULK_TRANSFER UsbBulkTransfer;
    EFI_USB_IO_ASYNC_INTERRUPT_TRANSFER UsbAsyncInterruptTransfer;
    EFI_USB_IO_SYNC_INTERRUPT_TRANSFER UsbSyncInterruptTransfer;
    EFI_USB_IO_ISOCHRONOUS_TRANSFER UsbIsochronousTransfer;
    EFI_USB_IO_ASYNC_ISOCHRONOUS_TRANSFER UsbAsyncIsochronousTransfer;
    EFI_USB_IO_GET_DEVICE_DESCRIPTOR UsbGetDeviceDescriptor;
    EFI_USB_IO_GET_CONFIG_DESCRIPTOR UsbGetConfigDescriptor;
    EFI_USB_IO_GET_INTERFACE_DESCRIPTOR UsbGetInterfaceDescriptor;
    EFI_USB_IO_GET_ENDPOINT_DESCRIPTOR UsbGetEndpointDescriptor;
    EFI_USB_IO_GET_STRING_DESCRIPTOR UsbGetStringDescriptor;
    EFI_USB_IO_GET_SUPPORTED_LANGUAGES UsbGetSupportedLanguages;
    EFI_USB_IO_PORT_RESET UsbPortReset;
} EFI_USB_IO_PROTOCOL;

// ============================================================================

