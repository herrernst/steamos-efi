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

#define EFI_USB2_HC_PROTOCOL_GUID \
    { 0x3e745226, 0x9818, 0x45b6, \
      { 0xa2, 0xac, 0xd7, 0xcd, 0x0e, 0x8b, 0xa2, 0xbc } }

typedef struct _EFI_USB2_HC_PROTOCOL EFI_USB2_HC_PROTOCOL;

typedef enum
{
    USB_HC_STATE_HALT,
    USB_HC_STATE_ACTIVE,
    USB_HC_STATE_SUSPEND,
    USB_HC_STATE_MAX
} EFI_USB_HC_STATE;

typedef struct
{
    UINT8 TranslatorHubAddress;
    UINT8 TranslatorPortNumber;
} EFI_USB2_HC_TRANSACTION_TRANSLATOR;

typedef EFI_STATUS
(EFIAPI *EFI_USB2_HC_PROTOCOL_GET_CAPABILITY)
    (IN struct _EFI_USB2_HC_PROTOCOL *this,
     OUT UINT8 *max_speed,
     OUT UINT8 *port_number,
     OUT UINT8 *wide);

typedef EFI_STATUS
(EFIAPI *EFI_USB2_HC_PROTOCOL_RESET)
    (IN struct _EFI_USB2_HC_PROTOCOL *this,
     IN UINT16 attr);

typedef EFI_STATUS
(EFIAPI *EFI_USB2_HC_PROTOCOL_GET_STATE)
    (IN struct _EFI_USB2_HC_PROTOCOL *this,
     OUT EFI_USB_HC_STATE *state);

typedef EFI_STATUS
(EFIAPI *EFI_USB2_HC_PROTOCOL_SET_STATE)
    (IN struct _EFI_USB2_HC_PROTOCOL *this,
     IN EFI_USB_HC_STATE state);

typedef EFI_STATUS
(EFIAPI *EFI_USB2_HC_PROTOCOL_CONTROL_TRANSFER)
    (IN struct _EFI_USB2_HC_PROTOCOL *this,
     IN UINT8 dev_addr,
     IN UINT8 dev_speed,
     IN UINTN max_packet,
     IN EFI_USB_DEVICE_REQUEST *request,
     IN EFI_USB_DATA_DIRECTION xfer_dir,
     IN OUT VOID *data OPTIONAL,
     IN OUT UINTN *size OPTIONAL,
     IN UINTN timeout,
     IN EFI_USB2_HC_TRANSACTION_TRANSLATOR *translator,
     OUT UINT32 *result);

typedef EFI_STATUS
(EFIAPI *EFI_USB2_HC_PROTOCOL_BULK_TRANSFER)
    (IN struct _EFI_USB2_HC_PROTOCOL *this,
     IN UINT8 dev_addr,
     IN UINT8 end_addr,
     IN UINT8 dev_speed,
     IN UINTN max_packet,
     IN UINT8 data_buf_count,
     IN OUT VOID *data[EFI_USB_MAX_BULK_BUFFER_NUM],
     IN OUT UINTN *size,
     IN OUT UINT8 *toggle,
     IN UINTN timeout,
     IN EFI_USB2_HC_TRANSACTION_TRANSLATOR *translator,
     OUT UINT32 *result);


typedef EFI_STATUS
(EFIAPI *EFI_USB2_HC_PROTOCOL_ASYNC_INTERRUPT_TRANSFER)
    (IN struct _EFI_USB2_HC_PROTOCOL *this,
     IN UINT8 dev_addr,
     IN UINT8 end_addr,
     IN UINT8 dev_speed,
     IN UINTN max_packet,
     IN BOOLEAN is_new,
     IN OUT UINT8 *toggle,
     IN UINTN poll_interval OPTIONAL,
     IN UINTN size OPTIONAL,
     IN EFI_USB2_HC_TRANSACTION_TRANSLATOR *translator OPTIONAL,
     IN EFI_ASYNC_USB_TRANSFER_CALLBACK callback OPTIONAL,
     IN VOID *context OPTIONAL);

typedef EFI_STATUS
(EFIAPI *EFI_USB2_HC_PROTOCOL_SYNC_INTERRUPT_TRANSFER)
    (IN struct _EFI_USB2_HC_PROTOCOL *this,
     IN UINT8 dev_addr,
     IN UINT8 end_addr,
     IN UINT8 dev_speed,
     IN UINTN max_packet,
     IN OUT VOID *data,
     IN OUT UINTN *size,
     IN OUT UINT8 *toggle,
     IN UINTN timeout,
     IN EFI_USB2_HC_TRANSACTION_TRANSLATOR *translator,
     OUT UINT32 *result);

typedef EFI_STATUS
(EFIAPI *EFI_USB2_HC_PROTOCOL_ISOCHRONOUS_TRANSFER)
    (IN struct _EFI_USB2_HC_PROTOCOL *this,
     IN UINT8 dev_addr,
     IN UINT8 end_addr,
     IN UINT8 dev_speed,
     IN UINTN max_packet,
     IN UINT8 data_buf_count,
     IN OUT VOID *data[EFI_USB_MAX_ISO_BUFFER_NUM],
     IN UINTN size,
     IN EFI_USB2_HC_TRANSACTION_TRANSLATOR *translator,
     OUT UINT32 *result);

typedef EFI_STATUS
(EFIAPI * EFI_USB2_HC_PROTOCOL_ASYNC_ISOCHRONOUS_TRANSFER)
    (IN struct _EFI_USB2_HC_PROTOCOL *this,
     IN UINT8 dev_addr,
     IN UINT8 end_addr,
     IN UINT8 dev_speed,
     IN UINTN max_packet,
     IN UINT8 data_buf_count,
     IN OUT VOID *data[EFI_USB_MAX_ISO_BUFFER_NUM],
     IN UINTN size,
     IN EFI_USB2_HC_TRANSACTION_TRANSLATOR *translator,
     IN EFI_ASYNC_USB_TRANSFER_CALLBACK callback,
     IN VOID *context OPTIONAL);

typedef EFI_STATUS
(EFIAPI *EFI_USB2_HC_PROTOCOL_GET_ROOTHUB_PORT_STATUS)
    (IN struct _EFI_USB2_HC_PROTOCOL *this,
     IN UINT8 port,
     OUT EFI_USB_PORT_STATUS *status);

typedef EFI_STATUS
(EFIAPI *EFI_USB2_HC_PROTOCOL_SET_ROOTHUB_PORT_FEATURE)
    (IN struct _EFI_USB2_HC_PROTOCOL *this,
     IN UINT8 port,
     IN EFI_USB_PORT_FEATURE feature);

typedef EFI_STATUS
(EFIAPI *EFI_USB2_HC_PROTOCOL_CLEAR_ROOTHUB_PORT_FEATURE)
    (IN struct _EFI_USB2_HC_PROTOCOL *this,
     IN UINT8 port,
     IN EFI_USB_PORT_FEATURE feature);

typedef struct _EFI_USB2_HC_PROTOCOL
{
    EFI_USB2_HC_PROTOCOL_GET_CAPABILITY GetCapability;
    EFI_USB2_HC_PROTOCOL_RESET Reset;
    EFI_USB2_HC_PROTOCOL_GET_STATE GetState;
    EFI_USB2_HC_PROTOCOL_SET_STATE SetState;
    EFI_USB2_HC_PROTOCOL_CONTROL_TRANSFER ControlTransfer;
    EFI_USB2_HC_PROTOCOL_BULK_TRANSFER BulkTransfer;
    EFI_USB2_HC_PROTOCOL_ASYNC_INTERRUPT_TRANSFER AsyncInterruptTransfer;
    EFI_USB2_HC_PROTOCOL_SYNC_INTERRUPT_TRANSFER SyncInterruptTransfer;
    EFI_USB2_HC_PROTOCOL_ISOCHRONOUS_TRANSFER IsochronousTransfer;
    EFI_USB2_HC_PROTOCOL_ASYNC_ISOCHRONOUS_TRANSFER AsyncIsochronousTransfer;
    EFI_USB2_HC_PROTOCOL_GET_ROOTHUB_PORT_STATUS GetRootHubPortStatus;
    EFI_USB2_HC_PROTOCOL_SET_ROOTHUB_PORT_FEATURE SetRootHubPortFeature;
    EFI_USB2_HC_PROTOCOL_CLEAR_ROOTHUB_PORT_FEATURE ClearRootHubPortFeature;
    UINT16 MajorRevision;
    UINT16 MinorRevision;
} EFI_USB2_HC_PROTOCOL;

// ============================================================================
EFI_STATUS dump_usb_state (void);
