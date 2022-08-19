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

#define EFI_USB_MAX_ISO_BUFFER_NUM  7
#define EFI_USB_MAX_ISO_BUFFER_NUM1 2
#define EFI_USB_MAX_BULK_BUFFER_NUM 10

#define USB_PORT_STAT_CONNECTION    0x0001
#define USB_PORT_STAT_ENABLE        0x0002
#define USB_PORT_STAT_SUSPEND       0x0004
#define USB_PORT_STAT_OVERCURRENT   0x0008
#define USB_PORT_STAT_RESET         0x0010
#define USB_PORT_STAT_POWER         0x0100
#define USB_PORT_STAT_LOW_SPEED     0x0200
#define USB_PORT_STAT_HIGH_SPEED    0x0400
#define USB_PORT_STAT_SUPER_SPEED   0x0800
#define USB_PORT_STAT_OWNER         0x2000

#define EFI_USB_NOERROR             0x0000
#define EFI_USB_ERR_NOTEXECUTE      0x0001
#define EFI_USB_ERR_STALL           0x0002
#define EFI_USB_ERR_BUFFER          0x0004
#define EFI_USB_ERR_BABBLE          0x0008
#define EFI_USB_ERR_NAK             0x0010
#define EFI_USB_ERR_CRC             0x0020
#define EFI_USB_ERR_TIMEOUT         0x0040
#define EFI_USB_ERR_BITSTUFF        0x0080
#define EFI_USB_ERR_SYSTEM          0x0100

typedef struct
{
    UINT8  RequestType;
    UINT8  Request;
    UINT16 Value;
    UINT16 Index;
    UINT16 Length;
} EFI_USB_DEVICE_REQUEST;

typedef enum
{
  //
  // USB request type
  //
  USB_REQ_TYPE_STANDARD = (0x00 << 5),
  USB_REQ_TYPE_CLASS    = (0x01 << 5),
  USB_REQ_TYPE_VENDOR   = (0x02 << 5),

  //
  // Standard control transfer request type, or the value
  // to fill in EFI_USB_DEVICE_REQUEST.Request
  //
  USB_REQ_GET_STATUS     = 0x00,
  USB_REQ_CLEAR_FEATURE  = 0x01,
  USB_REQ_SET_FEATURE    = 0x03,
  USB_REQ_SET_ADDRESS    = 0x05,
  USB_REQ_GET_DESCRIPTOR = 0x06,
  USB_REQ_SET_DESCRIPTOR = 0x07,
  USB_REQ_GET_CONFIG     = 0x08,
  USB_REQ_SET_CONFIG     = 0x09,
  USB_REQ_GET_INTERFACE  = 0x0A,
  USB_REQ_SET_INTERFACE  = 0x0B,
  USB_REQ_SYNCH_FRAME    = 0x0C,

  //
  // Usb control transfer target
  //
  USB_TARGET_DEVICE    = 0,
  USB_TARGET_INTERFACE = 0x01,
  USB_TARGET_ENDPOINT  = 0x02,
  USB_TARGET_OTHER     = 0x03,

  //
  // USB Descriptor types
  //
  USB_DESC_TYPE_DEVICE    = 0x01,
  USB_DESC_TYPE_CONFIG    = 0x02,
  USB_DESC_TYPE_STRING    = 0x03,
  USB_DESC_TYPE_INTERFACE = 0x04,
  USB_DESC_TYPE_ENDPOINT  = 0x05,
  USB_DESC_TYPE_HID       = 0x21,
  USB_DESC_TYPE_REPORT    = 0x22,

  //
  // Features to be cleared by CLEAR_FEATURE requests
  //
  USB_FEATURE_ENDPOINT_HALT = 0,

  //
  // USB endpoint types: 00: control, 01: isochronous, 10: bulk, 11: interrupt
  //
  USB_ENDPOINT_CONTROL   = 0x00,
  USB_ENDPOINT_ISO       = 0x01,
  USB_ENDPOINT_BULK      = 0x02,
  USB_ENDPOINT_INTERRUPT = 0x03,

  USB_ENDPOINT_TYPE_MASK = 0x03,
  USB_ENDPOINT_DIR_IN    = 0x80,

  //
  // Use 200 ms to increase the error handling response time
  //
  EFI_USB_INTERRUPT_DELAY = 2000000
} USB_TYPES_DEFINITION;

//

typedef enum
{
    USB_IN,
    USB_OUT,
    USB_NONE
} EFI_USB_DATA_DIRECTION;

typedef enum
{
    EfiUsbPortEnable            = 1,
    EfiUsbPortSuspend           = 2,
    EfiUsbPortReset             = 4,
    EfiUsbPortPower             = 8,
    EfiUsbPortOwner             = 13,
    EfiUsbPortConnectChange     = 16,
    EfiUsbPortEnableChange      = 17,
    EfiUsbPortSuspendChange     = 18,
    EfiUsbPortOverCurrentChange = 19,
    EfiUsbPortResetChange       = 20
} EFI_USB_PORT_FEATURE;

typedef struct
{
    UINT16 PortStatus;
    UINT16 PortChangeStatus;
} EFI_USB_PORT_STATUS;

typedef struct
{
    UINT8  Length;
    UINT8  DescriptorType;
    UINT16 BcdUSB;
    UINT8  DeviceClass;
    UINT8  DeviceSubClass;
    UINT8  DeviceProtocol;
    UINT8  MaxPacketSize0;
    UINT16 IdVendor;
    UINT16 IdProduct;
    UINT16 BcdDevice;
    UINT8  StrManufacturer;
    UINT8  StrProduct;
    UINT8  StrSerialNumber;
    UINT8  NumConfigurations;
} EFI_USB_DEVICE_DESCRIPTOR;

typedef struct
{
    UINT8  Length;
    UINT8  DescriptorType;
    UINT16 TotalLength;
    UINT8  NumInterfaces;
    UINT8  ConfigurationValue;
    UINT8  Configuration;
    UINT8  Attributes;
    UINT8  MaxPower;
} EFI_USB_CONFIG_DESCRIPTOR;

typedef struct
{
    UINT8 Length;
    UINT8 DescriptorType;
    UINT8 InterfaceNumber;
    UINT8 AlternateSetting;
    UINT8 NumEndpoints;
    UINT8 InterfaceClass;
    UINT8 InterfaceSubClass;
    UINT8 InterfaceProtocol;
    UINT8 Interface;
} EFI_USB_INTERFACE_DESCRIPTOR;

typedef struct
{
    UINT8  Length;
    UINT8  DescriptorType;
    UINT8  EndpointAddress;
    UINT8  Attributes;
    UINT16 MaxPacketSize;
    UINT8  Interval;
} EFI_USB_ENDPOINT_DESCRIPTOR;

typedef EFI_STATUS
(EFIAPI * EFI_ASYNC_USB_TRANSFER_CALLBACK)
    (IN VOID *data,
     IN UINTN size,
     IN VOID *context,
     IN UINT32 status);

EFI_STATUS dump_usb_state (void);
