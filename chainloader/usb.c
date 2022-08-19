// steamos-efi  --  SteamOS EFI Chainloader

// SPDX-License-Identifier: GPL-2.0+
// Copyright © 2018,2019 Collabora Ltd
// Copyright © 2018,2019 Valve Corporation
// Copyright © 2018,2019 Vivek Das Mohapatra <vivek@etla.org>

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

#include "usb-hc.h"
#include "usb-io.h"
#include "usb-fn.h"
#include "util.h"
#include "err.h"

// #define FORCE_ENABLE_USB_PORTS
// #define TRY_LIZARD_COMMAND
#define STEAM_SERIAL_LEN 10
#define STEAM_CMD_GET_SERIAL		0xae
#define STEAM_CMD_DEFAULT_MAPPINGS      0x85

#ifdef TRY_LIZARD_COMMAND
static UINT8
_steam_lizard (EFI_USB_IO_PROTOCOL *iop, EFI_USB_DEVICE_DESCRIPTOR *dd)
{
    EFI_USB_DEVICE_REQUEST req = { 0 };
    UINT32 ctl_status = 0;
    EFI_STATUS r1, r2;
    CHAR8 cmd = STEAM_CMD_DEFAULT_MAPPINGS;

    if( dd->IdVendor != 0x28de ||
        dd->IdProduct < 0x1200 )
        return 0;

    req.RequestType = 0x00;
    req.Request     = 0x09;
    req.Value  = cmd;
    req.Index  = 0;
    req.Length = 0;

    v_msg( L"Sending 1-byte lizard mode command 0x%x\n", req.Value );

    // unclear whether the command byte goes in the request structure
    r1 = uefi_call_wrapper( iop->UsbControlTransfer, 7,
                            iop, &req, USB_NONE, 1000, NULL, 0,
                            &ctl_status );
    v_msg( L"lizard response %d: %d(%s : %r)/%d\n",
           cmd, r1, efi_statstr(r1), r1, ctl_status );

    // or the data block:
    req.Value = 0;
    r2 = uefi_call_wrapper( iop->UsbControlTransfer, 7,
                            iop, &req, USB_OUT, 1000, &cmd, 1,
                            &ctl_status );
    v_msg( L"lizard response %d: %d(%s : %r)/%d\n",
           cmd, r2, efi_statstr(r2), r2, ctl_status );

    return 1;
}
#endif

EFI_STATUS dump_usb_state (void)
{
    EFI_HANDLE *hc = NULL;
    EFI_HANDLE *io = NULL;
    EFI_HANDLE *fn = NULL;
    EFI_STATUS res = EFI_SUCCESS;
    EFI_GUID hc_guid = EFI_USB2_HC_PROTOCOL_GUID;
    EFI_GUID io_guid = EFI_USB_IO_PROTOCOL_GUID;
    EFI_GUID fn_guid = EFI_USBFN_IO_PROTOCOL_GUID;
    UINTN count = 0;
    UINTN ioc = 0;
    UINTN fnc = 0;
    EFI_USB_HC_STATE state;

    res = get_protocol_handles( &hc_guid, &hc, &count );
    ERROR_RETURN( res, res,  L"Failed to get host-controller handles" );
    v_msg( L"%d host controllers found\n", count );

    res = get_protocol_handles( &io_guid, &io, &ioc );
    if( res == EFI_SUCCESS )
        v_msg( L"%d USB IO endpoints found\n", ioc );
    WARN_STATUS( res, L"Fetching USB-IO interfaces" );

    res = get_protocol_handles( &fn_guid, &fn, &fnc );
    if( res == EFI_SUCCESS )
        v_msg( L"%d USB FN interfaces found\n", fnc );
    WARN_STATUS( res, L"Fetching USB-FN interfaces" );

    for( UINTN i = 0; i < count; i++ )
    {
        EFI_USB2_HC_PROTOCOL *host = NULL;
        const CHAR16 *status;

        res = get_handle_protocol( &hc[i], &hc_guid, (VOID **)&host );
        ERROR_CONTINUE( res, L"Handle #%d (%x) missing USB2_HC protocol",
                        i, hc[i] );

        res = uefi_call_wrapper( host->GetState, 2, host, &state );

        if( res != EFI_SUCCESS )
            status = efi_statstr( res );
        else
            switch( state )
            {
              case USB_HC_STATE_HALT:    status = L"dead";   break;
              case USB_HC_STATE_ACTIVE:  status = L"alive";  break;
              case USB_HC_STATE_SUSPEND: status = L"asleep"; break;
              default:
                status = L"unknown";
            }

        UINT8 speed = 0;
        UINT8 ports = 0;
        UINT8 width = 0;
        const CHAR16 *spd_desc = L"???";

//        res = uefi_call_wrapper( host->Reset, 2, host, 0x1 );
//        v_msg( L"host reset: %s\n", efi_statstr(res) );

        res = uefi_call_wrapper( host->GetCapability, 4, host,
                                 &speed, &ports, &width );

        if( res == EFI_SUCCESS )
            switch( speed )
            {
              case 0: spd_desc = L"FULL" ; break;
              case 1: spd_desc = L"LOW"  ; break;
              case 2: spd_desc = L"HIGH" ; break;
              case 3: spd_desc = L"SUPER"; break;
              default:
                spd_desc = L"UNKNOWN";
            }

        v_msg( L"Host controller %d %s: %d ports, speed %s, %dbit\n",
               i, status, ports, spd_desc, width ? 64 : 32 );

        for( UINTN p = 0; p < ports; p++ )
        {
            UINT16 before = 0;
#ifdef FORCE_ENABLE_USB_PORTS
            UINT16 after  = 0;
#endif
            EFI_USB_PORT_STATUS pstat = { 0 };

            res = uefi_call_wrapper( host->GetRootHubPortStatus, 3,
                                     host, p, &pstat );
            ERROR_CONTINUE( res, L"port status #%d error", p );

            before = pstat.PortStatus;

#ifdef FORCE_ENABLE_USB_PORTS
            if( !(before & USB_PORT_STAT_ENABLE) )
            {
                res = uefi_call_wrapper( host->SetRootHubPortFeature, 3,
                                         host, p, EfiUsbPortEnable );
                WARN_STATUS(res, "enable port %d", p);
                v_msg( L"enable-%d ", res );
            }

            if( !(before & USB_PORT_STAT_POWER) )
            {
                res = uefi_call_wrapper( host->SetRootHubPortFeature, 3,
                                         host, p, EfiUsbPortPower );
                WARN_STATUS(res, "power port %d", p);
                v_msg( L"power-%d ", res );
            }

            res = uefi_call_wrapper( host->GetRootHubPortStatus, 3,
                                     host, p, &pstat );
            if( res == EFI_SUCCESS )
                after = pstat.PortStatus;
            else
                after = before;

            v_msg( L"%d [%04x -> %04x]\n", p, before, after );
#else
            v_msg( L"%d [%04x]\n", p, before );
#endif
        }
    }

#ifdef TRY_LIZARD_COMMAND
    UINT8 lizard = 0;
#endif

    for( UINTN i = 0; i < ioc; i++ )
    {
        UINT16 *lang = NULL;
        UINT16 nl = 0;
        EFI_USB_IO_PROTOCOL *iop = NULL;
        EFI_USB_DEVICE_DESCRIPTOR dd = { 0 };
        EFI_USB_INTERFACE_DESCRIPTOR usbif = { 0 };

        res = get_handle_protocol( &io[i], &io_guid, (VOID **)&iop );
        ERROR_CONTINUE( res, L"Handle #%d (%x) missing USB_IO protocol",
                        i, io[i] );

#ifdef FORCE_ENABLE_USB_PORTS
        res = uefi_call_wrapper( iop->UsbPortReset, i, iop );
        WARN_STATUS( res, L"Port reset" );
#endif

        res = uefi_call_wrapper( iop->UsbGetSupportedLanguages, 3,
                                 iop, &lang, &nl );

        res = uefi_call_wrapper( iop->UsbGetDeviceDescriptor, 2, iop, &dd );
        ERROR_CONTINUE( res, L"fetch device descriptor #%d", i );

#ifdef TRY_LIZARD_COMMAND
        if( !lizard )
            lizard += _steam_lizard( iop, &dd );
#endif

        if( nl > 0 )
        {
            CHAR16 *vend = NULL;
            CHAR16 *prod = NULL;
            EFI_STATUS ra, rb;

            ra = uefi_call_wrapper( iop->UsbGetStringDescriptor, 4,
                                    iop, lang[0], dd.StrManufacturer, &vend );
            rb = uefi_call_wrapper( iop->UsbGetStringDescriptor, 4,
                                    iop, lang[0], dd.StrProduct, &prod );

            if( ra != EFI_SUCCESS || rb != EFI_SUCCESS )
                v_msg( L"fetch: %s / %s\n", efi_statstr(ra), efi_statstr(rb) );

            v_msg( L"( io#%d %04x:%s %04x:%s [%04x/%04x] :: ", i,
                   dd.IdVendor , vend ?: L"-",
                   dd.IdProduct, prod ?: L"-",
                   dd.DeviceClass,
                   dd.DeviceSubClass );

            efi_free( vend );
            efi_free( prod );
        }
        else
        {
            v_msg( L"( io#%d %04x:%04x :: ", i, dd.IdVendor, dd.IdProduct );
        }

        res = uefi_call_wrapper( iop->UsbGetInterfaceDescriptor, 2,
                                 iop, &usbif );
        WARN_STATUS( res, L" Fetching USB interface descriptor:" );
        if( res == EFI_SUCCESS )
            v_msg( L"[%02x/%02x/%x] )\n",
                   usbif.InterfaceClass, usbif.InterfaceSubClass,
                   usbif.InterfaceProtocol );
        else
            v_msg( L"[--/--/-] )\n" );
    }

    return res;
}
