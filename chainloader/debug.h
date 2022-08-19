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

#pragma once

#include <efi.h>
#include "util.h"
#include "fileio.h"

extern EFI_FILE_PROTOCOL *debug_log;
extern UINT64 debug_message_count;
extern CHAR8 log_stamp[];

VOID update_logstamp   (VOID);
VOID debug_log_init    (EFI_FILE_PROTOCOL *dir, CHAR16 *path_rel, CHAR16 *file);
VOID debug_log_close   (VOID);
VOID debug_log_printf  (const char *fmt, ...);
VOID debug_log_wprintf (const CHAR16 *fmt, ...);

#define DEBUG_LOGGING (debug_log != NULL)

#define DEBUG_LOG(fmt, ...) \
    ({ if( DEBUG_LOGGING )                                              \
       {  update_logstamp();                                            \
          debug_log_printf( "%03d %a %a:%a@%d " fmt "\n",               \
                            debug_message_count++, &log_stamp[11],      \
                            __FILE__, __func__, __LINE__, ##__VA_ARGS__ ); } })

#define DEBUG_VMSG(fmt, ...) \
    ({ if( DEBUG_LOGGING )                                          \
       {  update_logstamp();                                        \
          debug_log_wprintf( L"%03d %a %a:%a@%d " fmt,              \
                             debug_message_count++, &log_stamp[11], \
                            __FILE__, __func__, __LINE__, ##__VA_ARGS__ ); } })
