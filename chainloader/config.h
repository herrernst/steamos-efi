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

#pragma once

#include <stdint.h>

#define MAX_BOOTCONFS 16

typedef enum
{
    cfg_string,
    cfg_bool,
    cfg_uint,
    cfg_path,
    cfg_stamp,
    cfg_end,
} cfg_entry_type;

typedef struct
{
    cfg_entry_type type;
    char *name;
    struct
    {
        struct { unsigned char *bytes; uint64_t size; } string;
        union  { uint64_t u; int64_t i; } number;
    } value;
} cfg_entry;


#ifndef NO_EFI_TYPES
EFI_STATUS parse_config (EFI_FILE_PROTOCOL *root_dir,
                         CHAR16 *path,
                         cfg_entry **config);

VOID dump_config (cfg_entry *config);
#else
const char *_cts (cfg_entry_type t);
#endif

const cfg_entry *get_conf_item (const cfg_entry *config, const CHAR8 *name);

UINT64 get_conf_uint (const cfg_entry *config, char *name);

CHAR8 *get_conf_str (const cfg_entry *config, char *name);

cfg_entry *new_config (VOID);

VOID free_config (cfg_entry **config);

EFI_STATUS set_config_from_data (cfg_entry *cfg, CHAR8 *data, UINTN size);

