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
        struct { CHAR8 *bytes; UINTN size; } string;
        union  { UINT64 u; INT64 i; } number;
    } value;
} cfg_entry;

EFI_STATUS parse_config (EFI_FILE_PROTOCOL *root_dir, cfg_entry **config);

VOID dump_config (cfg_entry *config);

const cfg_entry *get_conf_item (const cfg_entry *config, CHAR8 *name);

UINT64 get_conf_uint (const cfg_entry *config, char *name);

CHAR8 *get_conf_str (const cfg_entry *config, char *name);

VOID free_config (cfg_entry **config);
