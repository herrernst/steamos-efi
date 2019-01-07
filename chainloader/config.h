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

cfg_entry * get_conf_item (cfg_entry *config, CHAR8 *name);

UINT64 get_conf_uint (cfg_entry *config, char *name);

CHAR8 * get_conf_str (cfg_entry *config, char *name);


VOID free_config (cfg_entry **config);
