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
        // not sure we can even use fp in EFI, come to think of it:
        union  { UINTN u; INTN i; double d; float f; } number;
    } value;
} cfg_entry;

EFI_STATUS parse_config (EFI_HANDLE *partition, cfg_entry **config);

VOID dump_config (cfg_entry *config);
