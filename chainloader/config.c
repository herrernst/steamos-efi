// steamos-efi  --  SteamOS EFI Chainloader

// SPDX-License-Identifier: GPL-2.0+
// Copyright © 2018,2021 Collabora Ltd
// Copyright © 2018,2021 Valve Corporation
// Copyright © 2018,2020 Vivek Das Mohapatra <vivek@etla.org>

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

#ifdef NO_EFI_TYPES
#include "bootconf/efi.h"
#endif

#include "err.h"
#include "util.h"

#ifndef NO_EFI_TYPES
#include "fileio.h"
#include "bootload.h"
#include <efilib.h>
#endif

#include "config.h"

static cfg_entry bootspec[] =
  { { .type = cfg_stamp , .name = "boot-requested-at"   },
    { .type = cfg_bool  , .name = "boot-other"          },
    { .type = cfg_bool  , .name = "boot-other-disabled" },
    { .type = cfg_uint  , .name = "boot-attempts"       },
    { .type = cfg_uint  , .name = "boot-count"          },
    { .type = cfg_stamp , .name = "boot-time"           },
    { .type = cfg_bool  , .name = "image-invalid"       },
    { .type = cfg_bool  , .name = "update"              },
    { .type = cfg_bool  , .name = "update-disabled"     },
    { .type = cfg_stamp , .name = "update-window-start" },
    { .type = cfg_stamp , .name = "update-window-end"   },
    { .type = cfg_path  , .name = "loader"              },
    { .type = cfg_string, .name = "partitions"          },
    { .type = cfg_string, .name = "title"               },
    { .type = cfg_string, .name = "comment"             },
    { .type = cfg_end } };

static UINTN set_config_item_from_line (cfg_entry *item, CHAR8 *line)
{
    UINTN nl = strlen_a( (CHAR8 *)item->name );
    UINTN ll = strlen_a( line );
    CHAR8 *start = NULL;
    UINTN vsize = 0;
    CHAR8 *nstart = NULL;
    CHAR8 *nend = NULL;
    UINTN place = 1;
    // no room for "NAME:"
    if( ll <= nl + 1 )
        return 0;

    // beginning of line does not match item->name + ':'
    if( strncmpa( (CHAR8 *)item->name, line, nl ) )
        return 0;
    if( line[ nl ] != ':' )
        return 0;

    for( start = line + nl + 1; start < (line + ll) && *start; start++ )
        if( *start != ' ' )
            break;

    vsize = ll - (start - line);

    for( CHAR8 *c = start + vsize - 1; c >= start; c-- )
        if( *c == ' ' )
            vsize--;
        else
            break;

    item->value.string.bytes = ALLOC_OR_GOTO( vsize + 1, allocfail );
    item->value.string.size  = vsize;
    mem_copy( item->value.string.bytes, start, vsize );
    item->value.string.bytes[ vsize ] = (CHAR8)0;

    switch( item->type )
    {
      case cfg_bool:
      case cfg_uint:
      case cfg_stamp: // ← this is not OK on 32 bit. We don't care.
        nstart = &item->value.string.bytes[ 0 ];
        nend   = nstart + item->value.string.size;
        item->value.number.u = 0;
        for( nend--; nend >= nstart; nend-- )
        {
            if( *nend < '0' || *nend > '9' )
            {
                item->value.number.u = 0;
                break;
            }
            item->value.number.u += (*nend - '0') * place;
            place *= 10;
        }
        break;
      default:
        item->value.number.u = 0;
    }

    return 1;

allocfail:
#ifndef NO_EFI_TYPES
    Print( L"Red alert! alloc of %u bytes failed\n", vsize + 1 );
#endif
    return 0;
}

static UINTN set_config_from_line (cfg_entry *cfg, CHAR8* line)
{
    UINTN found = 0;

    for( UINTN i = 0; cfg[ i ].type != cfg_end; i++  )
        found += set_config_item_from_line( &cfg[ i ], line );

    return found;
}

EFI_STATUS set_config_from_data (cfg_entry *cfg, CHAR8 *data, UINTN size)
{
    UINTN found = 0;

    for( CHAR8 *c = data; c < data + size; c++ )
        if( *c == '\n')
            *c = (CHAR8) 0;

    for( CHAR8 *c = data; c < data + size; c++ )
        if( (c == data) || (*(c - 1) == (CHAR8)0) )
            found += set_config_from_line( cfg, c );

    return found ? EFI_SUCCESS : EFI_END_OF_FILE;
}

#ifndef NO_EFI_TYPES
static CONST CHAR16 *_cts (cfg_entry_type t)
{
    switch( t )
    {
      case cfg_string: return L"string";
      case cfg_bool:   return L"bool";
      case cfg_uint:   return L"uint";
      case cfg_path:   return L"path";
      case cfg_stamp:  return L"stamp";
      case cfg_end:    return L"end";
      default:
        return L"UNKNOWN";
    }
}
#else
const char *_cts (cfg_entry_type t)
{
    switch( t )
    {
      case cfg_string: return "string";
      case cfg_bool:   return "bool";
      case cfg_uint:   return "uint";
      case cfg_path:   return "path";
      case cfg_stamp:  return "stamp";
      case cfg_end:    return "end";
      default:
        return "UNKNOWN";
    }
}
#endif

__attribute__ ((unused))
static CONST CHAR8 *_vts (cfg_entry *c)
{
    return (CHAR8 *) c->value.string.bytes ?: (CHAR8 *) "-UNSET-";
}

#ifndef NO_EFI_TYPES
VOID dump_config (cfg_entry *config)
{
    for( UINTN i = 0; config[ i ].type != cfg_end; i++ )
        Print( L"#%u <%s>%a = <%u>'%a'\n",
               i,
               _cts( config[ i ].type ),
               config[ i ].name,
               config[ i ].value.string.size,
               _vts( &config[ i ] ) );
}
#endif

#ifndef NO_EFI_TYPES
EFI_STATUS parse_config (EFI_FILE_PROTOCOL *root_dir,
                         CHAR16 *path,
                         cfg_entry **config)
{
    EFI_STATUS res = EFI_SUCCESS;
    EFI_FILE_PROTOCOL *cffile = NULL;
    CHAR8 *cfdata;
    UINTN cfsize;
    UINTN cfalloc;

    *config = new_config();
    if( !config )
        goto allocfail;

    res = efi_file_open( root_dir, &cffile, path, 0, 0 );
    ERROR_JUMP( res, cleanup, L"parse_bootconfig: %s", path );

    res = efi_file_to_mem( cffile, &cfdata, &cfsize, &cfalloc );
    ERROR_JUMP( res, cleanup, L"parse_bootconfig: load to mem failed" );

    res = set_config_from_data( *config, cfdata, cfsize );

cleanup:
    efi_free( cfdata );
    efi_file_close( cffile );

    return res;

allocfail:
    efi_free( *config );
    *config = NULL;
    return EFI_OUT_OF_RESOURCES;
}
#endif

const cfg_entry *get_conf_item (const cfg_entry *config, const CHAR8 *name)
{
    if( !name )
        return NULL;

    if( !config )
        return NULL;

    for( UINTN i = 0; config[ i ].type != cfg_end; i++ )
        if( config[ i ].name && *(config[ i ].name))
            if( strcmpa( (CHAR8 *)config[ i ].name, name ) == 0 )
                return &config[ i ];

    return NULL;
}

UINT64 get_conf_uint (const cfg_entry *config, char *name)
{
    const cfg_entry *c = get_conf_item( config, (CHAR8 *)name );

    return c ? c->value.number.u : 0;
}

CHAR8 *get_conf_str (const cfg_entry *config, char *name)
{
    const cfg_entry *c = get_conf_item( config, (CHAR8 *)name );

    return c ? &c->value.string.bytes[ 0 ] : NULL;
}

cfg_entry *new_config (VOID)
{
    cfg_entry *config = efi_alloc( sizeof(bootspec) );

#ifndef NO_EFI_TYPES
    WARN_STATUS( (config != NULL) ? EFI_SUCCESS : EFI_OUT_OF_RESOURCES,
                 L"Failed to allocate %d bytes for bootspec",
                 sizeof(bootspec) );
#endif

    if( config )
        mem_copy( config, &bootspec[ 0 ], sizeof(bootspec) );

    return config;
}

VOID free_config (cfg_entry **config)
{
    cfg_entry *conf = *config;

    if( !conf )
        return;

    for( UINTN i = 0; conf[ i ].type != cfg_end; i++ )
    {
        conf[ i ].value.string.size = 0;
        conf[ i ].value.number.u = 0;
        if( !conf[ i ].value.string.bytes )
            continue;
        efi_free( conf[ i ].value.string.bytes );
        conf[ i ].value.string.bytes = NULL;
    }

    efi_free( conf );
    *config = NULL;
}
