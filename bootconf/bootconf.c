#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdarg.h>
#include <limits.h>
#include <time.h>
#include <sys/types.h>
#include <ctype.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/param.h>
#include <dirent.h>

#include "bootconf.h"
#include <chainloader/config.h>
#include <chainloader/partset.h>
#include "config-extra.h"

#define TRACE(x, fmt, ...) \
    ({ if( verbose >= x ) fprintf( stderr, fmt, ##__VA_ARGS__ ); })

typedef enum
{
    ARG_STD = 0,
    ARG_EARLY,
} phase;

typedef struct
{
    char ident[NAME_MAX];
    bool disabled;
    bool loaded;
    uint64_t at;
    cfg_entry *cfg;
    int fd;
    int altered;
} image_cfg;

typedef int (*cmd_func) (image_cfg *conf, size_t limit,
                         int argc, char **argv, uint params);
typedef int (*post_func) (image_cfg *conf, size_t limit);

typedef int (*arg_func) (int n, int max, char **argv,
                         image_cfg *conf, size_t limit);

typedef struct
{
    const char *cmd;
    uint params;
    arg_func function;
    phase parse_phase;
} arg_handler;

typedef struct
{
    const char *cmd;
    uint params;
    cmd_func preprocess;
    post_func postprocess;
    int status;
} cmd_handler;

static uint verbose = 0;
static uint create_missing = 1;
static DIR  *confdir = NULL;
static DIR  *efidir = NULL;
static int selected_image = -1;
static const char *progname = NULL;
static char target_ident[NAME_MAX] = "";
static char *confdir_path = NULL;
static char *efidir_path = NULL;
static image_cfg found[MAX_BOOTCONFS] = { 0 };

unsigned long get_conf_uint_highest (image_cfg *conf, char *k, size_t lim)
{
    size_t i;
    unsigned long max = 0;

    for( i = 0 ; i < lim; i++ )
    {
        unsigned long val = 0;

        if( !(conf + i)->loaded )
            continue;

        val = get_conf_uint( (conf + i)->cfg, k );

        if( val > max )
            max = val;
    }

    return max;
}

void set_other_conf_uint (image_cfg *conf,
                          size_t lim,
                          size_t ignore,
                          char *key,
                          uint64_t val)
{
    for( size_t i = 0 ; i < lim; i++ )
    {
        uint64_t old;

        if( i == ignore )
            continue;

        if( !(conf + i)->loaded )
            continue;

        old = get_conf_uint( (conf + i)->cfg, key );

        if( old == val )
            continue;

        set_conf_uint( (conf + i)->cfg, key, val );
        (conf + i)->altered = true;
    }
}

int set_entry   (int n, int argc, char **argv, image_cfg *cfg, size_t l);
int get_entry   (int n, int argc, char **argv, image_cfg *cfg, size_t l);
int del_entry   (int n, int argc, char **argv, image_cfg *cfg, size_t l);

int show_help   (opt int n,
                 opt int argc,
                 opt char **argv,
                 opt image_cfg *cfg,
                 opt size_t l);

int choose_image (int n,
                  int argc,
                  char **argv,
                  opt image_cfg *cfg,
                  opt size_t l);

int set_confdir (int n,
                 int argc,
                 char **argv,
                 opt image_cfg *cfg,
                 opt size_t l);

int set_efidir  (int n,
                 int argc,
                 char **argv,
                 opt image_cfg *cfg,
                 opt size_t l);

int set_verbose (opt int n,
                 opt int argc,
                 opt char **argv,
                 opt image_cfg *cfg,
                 opt size_t l);

int no_create (opt int n,
               opt int argc,
               opt char **argv,
               opt image_cfg *cfg,
               opt size_t l);

static arg_handler arg_handlers[] =
{
    { "-h"             , 0, show_help   , ARG_EARLY },
    { "--help"         , 0, show_help   , ARG_EARLY },
    { "--image"        , 1, choose_image, ARG_EARLY },
    { "--conf-dir"     , 1, set_confdir , ARG_EARLY },
    { "--efi-dir"      , 1, set_efidir  , ARG_EARLY },
    { "-v"             , 0, set_verbose , ARG_EARLY },
    { "--verbose"      , 0, set_verbose , ARG_EARLY },
    { "--no-create"    , 0, no_create   , ARG_EARLY },
    { "--set"          , 2, set_entry   , ARG_STD   },
    { "--get"          , 1, get_entry   , ARG_STD   },
    { "--del"          , 1, del_entry   , ARG_STD   },
    { NULL }
};

// ============================================================================
// preprocessors:
int show_ident  (image_cfg *cfg_array, size_t limit,
                 opt int argc, opt char **argv, opt uint params);
int dump_state  (image_cfg *cfg_array, size_t limit,
                 opt int argc, opt char **argv, opt uint params);
int list_images (image_cfg *cfg_array, size_t limit,
                 opt int argc, opt char **argv, opt uint params);
int next_ident  (image_cfg *cfg_array, size_t limit,
                 opt int argc, opt char **argv, opt uint params);
int set_target  (image_cfg *cfg_array, size_t limit,
                 opt int argc, opt char **argv, opt uint params);
int new_target  (image_cfg *cfg_array, size_t limit,
                 opt int argc, opt char **argv, opt uint params);
int set_mode    (image_cfg *cfg_array, size_t limit,
                 int argc, char **argv, uint params);

// postprocessors:
int save_updated_confs (image_cfg *cfg_array, size_t limit);

typedef enum
{
    CMD_NOT_CALLED = 0,
    CMD_PREPROCESSED,
    CMD_POSTPROCESSED,
    CMD_FAILED,
} cmd_status;

static cmd_handler cmd_handlers[] =
{
    { "selected-image", 0, next_ident , NULL, CMD_NOT_CALLED },
    { "dump-config"   , 0, dump_state , NULL, CMD_NOT_CALLED },
    { "this-image"    , 0, show_ident , NULL, CMD_NOT_CALLED },
    { "list-images"   , 0, list_images, NULL, CMD_NOT_CALLED },
    { "set-mode"      , 1, set_mode   , save_updated_confs, CMD_NOT_CALLED },
    { "config"        , 0, set_target , save_updated_confs, CMD_NOT_CALLED },
    { "create"        , 0, new_target , save_updated_confs, CMD_NOT_CALLED },
    { NULL }
};

// ============================================================================

opt
static int parse_uint_string (const char *str, uint64_t *num)
{
    char *nend;
    uint64_t nval = strtoul( str, &nend, 10 );

    if( num )
        *num = 0;

    if( nval  == ULONG_MAX ||
        errno == ERANGE    ||
        *nend != '\0'      ||
        str == nend        )
        return 0;

    if( num )
        *num = nval;

    return 1;
}

noreturn
static int error(int code, const char *msg, ...)
{
    if( msg )
    {
        va_list ap;
        va_start( ap, msg );
        vfprintf( stderr, msg, ap );
        fprintf ( stderr, "\n" );
        va_end( ap );
    }

    exit( code );
}

noreturn
static void usage (const char *msg, ...)
{
    if( msg )
    {
        va_list ap;
        va_start( ap, msg );
        vfprintf( stderr, msg, ap );
        fprintf ( stderr, "\n\n" );
        va_end( ap );
    }

    fprintf( stderr, "Usage: %s CMD [args...]\n", progname );
    fprintf( stderr, "\n\
  Commands:                                                                  \n\
    dump-config                                                              \n\
    selected-image                                                           \n\
    this-image                                                               \n\
    list-images                                                              \n\
    set-mode <update|update-other|shutdown|reboot|reboot-other|              \n\
              booted|first-boot>                                             \n\
    config [--no-create] [--set KEY VAL] [--del KEY] [--get KEY]             \n\
    create --image X [--set KEY VAL] ...                                     \n\
\n\
    selected-image prints the name of the image that the chainloader will    \n\
    choose during the next boot on stdout.                                   \n\
\n\
    this-image prints the name of the currently booted image on stdout.      \n\
\n\
    list-images printes the available image configs on stdout.               \n\
\n\
    create will initialise the specified config if it does not already exist.\n\
\n\
    set-mode combines the various config --set calls necessary to set up     \n\
    the specified reboot mode. You could achieve everything it does by       \n\
    issuing individual --set commands if you wanted to.                      \n\
\n\
    config modifies the selected (or currently booted) configuration as      \n\
    specified by the --set and --del arguments and/or prints the values      \n\
    requested by --get.                                                      \n\
\n\
  Arguments not related to commands:                                         \n\
    -v, --verbose : can be passed multiple times for increasing log levels   \n\
    --conf-dir    : specify a non-default conf dir (/esp/SteamOS/conf)       \n\
    --efi-dir     : specify a non-default EFI mount point (/efi)             \n\
    --image       : specify which config to operate on/read from             \n\
                    default: currently booted image                          \n\
    -h, --help    : print this message                                       \n\
\n\
  Arguments for the set-mode and config commands:                            \n\
    --set KEY VAL                                                            \n\
    --del KEY                                                                \n\
    --get KEY                                                                \n\
  These will set or delete a key from one image config (see --image) or      \n\
  print key: value pairs to stdout.                                          \n\
\n\
  If --set or --del cause the config to be altered the file will be updated  \n\
  atomically (by writing a tmpfile and renaming it).                         \n\
\n\
  Backwards compatibility:                                                   \n\
\n\
  If no command is found but there are non-command args then a default       \n\
  command of 'config' is assumed.                                            \n\
\n\
  If no command line args are present at all, a skeleton config with no      \n\
  values set is printed to stdout.                                           \n\
"
           );

    exit( msg ? -1 : 0 );
}

// =========================================================================
// arg handlers (of type arg_func, see above)
int show_help  (opt int n,
                opt int argc,
                opt char **argv,
                opt image_cfg *cfg,
                opt size_t l)
{
    usage( NULL );
    return 0;
}

int choose_image (int n,
                  int argc,
                  char **argv,
                  opt image_cfg *cfg,
                  opt size_t l)
{
    if( n + 1 >= argc )
        usage( "Error: %s requires an argument", argv[ n ] );

    strncpy( &target_ident[ 0 ], argv[ n + 1 ], sizeof(target_ident) );
    target_ident[ sizeof(target_ident) - 1 ] = 0;

    if( strlen( &target_ident[ 0 ] ) == 0 )
        usage( "Error: %s cannot specify an empty ident", argv[ n ] );

    for( char *c = (char *)&target_ident[ 0 ]; *c; c++ )
        if( !isalnum( *c ) )
            usage( "Error: %s non-alphanumeric character: %c #%02x",
                   argv[ n ], isprint( *c ) ? *c : '.', *c );

    return 1;
}

int set_confdir (int n,
                 int argc,
                 char **argv,
                 opt image_cfg *cfg,
                 opt size_t l)
{
    if( n + 1 >= argc )
        usage( "Error: %s requires an argument", argv[ n ] );

    confdir_path = strdup( argv[ n + 1 ] );
    TRACE( 2, "confdir '%s'", confdir_path );

    confdir = opendir( confdir_path );
    TRACE( 2, "confdir opened '%p'\n", confdir );

    if( confdir == NULL )
    {
        switch (errno)
        {
          case EACCES:
            usage( "Error: could not open config dir: '%s'", confdir_path );
          case ENOENT:
            usage( "Error: config dir not found: '%s'", confdir_path );
          case ENOTDIR:
            usage( "Error: path is not a directory: '%s'", confdir_path );
          default:
            usage( "Error: opening failed: '%s': %d", confdir_path, errno );
        }
    }

    return 1;
}

int set_efidir (int n,
                int argc,
                char **argv,
                opt image_cfg *cfg,
                opt size_t l)
{
    if( n + 1 >= argc )
        usage( "Error: %s requires an argument", argv[ n ] );

    efidir_path = strdup( argv[ n + 1 ] );
    TRACE( 2, "efidir '%s'", efidir_path );

    efidir = opendir( efidir_path );
    TRACE( 2, "efidir opened '%p'", efidir );

    if( efidir == NULL )
    {
        switch (errno)
        {
          case EACCES:
            usage( "Error: could not open efi dir: '%s'", efidir_path );
          case ENOENT:
            usage( "Error: efi dir not found: '%s'", efidir_path );
          case ENOTDIR:
            usage( "Error: path is not a directory: '%s'", efidir_path );
          default:
            usage( "Error: opening failed: '%s': %d", efidir_path, errno );
        }
    }

    return 1;
}

int set_verbose (opt int n,
                 opt int argc,
                 opt char **argv,
                 opt image_cfg *cfg,
                 opt size_t l)
{
    verbose++;

    return 0;
}

int no_create (opt int n,
               opt int argc,
               opt char **argv,
               opt image_cfg *cfg,
               opt size_t l)
{
    create_missing = 0;

    return 0;
}

int set_entry (int n, int argc, char **argv, image_cfg *cfg, opt size_t lim)
{
    image_cfg *tgt = NULL;

    if( n + 2 >= argc )
        usage( "Error: %s requires 2 arguments", argv[ n ] );

    const char *name  = argv[ n + 1 ];
    const char *value = argv[ n + 2 ];

     if( selected_image >= 0 &&
         selected_image < MAX_BOOTCONFS &&
         cfg[ selected_image ].loaded )
        tgt = &cfg[ selected_image ];
    else
        error( EINVAL, "No configuration selected, cannot get/set values" );

    const cfg_entry *c = get_conf_item( tgt->cfg, (unsigned char *)name );

    if( !c )
        error( ENOENT, "Error: no item '%s' in config '%s'",
               name, &tgt->ident[ 0 ] );

    unsigned long nval = 0;

    switch( c->type )
    {
      case cfg_uint:
      case cfg_bool:
      case cfg_stamp:
        if( !parse_uint_string( value, &nval ) )
            usage( "Error: suspicious number value '%s'", value );
        break;

      default:
        // noop, only need to parse out numeric types above
        nval = 0;
    }

    switch( c->type )
    {
      case cfg_uint:
      case cfg_bool:
        if( !set_conf_uint( c, name, nval ) )
            error( EINVAL, "Error: could not set %s to %lu", name, nval );
        tgt->altered = true;
        break;

      case cfg_stamp:
        if( !set_conf_stamp( c, name, nval ) )
            error( EINVAL, "Error: could not set %s to %lu", name, nval );
        tgt->altered = true;
        break;

      case cfg_string:
      case cfg_path:
        if( !set_conf_string( c, name, value ) )
            error( EINVAL, "Error: could not set %s to '%s'", name, value );
        tgt->altered = true;
        break;

      default:
        error( EINVAL, "Unsupported config type for %s (%s)",
               name, _cts( c->type ) );
    }

    return 1;
}

int get_entry (int n, int argc, char **argv, image_cfg *cfg, opt size_t lim)
{
    char buf[1024] = "";
    ssize_t out = 0;
    image_cfg *tgt = NULL;

    if( n + 1 >= argc )
        usage( "Error: %s requires 1 argument", argv[ n ] );

     if( selected_image >= 0 &&
         selected_image < MAX_BOOTCONFS &&
         cfg[ selected_image ].loaded )
        tgt = &cfg[ selected_image ];
    else
        error( EINVAL, "No configuration selected, cannot get/set values" );

    const char *name  = argv[ n + 1 ];
    const cfg_entry *c = get_conf_item( tgt->cfg, (unsigned char *)name );

    if( !c )
        usage( "Error: no such config item '%s'", name );

    out = snprint_item( buf, sizeof(buf), c );

    if( out >= (ssize_t)sizeof(buf) )
    {
        char *dbuf = calloc( 1, out + 1 );

        snprint_item( dbuf, out + 1, c );
        fputs( dbuf, stdout );

        free( dbuf );
    }
    else
    {
        fputs( buf, stdout );
    }

    return 1;
}

int del_entry (int n, int argc, char **argv, image_cfg *cfg, opt size_t lim)
{

    image_cfg *tgt = NULL;

    if( n + 1 >= argc )
        usage( "Error: %s requires 1 argument", argv[ n ] );

     if( selected_image >= 0 &&
         selected_image < MAX_BOOTCONFS &&
         cfg[ selected_image ].loaded )
        tgt = &cfg[ selected_image ];
    else
        error( EINVAL, "No configuration selected, cannot get/set values" );

    const char *name  = argv[ n + 1 ];

    if( del_conf_item( tgt->cfg, name ) )
        tgt->altered = true;

    return 1;
}

static int set_timestamped_note (cfg_entry *cfg, const char *note)
{
    char stamp[32];
    time_t tloc = 0;
    struct tm *now = NULL;
    const char *prefix = NULL;
    char *str = NULL;
    int rv;

    time( &tloc );
    now = localtime( &tloc );

    if( strftime( stamp, sizeof(stamp), "[%Y-%m-%d %T %z] ", now ) )
        prefix = stamp;
    else
        prefix = "[timestamp-error] ";

    str = calloc( strlen( prefix ) + strlen( note ) + 1, 1 );
    sprintf( str, "%s%s", prefix, note );
    rv = set_conf_string( cfg, "comment", str );
    free( str );

    return rv;
}

opt
static unsigned long timestamp_to_datestamp (unsigned long hhmm,
                                             unsigned long after)
{
    time_t tloc = 0;
    struct tm *now;
    unsigned long hhmm_now;
    unsigned long stamp;

    // when is an integer but it's actually an HHMM timestamp
    // we'd use time_t values and seconds but EFI doesn't have
    // decent time API so we have to calculate YYYYmmDDHHMMSS
    // style integer stamps like a 14th century peasant.
    if( hhmm >= 2359 )
        return hhmm;

    int mm = hhmm % 100;
    int hh = (hhmm - mm) / 100;

    time( &tloc );
    now = localtime( &tloc );
    hhmm_now = (now->tm_hour * 100) + now->tm_min;

    // easy case, the time requested, interpreted as a local time in the
    // current day, is later than the current local time:
    if( hhmm > hhmm_now )
    {
        now->tm_hour = hh;
        now->tm_min  = mm;
        now->tm_sec  = 0;
        stamp = structtm_to_stamp( now );
    }
    else
    {
        // jump to the next day:
        tloc += 86400;
        now = localtime( &tloc );
        now->tm_hour = hh;
        now->tm_min  = mm;
        now->tm_sec  = 0;
        stamp = structtm_to_stamp( now );
    }

    // if we must be fter a certain time but we aren't, jump another
    // 24 hours into the future:
    if( stamp < after )
    {
        tloc += 86400;
        now = localtime( &tloc );
        now->tm_hour = hh;
        now->tm_min  = mm;
        now->tm_sec  = 0;
    }

    tloc = mktime( now );
    now  = gmtime( &tloc );

    return structtm_to_stamp( now );
}

static void *mmap_path_at (DIR *efidir, const char *path, size_t *mapsize)
{
    int fd = -1;
    struct stat buf = {};
    char *data = NULL;
    size_t size = 0;
    int rc;

    *mapsize = 0;

    if( efidir )
    {
        int dfd = dirfd( efidir );

        fd = openat( dfd, path, O_RDONLY );
        if( fd < 0 )
            goto cleanup;
    }
    else
    {
        fd = open( path, O_RDONLY );
        if( fd < 0 )
            goto cleanup;
    }

    rc = fstat( fd, &buf );
    if( rc )
        goto cleanup;

    size = buf.st_size;
    data = mmap( NULL, size + 1, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0 );

    if( !data )
        goto cleanup;

    data[ size ] = (char)0;
    *mapsize = size + 1;

cleanup:
    if( fd >= 0 )
        close( fd );

    return data;
}

static void sync_unmap( void *addr, size_t length )
{
    msync( addr, length, MS_SYNC );
    munmap( addr, length );
}

static char *self_ident (image_cfg *cfg_array, size_t limit)
{
    size_t i = 0;
    image_cfg *conf = NULL;
    const char *self_partset = "SteamOS/partsets/self";
    unsigned char *self_data = NULL;
    size_t self_size = 0;
    const unsigned char *self_efi_uuid = NULL;
    char *this_image_ident = NULL;
    const unsigned char *ekey = (unsigned char *)"efi";

    self_data = mmap_path_at( efidir, self_partset, &self_size );
    if( !self_data )
        goto cleanup;

    self_efi_uuid = get_partset_value( self_data, self_size, ekey );
    if( !self_efi_uuid )
        goto cleanup;

    for( ; i < limit; i++ )
    {
        char path[PATH_MAX] = { 0 };
        unsigned char *x_data = NULL;
        size_t x_size = 0;

        conf = cfg_array + i;

        if( !conf || !conf->loaded )
            continue;

        snprintf( &path[0], PATH_MAX,
                  "SteamOS/partsets/%s", &conf->ident[0] );
        path[PATH_MAX - 1] = (char)0;

        x_data = mmap_path_at( efidir, &path[0], &x_size );

        if( x_data )
        {
            const unsigned char *x_efi_uuid =
              get_partset_value( x_data, x_size, ekey );

            if( strcmp( (const char *)self_efi_uuid,
                        (const char *)x_efi_uuid   ) == 0 )
                this_image_ident = strdup( &conf->ident[0] );

            sync_unmap( x_data, x_size );
        }
    }

cleanup:
    if( self_data )
    {
        sync_unmap( self_data, self_size );
    }
    else
        error( ENOENT, "partset '%s' not found in efi dir '%s'",
               self_partset, efidir_path ?: "" );

    return this_image_ident;
}

// ============================================================================
static int dump_cfg (image_cfg *conf)
{
    int i = 0;

    if( !conf )
        return 0;

    if( !conf->cfg )
        return 0;

    for( i = 0; conf && conf->cfg[ i ].type != cfg_end; i++ )
    {
        printf( "%s\t%s\t%s\n",
                &conf->ident[ 0 ],
                conf->cfg[ i ].name,
                (char *) conf->cfg[ i ].value.string.bytes ?: "-UNSET-" );
    }

    return CMD_PREPROCESSED;
}

int dump_state (image_cfg *cfg_array, size_t limit,
                opt int argc, opt char **argv, opt uint params)
{
    size_t i = 0;
    image_cfg *conf = NULL;
    int count = 0;

    for( ; i < limit; i++ )
    {
        conf = cfg_array + i;

        if( !conf || !conf->loaded )
            continue;

        // if a specifi config was asked for, skip the rest:
        if( target_ident[ 0 ] )
            if( strcmp( &target_ident[ 0 ], &conf->ident[0]) != 0 )
                continue;

        count += dump_cfg( conf );
    }

    if( !count && target_ident[ 0 ]  )
        error( ENOENT, "No config for '%s' found", &target_ident[ 0 ] );

    return CMD_PREPROCESSED;
}

int list_images (image_cfg *cfg_array, size_t limit,
                 opt int argc, opt char **argv, opt uint params)
{
    ssize_t i = 0;
    image_cfg *conf = NULL;

    TRACE( 3, "list_images %p %lu\n", cfg_array, limit );

    for( ; i < (ssize_t)limit; i++ )
    {
        conf = cfg_array + i;
        TRACE( 3, "config %p %s\n", conf, &conf->ident[0] );

        if( !conf || !conf->loaded )
            continue;

        printf( "%c %s %c\n",
                conf->disabled ? '-' : '+',
                &conf->ident[0],
                (i == selected_image) ? '*' :  ' ' );
    }

    return CMD_PREPROCESSED;;
}

// NOTE: preprocessors get a shifted argc/argv with the command at #0
int set_mode (image_cfg *cfg_array, size_t limit,
              int argc, char **argv, uint params)
{
    const char *action;
    unsigned long max = 0;
    unsigned long now = 0;
    unsigned long stamp = 0;
    cfg_entry *cfg = NULL;
    image_cfg *chosen = NULL;

    if( argc < 2 )
        usage( "Error: %s requires 1 argument", argv[ 0 ] );

    TRACE( 2, "set-mode - choosing target (user requested:'%s')\n",
           target_ident[0] ? &target_ident[0] : "-" );
    set_target( cfg_array, limit, argc, argv, params );

    if( selected_image < 0 || selected_image > (ssize_t)limit )
        error( EINVAL, "Selected config out of range 0 - %lu (%d)",
               limit, selected_image );

    chosen = cfg_array + selected_image;
    TRACE( 2, "set-mode - chose target #%d:'%s'\n",
           selected_image, &chosen->ident[ 0 ] );

    if( !chosen->loaded )
        error( EINVAL, "Invalid image %d selected (nothing loaded here)",
               selected_image );

    cfg = chosen->cfg;
    max = get_conf_uint_highest( cfg_array, "boot-requested-at", limit ) + 1;
    now = time_to_stamp( time( NULL ) );
    stamp = MAX( max, now );
    TRACE( 2, "MAX( %lu, %lu ) -> %lu", max, now, stamp );

    action = strdupa( argv[ 1 ] );
    // scrub the consumed argument:
    *argv[ 1 ] = '\0';

    // to update another partition we must NOT be booted into it, ie
    // we want to start with _this_ partition booted:
    if( strcmp( action, "update-other" ) == 0 )
    {
        // make sure this config selects itself for boot:
        set_conf_uint( cfg, "boot-other", 0 );

        // make sure it comes up in update mode:
        set_conf_uint( cfg, "update",     1 );

        // make this the config with the highest priority:
        set_conf_uint( cfg, "boot-requested-at", stamp );
        set_conf_uint( cfg, "image-invalid", 0 );

        set_timestamped_note( cfg, "bootconf mode: update (other)" );
        chosen->altered = true;
        return 1;
    }

    // similarly to update this partition we must boot into some other partition:
    if( strcmp( action, "update" ) == 0 )
    {
        // make this config ask for a different image to be booted:
        set_conf_uint( cfg, "boot-other", 1 );

        // make sure the next boot is in update mode:
        set_conf_uint( cfg, "update",     1 );

        // make this the config with the highest priority:
        set_conf_uint( cfg, "boot-requested-at", stamp );
        set_conf_uint( cfg, "image-invalid", 0 );

        // make sure no other configs have boot-other set, so that when we
        // boot the next highest priority image we don't bounce along the
        // boot order to the one after it:
        set_other_conf_uint( cfg_array, limit, selected_image, "boot-other", 0 );

        set_timestamped_note( cfg, "bootconf mode: update (self)" );
        chosen->altered = true;
        return 1;
    }

    if( strcmp( action, "shutdown" ) == 0 )
    {
        // when we get restarted, come back to this image:
        set_conf_uint( cfg, "boot-other", 0 );

        // don't come back in update mode:
        set_conf_uint( cfg, "update",     0 );

        set_timestamped_note( cfg, "bootconf mode: shutdown" );
        chosen->altered = true;
        return 1;
    }

    if( strcmp( action, "reboot" ) == 0 )
    {
        // make sure this conifg selects its own image:
        set_conf_uint( cfg, "boot-other", 0 );

        // don't come back in update mode:
        set_conf_uint( cfg, "update",     0 );
        set_other_conf_uint( cfg_array, limit, selected_image, "update", 0 );

        // this config should have the highest priority
        set_conf_uint( cfg, "boot-requested-at", stamp );
        set_conf_uint( cfg, "image-invalid", 0 );

        set_timestamped_note( cfg, "bootconf mode: reboot (self)" );
        chosen->altered = true;
        return 1;
    }

    if( strcmp( action, "reboot-other" ) == 0 )
    {
        // this config requests that the next highest prio image be booted instead
        set_conf_uint( cfg, "boot-other", 1 );

        // but no other images are set to bounce down the priority chain:
        set_other_conf_uint( cfg_array, limit, selected_image, "boot-other", 0 );

        // the next boot will NOT be in update mode:
        set_conf_uint( cfg, "update",     0 );
        set_other_conf_uint( cfg_array, limit, selected_image, "update", 0 );

        // this config has the highest priority
        set_conf_uint( cfg, "boot-requested-at", stamp );
        set_conf_uint( cfg, "image-invalid", 0 );

        set_timestamped_note( cfg, "bootconf mode: reboot (other)" );

        chosen->altered = true;
        return 1;
    }

    if( strcmp( action, "first-boot" ) == 0 )
    {
        // clear all the interesting flags and values on this image
        // and set it to the highest priority (as if it were being booted
        // for the first time):
        set_conf_uint( cfg, "image-invalid", 0 );
        set_conf_uint( cfg, "boot-other"   , 0 );
        set_conf_uint( cfg, "boot-attempts", 0 );
        set_conf_uint( cfg, "boot-count"   , 0 );
        set_conf_uint( cfg, "update"       , 0 );
        set_conf_uint( cfg, "boot-requested-at", stamp );
        set_timestamped_note( cfg, "bootconf mode: first-boot" );
        chosen->altered = true;
        return 1;
    }

    if( strcmp( action, "booted" ) == 0 )
    {
        uint64_t nth = get_conf_uint( cfg, "boot-count" );
        set_conf_uint( cfg, "invalid"      , 0 );
        set_conf_uint( cfg, "boot-attempts", 0 );
        set_conf_uint( cfg, "boot-count"   , nth + 1 );
        set_conf_stamp_time( cfg, "boot-time", time( NULL ) );
        set_timestamped_note( cfg, "bootconf mode: boot-ok" );
        chosen->altered = true;
        return 1;
    }

    usage( "Unknown --action value '%s'", action );
}

int set_target (image_cfg *cfg_array, size_t limit,
                opt int argc, opt char **argv, opt uint params)
{
    const char *id = NULL;

    if( target_ident[ 0 ] )
        id = &target_ident[ 0 ];
    else
        id = self_ident( cfg_array, limit );

    if( !id || !*id )
        error( EINVAL, "No image specified and current image not identifiable\n" );

    // Make sure we only pick existing targets.
    // (it's possible for a nonexistent target tro be selected here because
    // new_target needs to be able to create them)
    selected_image = -1;

    for( size_t i = 0; i < limit; i++ )
    {
        if( !cfg_array[ i ].loaded )
            continue;

        if( strcmp( &cfg_array[ i ].ident[ 0 ], id ) )
            continue;

        selected_image = i;
        break;
    }

    if( selected_image < 0 )
    {
        if( create_missing == 0 )
            error( ENOENT, "Image config for %s does not exist\n", id );

        new_target( cfg_array, limit, argc, argv, params );
    }

    return CMD_PREPROCESSED;
}

int new_target (image_cfg *cfg_array, size_t limit,
                opt int argc, opt char **argv, opt uint params)
{
    const char *id = NULL;
    int new_target = -1;

    if( target_ident[ 0 ] )
        id = &target_ident[ 0 ];
    else if( selected_image >= 0 && &cfg_array[ selected_image ].loaded )
        id = &cfg_array[ selected_image ].ident[ 0 ];

    if( !id || !*id )
        error( EINVAL, "No image specified\n" );

    for( size_t i = 0; i < limit; i++ )
    {
        if( !cfg_array[ i ].loaded )
            continue;

        if( strcmp( &cfg_array[ i ].ident[ 0 ], id ) )
            continue;

        new_target = i;
        break;
    }

    if( new_target >= 0 )
        error( EEXIST, "Config #%d for %s exists\n", selected_image, id );

    for( size_t i = 0; i < MAX_BOOTCONFS; i++ )
    {
        image_cfg *cfg = NULL;

        if( cfg_array[ i ].loaded )
            continue;

        cfg = &cfg_array[ i ];

        strncpy( &cfg->ident[ 0 ], id, sizeof( cfg->ident ) );
        cfg->ident[ sizeof(cfg->ident) - 1 ] = '\0';
        cfg->fd = -1;
        cfg->loaded = 1;
        cfg->altered = 1;
        cfg->disabled = 0;
        cfg->cfg = new_config();

        selected_image = i;
        break;
    }

    if( selected_image < 0 )
        error( ENOSPC, "Cannot add new config: Limit reached\n" );

    return CMD_PREPROCESSED;
}


int show_ident (image_cfg *cfg_array, size_t limit,
                opt int argc, opt char **argv, opt uint params)
{
    char *ident = self_ident( cfg_array, limit );

    if( ident )
    {
        printf( "%s\n", ident );
        free( ident );

        return 1;
    }

    return CMD_PREPROCESSED;
}

int next_ident (image_cfg *cfg_array, size_t limit,
                opt int argc, opt char **argv, opt uint params)
{
    if( !cfg_array )
        error( EINVAL, "No config data" );

    if( selected_image < 0 )
        error( EINVAL, "No valid image found out of %lu candidates", limit );

    if( selected_image >= (ssize_t)limit )
        error( EINVAL, "Selected image out of range %d/%lu",
               selected_image, limit );

    printf( "%s\n", &cfg_array[ selected_image ].ident[ 0 ] );

    return CMD_PREPROCESSED;
}

// ============================================================================
int save_updated_confs (image_cfg *cfg_array, opt size_t limit)
{
    size_t i = 0;
    image_cfg *conf = NULL;

    for( ; i < MAX_BOOTCONFS; i++ )
    {
        int e = 0;

        conf = cfg_array + i;

        if( !conf || !conf->loaded )
            continue;

        if( !conf->altered )
            continue;

        e = write_config( confdir, &conf->ident[0], conf->cfg );

        if( e < 0 )
            error( -e, "Save config '%s' failed", &conf->ident[ 0 ] );
    }

    return CMD_POSTPROCESSED;
}

static cmd_handler *preprocess_cmd (int argc,
                                    char **argv,
                                    image_cfg *cfg_array,
                                    size_t limit)
{
    cmd_handler *handler = NULL;

    for( int i = 1; i < argc; i++ )
    {
        char *command = argv[ i ];

        if( *command == '\0' )
            continue;

        TRACE( 3, "command? '%s'\n", command );
        for( handler = &cmd_handlers[ 0 ]; handler->cmd; handler++ )
        {
            if( strcmp( handler->cmd, command ) )
                continue;

            //  0  1 2   3        4  | argc = 5, i = 2, CMDPARAM @ argv + 3,
            // $0 -v CMD CMDPARAM ...
            // 0   1        2        | argc = 3
            // CMD CMDPARAM ...
            if( handler->preprocess )
                handler->status =
                  handler->preprocess( cfg_array, limit,
                                       argc - i, argv + i, handler->params );
            else
                handler->status = CMD_PREPROCESSED;

            // scrub the consumed value from the command line:
            *command = '\0';

            return handler;
        }
    }

    // default command is "config" to match the behaviour of the previous
    // version(s) of steamos-bootconf:
    for( handler = &cmd_handlers[ 0 ]; handler->cmd; handler++ )
    {
        if( strcmp( handler->cmd, "config" ) )
            continue;

        if( handler->preprocess )
            handler->status =
              handler->preprocess( cfg_array, limit,
                                   argc, argv, handler->params );
        return handler;
    }

    usage( "Unknown command or command not found" );
}

static cmd_handler *postprocess_cmd (cmd_handler *cmd,
                                     image_cfg *cfg_array,
                                     size_t limit)
{
    if( !cmd )
        return NULL;

    if( !cmd->postprocess )
    {
        cmd->status = CMD_POSTPROCESSED;
        return cmd;
    }

    cmd->status = cmd->postprocess( cfg_array, limit );

    return cmd;
}

// =========================================================================

static int process_early_cmdline_args (int x, int argc, char **argv, size_t lim)
{
    arg_handler *handler = NULL;

    for( handler = &arg_handlers[ 0 ]; handler->cmd; handler++ )
    {
        if( strcmp( handler->cmd, argv[ x ] ) == 0 )
        {
            if( handler->parse_phase == ARG_EARLY )
            {
                handler->function( x, argc, argv, NULL, lim );
                // scrub the values we've already consumed:
                for( uint n = 0; n <= handler->params; n++ )
                    *argv[ x + n ] = '\0';

                return handler->params;
            }
        }
    }

    return 0;
}

static int process_cmdline_arg (int x, int argc, char **argv,
                                image_cfg *cfg, size_t loaded)
{
    arg_handler *handler = NULL;

    for( handler = &arg_handlers[ 0 ]; handler->cmd; handler++ )
    {
        int rv = 0;

        if( strcmp( handler->cmd, argv[ x ] ) )
            continue;

        if( handler->function && (handler->parse_phase != ARG_EARLY) )
            rv = handler->function( x, argc, argv, cfg, loaded );

        if( rv < 0 )
            exit( EINVAL );

        if( rv >= 0 )
            for( int i = 0; i <= (int)handler->params && (x + i) < argc; i++ )
                *argv[ x + i ] = '\0';

        return handler->params;
    }

    error( EINVAL, "Unknown command line argument %s", argv[ x ] );
}
// ============================================================================

static int parse_config_fd (int cffile, cfg_entry **config)
{
    int res = 0;
    unsigned char *cfdata = NULL;
    size_t cfsize;
    struct stat buf = {};

    *config = new_config();
    if( !config )
        goto allocfail;

    res = fstat( cffile, &buf );
    if( res )
        goto cleanup;

    cfsize = buf.st_size;
    if( buf.st_size )
    {
        cfdata =
          mmap( NULL, cfsize, PROT_READ|PROT_WRITE, MAP_PRIVATE, cffile, 0 );
        if( !cfdata )
            goto allocfail;

        res = set_config_from_data( *config, cfdata, cfsize );
    }
    else
    {
        unsigned char dummy[] = "title: -\n";
        res = set_config_from_data( *config, &dummy[ 0 ], sizeof(dummy) );
    }

cleanup:
    if( cfdata )
        sync_unmap( cfdata, cfsize );
    return res;

allocfail:
    free( *config );
    *config = NULL;
    return ENOMEM;
}

static void free_image_configs (image_cfg *cfg_array, size_t limit)
{
    size_t i = 0;

    if( !cfg_array )
        return;

    for( i = 0; i < limit; i++ )
    {
        image_cfg *conf = cfg_array + i;

        TRACE( 3, "config#%lu '%s' %c %c\n", i,
               &conf->ident[ 0 ],
               conf->disabled ? '-' : '+',
               conf->loaded   ? 'Y' : 'n' );
        if( !conf->loaded )
            continue;

        if( conf->fd >= 0 )
        {
            TRACE( 3, "close %d\n", conf->fd );
            close( conf->fd );
            conf->fd = -1;
        }

        TRACE( 3, "freeing %p\n", conf->cfg );
        free_config( &conf->cfg );
        conf->cfg = NULL;
        conf->ident[0] = '\0';
        conf->loaded = 0;
        conf->altered = 0;
    }
}

#define COPY_CONFIG(src,dst) \
    ({ dst.disabled = src.disabled; \
       dst.loaded   = src.loaded;   \
       dst.at       = src.at;       \
       dst.cfg      = src.cfg;      \
       dst.fd       = src.fd;       \
       dst.altered  = src.altered;  \
       memcpy( &dst.ident[0], &src.ident[0], sizeof(dst.ident) ); })

static uint64_t swap_cfgs (image_cfg *conf, uint64_t a, uint64_t b)
{
    image_cfg c;

    COPY_CONFIG( conf[ a ], c      );
    COPY_CONFIG( conf[ b ], conf[ a ] );
    COPY_CONFIG( c        , conf[ b ] );

    return 1;
}

static bool earlier_entry_is_newer (image_cfg *a, image_cfg *b)
{
    // a disabled entry is always lower prio than a "good" one:
    if( a->disabled && !b->disabled )
        return false;

    if( !a->disabled && b->disabled )
        return true;

    // entries at same level of disabled-flag-ness:
    // pick the most recently boot-requested image.
    if( a->at > b->at )
        return true;

    return false;
}

static int load_image_configs (image_cfg *cfg_array, size_t limit)
{
    size_t loaded = 0;
    struct dirent *maybe_conf;

    if (!confdir)
        return 0;

    TRACE( 2, "rewinding conf dir %p\n", confdir );
    rewinddir( confdir );

    while( (maybe_conf = readdir( confdir )) && (loaded < limit) )
    {
        char *extn = NULL;
        image_cfg *conf = NULL;
        int dfd = -1;

        if( maybe_conf->d_name[0] == '.' )
            continue;

        extn = strrchr( &maybe_conf->d_name[0], '.' );

        if( !extn || strcasecmp( extn, ".conf" ) )
            continue;

        TRACE( 3, "config '%s'\n", &maybe_conf->d_name[ 0 ] );

        conf = cfg_array + loaded;
        dfd = dirfd( confdir );
        conf->fd = openat( dfd, &maybe_conf->d_name[ 0 ], O_RDONLY, 0 );

        if( conf->fd < 0 )
            continue;

        TRACE( 3, "opened conf fd %d\n", conf->fd );

        if( parse_config_fd( conf->fd, &conf->cfg ) == 0 )
        {
            char *dot = NULL;
            conf->disabled = get_conf_uint( conf->cfg, "image-invalid" ) > 0;
            conf->at       = get_conf_uint( conf->cfg, "boot-requested-at" );
            conf->loaded   = 1;
            conf->altered  = 0;
            strncpy( &conf->ident[0], &maybe_conf->d_name[0], sizeof(conf->ident) );
            dot = strrchr( &conf->ident[0], '.' );
            TRACE( 3, "parsed conf '%s' at %p\n", &conf->ident[0], conf->cfg );

            if( dot )
                *dot = '\0';

            loaded++;
        }
    }

    TRACE( 2, "sorting image configs by priority (lowest to highest)\n" );
    for( uint64_t sort_confs = loaded > 1 ? 1 : 0; sort_confs; )
        for( uint64_t i = sort_confs = 0; i < loaded - 1; i++ )
            if( earlier_entry_is_newer( &cfg_array[ i ], &cfg_array[ i + 1 ] ) )
                sort_confs += swap_cfgs( &cfg_array[ 0 ], i, i + 1 );

    return loaded;
}

// NOTE: this mirrors the logic in the chainloader. If you think this is
// wrong, FIX IT THERE FIRST. The implementations must match and the
// chainloader is canonical.
static int select_image_config (image_cfg *conf, size_t loaded)
{
    int selected = -1;
    bool update  = false;

    if( loaded == 0 )
        return -1;

    for( int i = (int) loaded - 1; i >= 0; i-- )
    {
        selected = i;

        if( target_ident[ 0 ] )
            if( strcmp( &target_ident[ 0 ], &conf[ i ].ident[ 0 ] ) != 0 )
                continue;

        TRACE( 1, "selected image is #%d (%s)\n", i, &conf[ i ].ident[ 0 ] );

        if( get_conf_uint( conf[i].cfg, "boot-other" ) )
        {
            TRACE( 1, "  boot-other is set, considering other images\n" );
            // NOTE: we don't implement the update-window logic from
            // the chainloader here as it is not currently in use.
            // if the chainloader update-window behaviour is resurrected,
            // an implementation will be required here:

            // if boot-other is set, update should persist until we get to
            // a non-boot-other entry:
            if( !update )
            {
                update = get_conf_uint( conf[ i ].cfg, "update" ) > 0;
                if( update )
                    TRACE( 1, "  update flag set from config\n" );
            }
            continue;
        }

        if( update && get_conf_uint( conf[ i ].cfg, "update-disabled" ) > 0 )
        {
            TRACE( 1, "  update requested, but this image does not allow it\n" );
            continue;
        }

        break;
    }

    if( target_ident[ 0 ] && selected == -1 )
        error( ENOENT, "No image matching '%s' found", &target_ident[ 0 ] );

    if( selected >= 0 )
        TRACE( 1, "selected image #%d '%s' (update: %c)\n",
               selected, &conf[ selected ].ident[ 0 ], update ? 'Y' : 'n' );
    else
        TRACE( 1, "no image selected out of %lu available\n", loaded );

    return selected;
}

// ============================================================================

void print_skeleton ()
{
    cfg_entry *blank = new_config();

    write_config( NULL, NULL, blank );

    free( blank );
}

// ============================================================================
void exit_handler (void)
{
    if( confdir )
    {
        closedir( confdir );
        confdir = NULL;
    }

    if( efidir )
    {
        closedir( efidir );
        efidir = NULL;
    }

    free( confdir_path );
    confdir_path = NULL;

    free( efidir_path );
    efidir_path = NULL;

    free_image_configs( &found[0], MAX_BOOTCONFS );
}

int main (int argc, char **argv)
{
    const size_t limit = sizeof(found) / sizeof(image_cfg);
    size_t loaded = 0;
    cmd_handler *cmd = NULL;

    atexit( exit_handler );

    progname = argv[ 0 ];

    // handle cmdline args (like --conf-dir) that need to be processed
    // before the command:
    TRACE( 2, "processing early command line args\n" );
    for( int c = 1; c < argc; c++ )
        c += process_early_cmdline_args( c, argc, argv, limit );

    if( !confdir )
    {
        TRACE( 2, "opening default confdir\n" );
        confdir_path = strdup( "/esp/SteamOS/conf" );
        confdir = opendir( confdir_path );
    }

    if( !efidir )
    {
        TRACE( 2, "opening default efidir\n" );
        efidir_path = strdup( "/efi" );
        efidir = opendir( efidir_path );
    }

    // load all available config files:
    TRACE( 2, "loading boot configurations\n" );
    loaded = load_image_configs( &found[0], limit );
    selected_image = select_image_config( &found[0], loaded );

    if( argc >= 2 )
    {
        cmd = preprocess_cmd( argc, argv, &found[0], loaded );

        if( cmd )
            TRACE( 2, "command found: %s %p\n", cmd->cmd, cmd );
    }

    if( !cmd )
    {
        // this was the old no-args-at-all behaviour of steamos-bootconf
        print_skeleton();
    }
    else if( cmd->postprocess ) // no postprocess => don't parse remaining args
    {
        for( int c = 1 + cmd->params; c < argc; c++ )
            if( *argv[ c ] != '\0' )
            {
                c += process_cmdline_arg( c, argc, argv, &found[0], loaded );
            }

        // remaining args have had their effect, call the postprocess function:
        TRACE( 2, "postprocessing command %s\n", cmd->cmd );
        postprocess_cmd( cmd, &found[0], loaded );
    }

    return 0;
}
