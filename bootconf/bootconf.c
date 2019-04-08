#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdarg.h>
#include <limits.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>

#include "bootconf.h"
#include <chainloader/config.h>
#include "config-extra.h"

#define DEFAULT_OUTPUT     -3
#define OVERWRITE_INPUT    -2
#define NO_BOOTCONF_OUTPUT -1

typedef int (*handler) (int n, int max, char **argv, cfg_entry *cfg);

typedef struct
{
    const char *cmd;
    uint params;
    handler function;
} arg_handler;

UINTN verbose = 0;
int output_fd;
static const char *progname;
static const char *input_file;
static int file_arg;

static int set_entry   (int n, int argc, char **argv, cfg_entry *cfg);
static int get_entry   (int n, int argc, char **argv, cfg_entry *cfg);
static int del_entry   (int n, int argc, char **argv, cfg_entry *cfg);
static int set_output  (int n, int argc, char **argv, cfg_entry *cfg);
static int set_mode    (int n, int argc, char **argv, cfg_entry *cfg);
static int set_window  (int n, int argc, char **argv, cfg_entry *cfg);
static int show_help   (unused int n,
                        unused int argc,
                        unused char **argv,
                        unused cfg_entry *cfg);

static arg_handler arg_handlers[] =
{
    { "--help"         , 0, show_help   },
    { "--set"          , 2, set_entry   },
    { "--get"          , 1, get_entry   },
    { "--del"          , 1, del_entry   },
    { "--output-to"    , 1, set_output  },
    { "--mode"         , 1, set_mode    },
    { "--update-window", 2, set_window  },
    { NULL }
};

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
    cfdata = mmap( NULL, cfsize, PROT_READ|PROT_WRITE, MAP_PRIVATE, cffile, 0 );
    if( !cfdata )
        goto allocfail;

    res = set_config_from_data( *config, cfdata, cfsize );

cleanup:
    if( cfdata )
        munmap( cfdata, cfsize );
    return res;

allocfail:
    free( *config );
    *config = NULL;
    return ENOMEM;
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

static int usage (const char *msg, ...)
{
    if( msg )
    {
        va_list ap;
        va_start( ap, msg );
        vfprintf( stderr, msg, ap );
        fprintf ( stderr, "\n\n" );
        va_end( ap );
    }

    fprintf( stderr, "Usage: %s /path/to/bootconf [cmds...]\n", progname );
    fprintf( stderr, "\n\
  Commands:                                                                  \n\
    --set <param> <value>                                                    \n\
    --get <param>                                                            \n\
    --del <param>                                                            \n\
    --mode <update|update-other|shutdown|reboot|reboot-other|booted>         \n\
    --update-window <0|START> <0|END>                                        \n\
    --output-to <stdout|nowhere|input>                                       \n\
                                                                             \n\
If an error occurs before final output, the bootconf file will not be        \n\
rewritten. It is still possible that an errorduring the writing of said file \n\
could leave it in an inconsistent state.                                     \n\
                                                                             \n\
START and END may be:                                                        \n\
  20380119031407 style UTC datestamps (yyyymmddHHMMSS)                       \n\
                                                                             \n\
  HHMM style *LOCAL* time specifications.                                    \n\
  An HHMM value will be mapped to the next UTC time which corresponds to     \n\
  a time of HH:MM in the local timezone.                                     \n\
  END will always be after START.                                            \n\
  Example:                                                                   \n\
  At 2019-03-27 12:19:29 US/Pacific, --update-window 0200 0100               \n\
  becomes: 20190328090000 to 20190329080000                                  \n\
                                                                             \n\
  0 means \"don't care\" and is distinct from 0000                           \n\
                                                                             \n\
--output-to determines where the [modified] bootconf file will be written:   \n\
  stdout - to standard output                                                \n\
  none   - not emitted (useful if you are using --get)                       \n\
  input  - the input path will be overwritten with the modified data         \n\
  NOTE: this does not affect putput from --get commands and similar - only   \n\
  the destination of the full modified bootconf data.\n"
           );

    return msg ? -1 : 0;
}

// =========================================================================
// arg handlers (of type handler, see above)

static int show_help   (unused int n,
                        unused int argc,
                        unused char **argv,
                        unused cfg_entry *cfg)
{
    usage( NULL );
    return -1;
}

static int set_entry (int n, int argc, char **argv, cfg_entry *cfg)
{
    if( n + 2 >= argc )
        return usage( "Error: %s requires 2 arguments", argv[n] );

    const char *name  = argv[ n + 1 ];
    const char *value = argv[ n + 2 ];

    const cfg_entry *c = get_conf_item( cfg, (unsigned char *)name );

    if( !c )
        return usage( "Error: no such config item '%s'", name );

    unsigned long nval = 0;

    switch( c->type )
    {
      case cfg_uint:
      case cfg_bool:
      case cfg_stamp:
        if( !parse_uint_string( value, &nval ) )
            return usage( "Error: suspicious number value '%s'", value );
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
        break;

      case cfg_stamp:
        if( !set_conf_stamp( c, name, nval ) )
            error( EINVAL, "Error: could not set %s to %lu", name, nval );
        break;

      case cfg_string:
      case cfg_path:
        if( !set_conf_string( c, name, value ) )
            error( EINVAL, "Error: could not set %s to '%s'", name, value );
        break;

      default:
        error( EINVAL, "Unsupported config type for %s (%s)",
               name, _cts( c->type ) );
    }

    return 1;
}

static int get_entry (int n, int argc, char **argv, cfg_entry *cfg)
{
    char buf[1024] = "";
    ssize_t out = 0;

    if( n + 1 >= argc )
        return usage( "Error: %s requires 1 argument", argv[n] );

    const char *name  = argv[ n + 1 ];
    const cfg_entry *c = get_conf_item( cfg, (unsigned char *)name );

    if( !c )
        return usage( "Error: no such config item '%s'", name );

    out = snprint_item( buf, sizeof(buf), c );

    if( out >= (ssize_t) sizeof(buf) )
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

static int del_entry (int n, int argc, char **argv, cfg_entry *cfg)
{
    if( n + 1 >= argc )
        return usage( "Error: %s requires 1 argument", argv[n] );

    const char *name  = argv[ n + 1 ];

    del_conf_item( cfg, name );

    return 1;
}


static int set_output (int n, int argc, char **argv, unused cfg_entry *cfg)
{
    if( n + 1 >= argc )
        return usage( "Error: %s requires 1 argument", argv[ n ] );

    const char *where = argv[ n + 1 ];

    if( strcmp( where, "stdout" ) == 0 )
        output_fd = DEFAULT_OUTPUT;
    else if( strcmp( where, "nowhere" ) == 0 )
        output_fd = NO_BOOTCONF_OUTPUT;
    else if( strcmp( where, "input" ) == 0 )
        output_fd = OVERWRITE_INPUT;
    else
        return usage( "Unknown --output-to value '%s'", where );

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

static int set_mode (int n, int argc, char **argv, cfg_entry *cfg)
{
    if( n + 1 >= argc )
        return usage( "Error: %s requires 1 argument", argv[ n ] );

    const char *action = argv[ n + 1 ];

    // to update the _other_ partition we must boot this one:
    if( strcmp( action, "update-other" ) == 0 )
    {
        set_conf_uint( cfg, "boot-other", 0 );
        set_conf_uint( cfg, "update",     1 );
        set_conf_stamp_time( cfg, "boot-requested-at", time(NULL) );
        set_timestamped_note( cfg, "bootconf mode: update (other)" );
        return 1;
    }

    // similarly to update this partition we must boot the other one:
    if( strcmp( action, "update") == 0 )
    {
        set_conf_uint( cfg, "boot-other", 1 );
        set_conf_uint( cfg, "update",     1 );
        set_conf_stamp_time( cfg, "boot-requested-at", time(NULL) );
        set_timestamped_note( cfg, "bootconf mode: update (self)" );
        return 1;
    }

    if( strcmp( action, "shutdown") == 0 )
    {
        set_conf_uint( cfg, "boot-other", 0 );
        set_conf_uint( cfg, "update",     0 );
        set_timestamped_note( cfg, "bootconf mode: shutdown" );
        return 1;
    }

    if( strcmp( action, "reboot") == 0 )
    {
        set_conf_uint( cfg, "boot-other", 0 );
        set_conf_uint( cfg, "update",     0 );
        set_conf_stamp_time( cfg, "boot-requested-at", time(NULL) );
        set_timestamped_note( cfg, "bootconf mode: reboot (self)" );
        return 1;
    }

    if( strcmp( action, "reboot-other") == 0 )
    {
        set_conf_uint( cfg, "boot-other", 1 );
        set_conf_uint( cfg, "update",     0 );
        set_conf_stamp_time( cfg, "boot-requested-at", time(NULL) );
        set_timestamped_note( cfg, "bootconf mode: reboot (other)" );
        return 1;
    }

    if( strcmp( action, "booted") == 0 )
    {
        uint64_t nth = get_conf_uint( cfg, "boot-count" );
        set_conf_uint( cfg, "invalid"      , 0 );
        set_conf_uint( cfg, "boot-attempts", 0 );
        set_conf_uint( cfg, "boot-count"   , nth + 1 );
        set_conf_stamp_time( cfg, "boot-time", time(NULL) );
        set_timestamped_note( cfg, "bootconf mode: boot-ok" );
        return 1;
    }

    return usage( "Unknown --action value '%s'", action );
}

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

static int set_window (int n, int argc, char **argv, cfg_entry *cfg)
{
    if( n + 2 >= argc )
        return usage( "Error: %s requires 2 arguments", argv[n] );

    const char *beg = argv[ n + 1 ];
    const char *end = argv[ n + 2 ];

    unsigned long wbeg = 0;
    unsigned long wend = 0;

    if( !parse_uint_string( beg, &wbeg ) )
        return usage( "Suspicious START value for %s (%s)", argv[ n ], beg );

    if( !parse_uint_string( end, &wend ) )
        return usage( "Suspicious END value for %s (%s)", argv[ n ], end );

    if( !strcmp( beg, "0000") || ((wbeg > 0) && (wbeg < 2360)) )
        wbeg = timestamp_to_datestamp( wbeg, 0 );
    if( !strcmp( end, "0000") || ((wend > 0) && (wend < 2360)) )
        wend = timestamp_to_datestamp( wend, wbeg );

    if( !set_conf_uint( cfg, "update-window-start", wbeg ) ||
        !set_conf_uint( cfg, "update-window-end"  , wend ) )
        error( EINVAL, "Could not set update window (internal error?)" );

    return 1;
}

// =========================================================================

static int find_input_file (int x, char **argv)
{
    arg_handler *handler = NULL;

    for( handler = &arg_handlers[0]; handler->cmd; handler++ )
    {
        if( strcmp( handler->cmd, argv[x] ) )
            continue;

        return handler->params;
    }

    file_arg = x;
    input_file = argv[ x ];

    return 0;
}

static int process_cmdline_arg (int x, int argc, char **argv, cfg_entry *cfg)
{
    arg_handler *handler = NULL;

    if( x == file_arg )
        return 0;

    for( handler = &arg_handlers[0]; handler->cmd; handler++ )
    {
        int rv = 0;

        if( strcmp( handler->cmd, argv[x] ) )
            continue;

        if( handler->function )
            rv = handler->function( x, argc, argv, cfg );

        if( rv < 0 )
            exit( EINVAL );

        return handler->params;
    }

    error( EINVAL, "Unknown command line argument %s", argv[x] );
}

int main (int argc, char **argv)
{
    int cfg_fd = -1;
    cfg_entry *config = NULL;

    progname = argv[0];

    for( int c = 1; !input_file && (c < argc); c++ )
        c += find_input_file( c, argv );

    if( input_file )
    {
        cfg_fd = open( input_file, O_RDWR );

        if( cfg_fd < 0 )
        {
            int e = errno;
            perror( "Error" );
            error( e, "While looking for input file '%s'", argv[1] );
        }
    }

    parse_config_fd( cfg_fd, &config );

    for( int c = 1; c < argc; c++ )
        c += process_cmdline_arg( c, argc, argv, config );

    switch( output_fd )
    {
      case NO_BOOTCONF_OUTPUT:
        break;

      case OVERWRITE_INPUT:
        output_fd = cfg_fd;
        // not checking if the fd is seekable, can't see a way for
        // that to happen given opened it just above, and if you
        // used this on a fifo you get to keep the pieces:
        lseek( cfg_fd, SEEK_SET, 0 );
        break;

      default:
        output_fd = fileno( stdout );
    }

    if( output_fd != NO_BOOTCONF_OUTPUT )
    {
        size_t written = write_config( output_fd, config );

        // if we're overwriting our input it may end up shrinking:
        if( (output_fd == cfg_fd) && ftruncate( output_fd, written ) )
            perror( "Output file not truncated - may be the wrong size" );
    }

    free_config( &config );

    return 0;
}
