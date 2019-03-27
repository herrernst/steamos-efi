#include "efi.h"
#include <stdarg.h>

int Print (const char16_t *f, ...)
{
    char *fmt = NULL;
    char16_t *wfmt;
    size_t s = 0;
    va_list ap;

    for (wfmt = (char16_t *)f; wfmt && *wfmt; wfmt++, s++);
    fmt = calloc( s+1, 1 );
    s = 0;

    for (wfmt = (char16_t *)f; wfmt && *wfmt; wfmt++, s++)
        *(fmt + s) = (char)(0xff & *wfmt);

    va_start(ap, f);
    int rv = vprintf( fmt,  ap );
    va_end(ap);

    free( fmt );
    return rv;
}
