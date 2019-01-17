#include "err.h"

UINTN verbose;

UINTN set_verbosity (UINTN level)
{
    UINTN old_level = verbose;

    verbose = level;

    return old_level;
}
