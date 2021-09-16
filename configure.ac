# -*- autoconf -*-

# Process this file with autoconf to produce a configure script.

# Copyright (C) 2002,2003,2004,2005,2006,2007,2008,2009,2010  Free Software Foundation, Inc.
# Copyright © 2018,2020 Collabora Ltd.
# Copyright © 2020 2020 Valve Corporation
# Copyright © 2018,2019 Vivek Das Mohapatra <vivek@etla.org>
#
# This configure.ac is free software; the author
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.

dnl This configure script is complicated, because steamos-efi needs to deal
dnl with three potentially different types:
dnl
dnl   build  -- the environment for building GRUB
dnl   host   -- the environment for running utilities
dnl   target -- the environment for running GRUB
dnl
dnl In addition, steamos-efi needs to deal with a platform specification
dnl which specifies the system running steamos-efi, such as firmware.
dnl This is necessary because the target type in autoconf does not
dnl describe such a system very well.
dnl
dnl The current strategy is to use variables with no prefix (such as
dnl CC, CFLAGS, etc.) for the host type, variables with prefix "BUILD_"
dnl (such as BUILD_CC, BUILD_CFLAGS, etc.) for the build type and variables
dnl with the prefix "TARGET_" (such as TARGET_CC, TARGET_CFLAGS, etc.) are
dnl used for the target type. See INSTALL for full list of variables.

AC_PREREQ([2.60])
AC_INIT([steamos-efi],[0.01],[vivek@collabora.com])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

# We don't want -g -O2 by default in CFLAGS
: ${CFLAGS=""}

# Checks for build, host and target systems.
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
save_program_prefix="${program_prefix}"
AC_CANONICAL_TARGET
program_prefix="${save_program_prefix}"

PKG_PROG_PKG_CONFIG

AM_INIT_AUTOMAKE([-Wno-portability foreign])
AM_SILENT_RULES([yes])

AC_ARG_PROGRAM

# Optimise for size by default, EFI doesn't have a lot of headroom:
AS_CASE([$TARGET_CFLAGS],
        [*-O?|*-O?\ *], [true],
        [TARGET_CFLAGS="$TARGET_CFLAGS -Os"])

# Default HOST_CPPFLAGS
HOST_CPPFLAGS="$HOST_CPPFLAGS -Wall -W"

AS_CASE([$target_cpu],
        [amd64],    [target_cpu=x86_64],
        [aarch64*], [target_cpu=arm64],
        [x86_64],   [true],
        [AC_MSG_ERROR([Unsupported CPU "$target_cpu"])])

# Specify the platform (such as firmware).
AC_ARG_WITH([platform],
            [AS_HELP_STRING([--with-platform=PLATFORM],
                            [select the host platform [[guessed]]])])

AC_ARG_WITH([efilib],
            [AS_HELP_STRING([--with-efilib=EFILIB],
                            [select the EFI library (gnu or tiano)])],
            [with_efilib=$with_efilib],
            [with_efilib=gnu])

# define a release version number to bake into the binary
# this is for the upgrade/install helper script to use:
AC_ARG_WITH([release-version],
            [AS_HELP_STRING([--with-release-version=VERSION-STRING],
                            [Version to bake into the EFI binary])],
            [AC_SUBST([RELEASE_VERSION],"$with_release_version")],
            [AC_SUBST([RELEASE_VERSION],"$VERSION")])

# Guess the platform if not specified.
# Explode if the default for the platform is not EFI
AS_IF([test x"$with_platform" = x],
      [AS_CASE([$target_cpu-$target_vendor],
               [i386-apple], [platform=efi],
               [x86_64-*],   [platform=efi],
               [ia64-*],     [platform=efi],
               [arm64-*],    [platform=efi],
               [AC_MSG_ERROR([unsupported CPU, use --with-platform: "$target_cpu"])])],
      [platform="$with_platform"])

# we're special casing this because the EFI binary is a different platform
# than the intermediate blob that autofoo actually knows how to build.
# directory name chosen by analogy with grub's packaging:
AC_ARG_WITH([pkglibexecdir],
            [AS_HELP_STRING([--with-pkglibexecdir=DIR],
                            [Override the pkglibexecdir location])],
            [pkglibexecdir=$with_pkglibexecdir],
            [pkglibexecdir=${prefix}/lib/$PACKAGE_NAME/$host_cpu-$platform])
AC_SUBST([pkglibexecdir])

AS_CASE(["$target_cpu"-"$platform"],
        [*-efi], [],
        [AC_MSG_ERROR([Selected CPU/platform "$target_cpu"-"$target_vendor" is not EFI])])

AS_CASE([$platform],
        [emu],[true],
        [AS_CASE([$target_cpu],
                 [i386],  [target_m32=1],
                 [x86_64],[target_m64=1])])

# This normalizes the names, and creates a new variable ("host_kernel")
# while at it, since the mapping is not always 1:1 (e.g. different OSes
# using the same kernel type).
AS_CASE([$host_os],
        [gnu*],                         [host_kernel=hurd],
        [linux*],                       [host_kernel=linux],
        [freebsd* | kfreebsd*-gnu],     [host_kernel=kfreebsd],
        [netbsd*],                      [host_kernel=netbsd],
        [solaris*],                     [host_kernel=illumos],
        [darwin*],                      [host_kernel=xnu],
        [cygwin | windows* | mingw32*], [host_kernel=windows])

AS_CASE([$host_os],
        [cygwin | windows* | mingw32*], [have_exec=n],
        [aros*],                        [have_exec=n],
        [have_exec=y])

AS_CASE([$platform],
        [efi], [machine_CPPFLAGS="$machine_CPPFLAGS -DGRUB_MACHINE_EFI=1"],
        [AC_MSG_ERROR([Platform "$platform" must currently be efi])])

AC_SUBST(TARGET_LINK_ADDR)
AC_SUBST(TARGET_DECOMPRESSOR_LINK_ADDR)
TARGET_CPPFLAGS="$TARGET_CPPFLAGS $machine_CPPFLAGS"
AC_SUBST(host_cpu)
AC_SUBST(host_os)
AC_SUBST(host_kernel)
AC_SUBST(target_cpu)
AC_SUBST(platform)

AC_PROG_INSTALL
AC_PROG_CC

AC_GNU_SOURCE
AC_SYS_LARGEFILE

# Identify characteristics of the host architecture.
unset ac_cv_c_bigendian
CPPFLAGS="$CPPFLAGS -D_FILE_OFFSET_BITS=64"
HOST_CPPFLAGS="$HOST_CPPFLAGS -D_FILE_OFFSET_BITS=64"
AC_C_BIGENDIAN
AC_CHECK_SIZEOF(void *)
AC_CHECK_SIZEOF(long)

AS_CASE([$host_os],
        [cygwin | windows* | mingw32*],
        [HOST_CPPFLAGS="$HOST_CPPFLAGS -DUNICODE=1 -D_WIN32_WINNT=0x0500"]
        [CPPFLAGS="$CPPFLAGS -DUNICODE=1 -D_WIN32_WINNT=0x0500"]
        [AC_CHECK_SIZEOF(TCHAR,,[#include <windows.h>])]
        )

AS_CASE([$host_os],
        [cygwin | windows* | mingw32* | aros*],[true]
        [AC_CHECK_SIZEOF(off_t)]
        [AS_IF([text x"$ac_cv_sizeof_off_t" = x8],[true],
               [AC_MSG_ERROR([Large file support must be enabled])])])

#
# Check for host and build compilers.
#
HOST_CC=$CC
AC_CHECK_PROGS(BUILD_CC, [gcc cc])
AS_IF([test -z "$BUILD_CC"],
      [AC_MSG_ERROR([Neither gcc nor cc found. Set BUILD_CC manually])])
BUILD_CPP="$BUILD_CC -E"
BUILD_LIBM=-lm;

AS_CASE([$build_os],
        [cygwin*|mingw32*|mingw64*], [BUILD_EXEEXT=.exe],
        [BUILD_EXEEXT=])
AC_SUBST([BUILD_EXEEXT])

WARN_FLAGS="-Wall -Wextra"
HOST_CFLAGS="$HOST_CFLAGS $WARN_FLAGS -Wcast-align"

AS_IF([test x"$target_alias" != x && test x"$host_alias" != x"$target_alias"],
      [tmp_ac_tool_prefix="$ac_tool_prefix"]
      [ac_tool_prefix="$target_alias"-]
      [AC_CHECK_TOOLS(TARGET_CC, [gcc cc],
                      [AC_MSG_ERROR([Neither gcc nor cc found. Set TARGET_CC])])]
      [AC_CHECK_TOOL(TARGET_OBJCOPY, objcopy)]
      [AC_CHECK_TOOL(TARGET_STRIP, strip)]
      [AC_CHECK_TOOL(TARGET_NM, nm)]
      [AC_CHECK_TOOL(TARGET_RANLIB, ranlib)]
      [ac_tool_prefix="$tmp_ac_tool_prefix"],
      [AS_IF([test x"$TARGET_CC" = x],[TARGET_CC="$CC"])]
      [AC_CHECK_TOOL(TARGET_OBJCOPY, objcopy)]
      [AC_CHECK_TOOL(TARGET_STRIP, strip)]
      [AC_CHECK_TOOL(TARGET_NM, nm)]
      [AC_CHECK_TOOL(TARGET_RANLIB, ranlib)]
      )

AC_SUBST(HOST_CC)
AC_SUBST(BUILD_CC)
AC_SUBST(BUILD_CFLAGS)
AC_SUBST(BUILD_CPPFLAGS)
AC_SUBST(BUILD_LDFLAGS)
AC_SUBST(TARGET_CC)
AC_SUBST(TARGET_CFLAGS)
AC_SUBST(TARGET_NM)
AC_SUBST(TARGET_RANLIB)
AC_SUBST(TARGET_STRIP)
AC_SUBST(TARGET_OBJCOPY)

AS_CASE([$target_cpu],[i386],
        [AS_CASE([$platform],
                 [emu],[true],
                 [TARGET_CFLAGS="$TARGET_CFLAGS -march=i386"])])

AS_IF([test x"$target_m32"x"$target_m63" = x1x1],
      [AC_MSG_ERROR([Target cannot be both 32 and 64 bit])])

AS_IF([test x"$target_m32" = x1],
      [TARGET_CFLAGS="$TARGET_CFLAGS -m32"]
      [TARGET_CCASFLAGS="$TARGET_CCASFLAGS -m32"]
      [TARGET_CPPFLAGS="$TARGET_CPPFLAGS -m32"]
      [TARGET_LDFLAGS="$TARGET_LDFLAGS -m32"]
      [TARGET_MODULE_FORMAT="elf32"])

AS_IF([test x"$target_m64" = x1],
      [TARGET_CFLAGS="$TARGET_CFLAGS -m64"]
      [TARGET_CCASFLAGS="$TARGET_CCASFLAGS -m64"]
      [TARGET_CPPFLAGS="$TARGET_CPPFLAGS -m64"]
      [TARGET_MODULE_FORMAT="elf64"])

# Some toolchains enable these features by default, but they need
# registers that aren't set up properly pre-OS start
AS_CASE([$platform-$target_cpu],
        [emu-*], [true]
        [*-i386|*-x86_64],
        [TARGET_CFLAGS="$TARGET_CFLAGS -mno-mmx -mno-sse -mno-sse2 -mno-sse3 -mno-3dnow"])

dnl May need to forcibly disable floating point here, see grub's configure.ac
dnl grub also disables a lot of fetures for space or not-crashing optimisations:
dnl include them here if needed.

CFLAGS="$TARGET_CFLAGS"
LDFLAGS="$TARGET_LDFLAGS"

AS_CASE([$target_cpu],[x86_64],
        [AC_CACHE_CHECK([whether -mcmodel=large works],[steamos_efi_cv_cc_mcmodel],
                        [TARGET_CFLAGS="$TARGET_CFLAGS -mcmodel=large"]
                        [AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[]])],
                                           [grub_cv_cc_mcmodel=yes],
                                           [grub_cv_cc_mcmodel=no])])]
        [AS_CASE([$steamos_efi_cv_cc_mcmodel],
                 [yes], [TARGET_CFLAGS="$TARGET_CFLAGS -mcmodel=large"])]
        )

AS_CASE(["$target_cpu"-"$platform"],[x86_64-efi],
        [AC_CACHE_CHECK([whether -mno-red-zone works],[steamos_efi_cv_cc_no_red_zone],
                       [TARGET_CFLAGS="$TARGET_CFLAGS -mno-red-zone"]
                       [AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[]])],
                                          [steamos_efi_cv_cc_no_red_zone=yes],
                                          [steamos_efi_cv_cc_no_red_zone=no])])]
        [AS_CASE([$steamos_efi_cv_cc_no_red_zone],
                 [no], [AC_MSG_ERROR([-mno-red-zone unsupported - update $CC])])]
        [TARGET_CFLAGS="$TARGET_CFLAGS -mno-red-zone"]
        )

AS_CASE([$with_efilib],
        [gnu],
        [EFI_INC=/usr/include/efi]
        [EFI_LIB=/usr/lib]
        [EFI_EXTRALIBS="-lefi -lgnuefi $($TARGET_CC -print-libgcc-file-name)"]
        [EFI_LDSCRIPT=${EFI_LIB}/elf_${target_cpu}_efi.lds]
        [EFI_CRTOBJS=${EFI_LIB}/crt0-efi-${target_cpu}.o]
        [EFI_LDFLAGS="-T ${EFI_LDSCRIPT} -shared -Bsymbolic -nostdlib"]
        [EFI_LDFLAGS="${EFI_LDFLAGS} -L${EFI_LIB} ${EFI_CRTOBJS}"]
        [EFI_CFLAGS="-fpic -I $EFI_INC -I${EFI_INC}/${target_cpu}"]
        [EFI_CFLAGS="$EFI_CFLAGS -I ${EFI_INC}/protocol"]
        [EFI_SECT="text sdata data dynamic dynsym rel rela rel.\* rel\* rela\*"],
        [tiano], [AC_MSG_ERROR(["tiano core efi is not supported yet"])],
        [AC_MSG_ERROR(["--with-efilib= value must be gnu or tiano"])])

for x in $EFI_SECT; do EFI_OBJCOPYARGS="$EFI_OBJCOPYARGS -j .$x"; done;
EFI_OBJCOPYARGS="$EFI_OBJCOPYARGS --target=$platform-app-$target_cpu";

AC_SUBST([EFI_INC])
AC_SUBST([EFI_LIB])
AC_SUBST([EFI_LDSCRIPT])
AC_SUBST([EFI_LDFLAGS])
AC_SUBST([EFI_CFLAGS])
AC_SUBST([EFI_EXTRALIBS])
AC_SUBST([EFI_SECT])
AC_SUBST([EFI_OBJCOPYARGS])

TARGET_LDFLAGS="$TARGET_LDFLAGS -no-pie -znocombreloc -zdefs"
TARGET_CFLAGS="$TARGET_CFLAGS -fno-PIE -fno-pie"
TARGET_CFLAGS="$TARGET_CFLAGS -fno-stack-protector"
TARGET_CFLAGS="$TARGET_CFLAGS -fno-strict-aliasing"
TARGET_CFLAGS="$TARGET_CFLAGS -fno-stack-protector"
TARGET_CFLAGS="$TARGET_CFLAGS -fshort-wchar"
TARGET_CPPFLAGS="$TARGET_CPPFLAGS -nostdinc -isystem"
TARGET_CPPFLAGS="$TARGET_CPPFLAGS $($TARGET_CC -print-file-name=include)"
TARGET_CPP="$TARGET_CC -E"
TARGET_CCAS=$TARGET_CC

CFLAGS="$TARGET_CFLAGS"
LDFLAGS="$TARGET_LDFLAGS"

AC_SUBST(HOST_CFLAGS)
AC_SUBST(HOST_LDFLAGS)
AC_SUBST(HOST_CPPFLAGS)
AC_SUBST(HOST_CCASFLAGS)

AC_ARG_WITH([bash-completion-dir],
            [AS_HELP_STRING([--with-bash-completion-dir[=PATH]],
                            [Install the bash auto-completion script in this directory. @<:@default=yes@:>@])],
            [with_bash_completion_dir=$withval],
            [with_bash_completion_dir=yes])

AS_IF([test x"$with_bash_completion_dir" = xyes],
      [PKG_CHECK_MODULES([BASH_COMPLETION], [bash-completion >= 2.0],
			 [BASH_COMPLETION_DIR="`pkg-config --variable=completionsdir bash-completion`"],
                         [BASH_COMPLETION_DIR="$datadir/bash-completion/completions"])],
      [BASH_COMPLETION_DIR="$with_bash_completion_dir"])

AC_SUBST([BASH_COMPLETION_DIR])
AM_CONDITIONAL([ENABLE_BASH_COMPLETION],[test "x$with_bash_completion_dir" != "xno"])

AC_CONFIG_FILES([Makefile util/steamcl-install])
AC_OUTPUT
