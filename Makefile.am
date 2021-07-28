# SPDX-License-Identifier: GPL-2.0+
# This file is part of steamos-efi.

# Copyright © 2018,2019 Collabora Ltd
# Copyright © 2018,2019 Valve Corporation
# Copyright © 2018,2019 Vivek Das Mohapatra <vivek@etla.org>

# steamos-efi is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2.0 of the License, or
# (at your option) any later version.

# steamos-efi is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with steamos-efi.  If not, see <http://www.gnu.org/licenses/>.

AUTOMAKE_OPTIONS = subdir-objects

############################################################################
# cosmetic settings to make the objcopy output tidy when using silent rules
am__v_OC_   = $(am__v_OC_$(AM_DEFAULT_VERBOSITY))
am__v_OC_0  = @echo "  OBJCOPY " $@;
am__v_OC_1  = 
AM_V_OC     = $(am__v_OC_$(V))
############################################################################

############################################################################
# since efi builds are always cross-compiling, more or less:
AM_CFLAGS    	 = $(HOST_CFLAGS)
AM_LDFLAGS   	 = $(HOST_LDFLAGS)
AM_CPPFLAGS  	 = $(HOST_CPPFLAGS) $(CPPFLAGS_DEFAULT)
AM_CCASFLAGS 	 = $(HOST_CCASFLAGS) $(CCASFLAGS_DEFAULT)
############################################################################

ACLOCAL_AMFLAGS  = -I m4

bin_PROGRAMS        = steamos-bootconf
pkglibexec_PROGRAMS = steamcl.efi
noinst_PROGRAMS     = steamcl.elf
if ENABLE_BASH_COMPLETION
bashcompletiondir   = $(BASH_COMPLETION_DIR)
dist_bashcompletion_DATA = bash-completion/steamcl-install \
                           bash-completion/steamos-bootconf
endif
dist_pkgdata_DATA   = data/steamcl.version
dist_sbin_SCRIPTS   = util/steamcl-install
CLEANFILES          = data/steamcl.version

# we need a non-standard step here to turn the elf output of the normal-ish
# link stage into a PE32 blob:
%.efi$(EXEEXT): %.elf
	$(AM_V_OC)$(TARGET_OBJCOPY) $(EFI_OBJCOPYARGS) $< $@

# this prevents automake from trying to build steamcl.efi as a normal binary
steamcl.efi$(EXEEXT): steamcl.elf

# the checksum/version file:
data/steamcl.version: steamcl.efi Makefile
	@SUM=$$(sha256sum $<) && echo -n $${SUM%% *} > $@;
	@echo " @RELEASE_VERSION@" >> $@;

steamcl_efi_SOURCES = steamcl.elf

# this builds an ELF DSO with the right characteristics to be turned into
# an EFI blob in the final stage.
# We can't just subvert the link stage to do this because of the way the link
# command is contructed (I think)
steamcl_elf_SOURCES  = chainloader/chainloader.c \
                       chainloader/fileio.c \
                       chainloader/util.c \
                       chainloader/exec.c \
                       chainloader/config.c \
                       chainloader/err.c \
                       chainloader/bootload.c \
                       chainloader/variable.c \
                       chainloader/console.c
steamcl_elf_CFLAGS   = $(CFLAGS) $(EFI_CFLAGS) -DRELEASE_VERSION="\"$(RELEASE_VERSION)\""
steamcl_elf_CFLAGS  += -I${EFI_INC} -I${EFI_INC}/${build_cpu}
steamcl_elf_LDFLAGS  = $(LDFLAGS) $(EFI_LDFLAGS) 
steamcl_elf_LDADD    = $(EFI_EXTRALIBS)
steamcl_elf_LINK     = $(LD) $(steamcl_elf_LDFLAGS) -o $@

steamos_bootconf_SOURCES = bootconf/bootconf.c     \
                           bootconf/config-extra.c \
                           bootconf/efi.c          \
                           chainloader/config.c
steamos_bootconf_CFLAGS  = $(CFLAGS) -DNO_EFI_TYPES -fshort-wchar -g
steamos_bootconf_LDFLAGS = $(LDFLAGS)


