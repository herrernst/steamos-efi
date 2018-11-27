# Copyright © 2018 Collabora Ltd

# This file is part of steamos-efi.

# steamos-efi is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of the
# License, or (at your option) any later version.

# steamos-efi is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public
# License along with steamos-efi.  If not, see <http://www.gnu.org/licenses/>.

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

pkglibexec_PROGRAMS = steamcl.efi
noinst_bin_PROGRAMS = steamcl.elf
noinst_bindir       = elf

# we need a non-standard step here to turn the elf output of the normal-ish
# link stage into a PE32 blob:
%.efi$(EXEEXT): %.elf
	$(AM_V_OC)$(TARGET_OBJCOPY) $(EFI_OBJCOPYARGS) $< $@

# this prevents automake from trying to build steamcl.efi as a normal binary
steamcl.efi$(EXEEXT): steamcl.elf

# this builds an ELF DSO with the right charactteristics to be turned into
# an EFI blob in the final stage.
# We can't just subvert the link stage to do this because of the way the link
# command is contructed (I think)
steamcl_elf_SOURCES  = chainloader/hello.c
steamcl_elf_CFLAGS   = $(CFLAGS) $(EFI_CFLAGS)
steamcl_elf_CFLAGS  += -I${EFI_INC} -I${EFI_INC}/${build_cpu}
steamcl_elf_LDFLAGS  = $(LDFLAGS) $(EFI_LDFLAGS) 
steamcl_elf_LDADD    = $(EFI_EXTRALIBS)
steamcl_elf_LINK     = $(LD) $(steamcl_elf_LDFLAGS) -o $@

