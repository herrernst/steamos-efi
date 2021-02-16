AC_DEFUN([cc_has_PIE],
         [AC_MSG_CHECKING([whether `$CC' has `-fPIE' by default])
         AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#ifndef __PIE__
#error NO PIE
#endif
                                            ]], [[]])],
                           [AC_MSG_RESULT([yes])
                            [cv_cc_has_pie=yes]],
                           [AC_MSG_RESULT([no])
                            [cv_cc_has_pie=no]])
        ])


AC_DEFUN([link_disable_PIE],
         [[cv_link_disable_pie=no]
          AC_MSG_CHECKING([whether linker `$CC' needs PIE disabled])
          [save_CFLAGS="$CFLAGS"]
          [CFLAGS="-Wl,-r,-d -nostdlib -Werror"]
          AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[]])],
                            [AC_MSG_RESULT([no])
                             [cv_link_disable_pie=no]],
                            [AC_MSG_RESULT([yes])
                             [cv_link_disable_pie=yes]])
          [CFLAGS="$save_CFLAGS"]
         ])

AC_DEFUN([link_understands_NO_PIE],
         [[cv_link_understands_no_pie=no]
          AC_MSG_CHECKING([whether linker `$CC' understands -no-pie])
          [save_LDFLAGS="$LDFLAGS"]
          [LDFLAGS="$LDFLAGS -no-pie -nostdlib -Werror"]
          AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[]])],
                         [AC_MSG_RESULT([yes])
                          [cv_link_understands_no_pie=yes]],
                         [AC_MSG_RESULT([no])
                          [cv_link_understands_no_pie=no]])
          [LDFLAGS="$save_LDFLAGS"]
         ])

AC_DEFUN([link_understands_NOPIE],
         [[cv_link_understands_nopie=no]
          AC_MSG_CHECKING([whether linker `$CC' understands -nopie])
          [save_LDFLAGS="$LDFLAGS"]
          [LDFLAGS="$LDFLAGS -nopie -nostdlib -Werror"]
          AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[]])],
                         [AC_MSG_RESULT([yes])
                          [cv_link_understands_nopie=yes]],
                         [AC_MSG_RESULT([no])
                          [cv_link_understands_nopie=no]])
          [LDFLAGS="$save_LDFLAGS"]
         ])
