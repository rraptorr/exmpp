dnl
dnl Configure path for GnuTLS
dnl

dnl EXMPP_GNUTLS([ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]])
dnl Substitutes
dnl   GNUTLS_CPPFLAGS
dnl   GNUTLS_LDFLAGS
dnl   GNUTLS_LIBS
AC_DEFUN([EXMPP_GNUTLS],
[
  AC_ARG_WITH(gnutls,
    AC_HELP_STRING([--with-gnutls=PREFIX],
      [prefix where GnuTLS is installed (optional)]),
    gnutls_prefix="$withval",)

  no_gnutls=""
  GNUTLS_CPPFLAGS=""
  GNUTLS_LDFLAGS=""
  GNUTLS_LIBS="-lgnutls"

  if test x"${gnutls_prefix:+set}" = "xset"; then
    GNUTLS_CPPFLAGS="-I${gnutls_prefix%%\/}/include ${GNUTLS_CPPFLAGS}"
    GNUTLS_LDFLAGS="-L${gnutls_prefix%%\/}/lib ${GNUTLS_LDFLAGS}"
  fi

  ac_save_CPPFLAGS="$CPPFLAGS"
  ac_save_LDFLAGS="$LDFLAGS"
  ac_save_LIBS="$LIBS"
  CPPFLAGS="$CPPFLAGS $GNUTLS_CPPFLAGS"
  LDFLAGS="$LDFLAGS $GNUTLS_LDFLAGS"

  AC_CHECK_HEADERS(gnutls/gnutls.h,, no_gnutls="yes",)

  AC_CHECK_LIB(gnutls, gnutls_init,, no_gnutls="yes")

  CPPFLAGS="$ac_save_CPPFLAGS"
  LDFLAGS="$ac_save_LDFLAGS"
  LIBS="$ac_save_LIBS"

  AC_MSG_CHECKING([for GnuTLS library])
  if test x"$no_gnutls" = "x"; then
    AC_MSG_RESULT([yes])
    ifelse([$1], , :, [$1])
  else
    AC_MSG_RESULT([no])
    ifelse([$2], , :, [$2])

    GNUTLS_CPPFLAGS=""
    GNUTLS_LDFLAGS=""
    GNUTLS_LIBS=""
  fi

  AC_SUBST(GNUTLS_CPPFLAGS)
  AC_SUBST(GNUTLS_LDFLAGS)
  AC_SUBST(GNUTLS_LIBS)
])
