AC_INIT([tls-scan], [1.4.1], [])
AC_CONFIG_AUX_DIR([.])
AM_INIT_AUTOMAKE([-Wall -Werror foreign -Wno-portability])
AC_PROG_CC
AC_CONFIG_FILES([Makefile])
AC_CANONICAL_HOST
case "$host_os" in
        darwin*)
            darwin=true
        ;;
        linux*)
            linux=true
        ;;
esac

AM_CONDITIONAL([LINUX], [test x$linux = xtrue])
AM_CONDITIONAL([DARWIN], [test x$darwin = xtrue])
AC_OUTPUT

