AC_INIT([tls-scan], [1.4.1], [bug-automake@gnu.org])
AC_CONFIG_AUX_DIR([.])
AM_INIT_AUTOMAKE([-Wall -Werror foreign -Wno-portability])
#AM_INIT_AUTOMAKE
AC_PROG_CC
AC_CONFIG_FILES([Makefile])
#ac_configure_args=" --static -64"
# Call hand's ./configure script recursively.
#AC_CONFIG_SUBDIRS([third-party/zlib])
#AC_CONFIG_SUBDIRS([third-party/openssl])
#AC_DISABLE_OPTION_CHECKING
#AC_CONFIG_SUBDIRS([third-party/zlib], [third-party/openssl])

AC_CANONICAL_HOST
case "$host_os" in
        darwin*)
            darwin=true
        ;;
        linux*)
            linux=true
        ;;
esac

echo  "===========> $host_os"
AM_CONDITIONAL([LINUX], [test x$linux = xtrue])
AM_CONDITIONAL([DARWIN], [test x$darwin = xtrue])

AC_OUTPUT

