AC_INIT([tls-scan], m4_esyscmd([grep -m 1  Version CHANGELOG | awk '{print $2}' | tr -d '\n']), [])
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

case "$host_cpu" in
        aarch64)
            arm64=true
        ;;
        x86_64)
            amd64=true
        ;;
        arm)
            arm64=true
        ;;
esac

AM_CONDITIONAL([LINUX_ARM64], [test x$linux$arm64 = xtruetrue])
AM_CONDITIONAL([LINUX_AMD64], [test x$linux$amd64 = xtruetrue])
AM_CONDITIONAL([DARWIN_AMD64], [test x$darwin = xtrue])
AC_OUTPUT

