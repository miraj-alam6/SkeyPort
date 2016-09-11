#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([skey], [2.0], [BUG-REPORT-ADDRESS])
#AC_CONFIG_SRCDIR([src])  Ask professor if I need this
AC_CONFIG_HEADERS([config.h])
#what's the difference between previous line and next in? Resolved: the next line is required for older versions. No longer needed.
#AM_CONFIG_HEADER([config.h])
AC_CANONICAL_TARGET
#AC_CANONICAL_HOST
#AC_CANONICAL_BUILD

AC_PROG_LIBTOOL

AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

#Check for endianness
AC_C_BIGENDIAN

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h sgtty.h shadow.h stdlib.h string.h sys/param.h sys/systeminfo.h sys/types.h sys/resource.h sys/stat.h sys/time.h sys/timeb.h termio.h termios.h unistd.h crypt.h stdio.h ctype.h errno.h pwd.h signal.h time.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gethostname getpass getspnam isascii memset strchr sysinfo getenv setenv])


#added a lot of the following from am-utils. Trying to get it to work
AC_PROG_CC
AC_PROG_CPP
AC_PROG_CC_C_O
AC_PROG_GCC_TRADITIONAL
AC_PROG_MAKE_SET
AC_ISC_POSIX
#AC_AIX this is obsolete I think, so I took it out. Was causing unncessary warnigns
 #I added this because of what terminal said to do, this is not how example did things however.

#more stuff trying to make subdirs work now

#moved these four above
#AC_PROG_INSTALL
#AC_CANONICAL_BUILD
#AC_CANONICAL_HOST
#AC_CANONICAL TARGET
#AMU_HOST_MACROS  command not found
#AMU_LINUX_HEADERS command not found
#end stuff here

#copied next four from am-utils. Seems important. especially ar
#AC_MSG_NOTICE(*** GENERIC PROGRAMS ***)
#AC_PATH_PROGS(AR, ar, :)
#AC_PATH_PROGS(PERL, perl5 perl4 perl, /usr/bin/perl)
#AC_PATH_PROGS(UNMOUNT_PROGRAM, umount unmount, /bin/umount)


AC_CONFIG_FILES(\
Makefile \
lib/Makefile \
include/Makefile \
skey/Makefile \
)

AC_CONFIG_COMMANDS_PRE


AC_OUTPUT
