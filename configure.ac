AC_INIT([autocrack], [0.0.1], [massimo.dragano@gmail.com],,[https://github.com/tux-mind/autocrack])
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_PROG_CC
AM_PROG_CC_C_O
AC_FUNC_FNMATCH
AC_FUNC_FORK
AC_HEADER_DIRENT
AC_HEADER_RESOLV
AC_HEADER_STAT
AC_HEADER_STDBOOL
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_HEADER_TIME
AC_HEADER_TIOCGWINSZ
AC_FUNC_MALLOC
AC_FUNC_REALLOC

AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([regex.h])
AC_CHECK_LIB([pthread],[main])
AC_CHECK_LIB([curl],[main])
AC_CHECK_LIB([crypto],[main])
AC_CHECK_LIB([magic],[main])

debug_default="yes"
AC_ARG_ENABLE(debug, [  --enable-debug=[no/YES] write debugging symbols and turn off optimization.],enable_debug=$enableval, enable_debug=$debug_default)
if test "x$enable_debug" == "xyes"; then
	CFLAGS="$CFLAGS -ggdb -O0"
	#AC_MSG_RESULT([yes])
else
	CFLAGS="$CFLAGS -g -O2 -ffast-math -fomit-frame-pointer -pipe"
	#AC_MSG_RESULT([no])
fi
AC_DEFUN([AC_SET_DEFAULT_PATHS_SYSTEM],
[AC_REQUIRE([AC_CANONICAL_HOST]) # --------------------------------------------
case "$prefix:$ac_default_prefix" in
  NONE:/usr/local)
    result=""
    AC_MSG_CHECKING(default prefix path)
    case "${target_os}" in
      *cygwin* | *mingw* | *uwin* | *djgpp | *emx* )
        if test "${host_os}" = "${target_os}" ; then
           ac_default_prefix="/programs"
           result="(win/dos target)"
        else
           case "$PATH" in
              *:/usr/local/cross-tools/$target_alias/bin:*)
                  ac_default_prefix="/usr/local/cross-tools/$target_alias" ;;
              *:/usr/local/$target_alias/bin:*)
                  ac_default_prefix="/usr/local/$target_alias" ;;
              *:/usr/local/$target_cpu-$target_os/bin:*)
                  ac_default_prefix="/usr/local/$target_cpu-$target_os" ;;
              *)
                  ac_default_prefix="/programs" ;;
           esac
           result="(win/dos cross-compiler)"
        fi
    ;;
    esac
    AC_MSG_RESULT($ac_default_prefix $result)
  ;;
esac
AC_MSG_CHECKING(default prefix system)
result="$prefix" ; test "$result" = "NONE" && result="$ac_default_prefix"
case ${result} in
  /programs | /programs/*) result="is win-/programs"
     # on win/dos, .exe .dll and .cfg live in the same directory
     libdir=`echo $libdir |sed -e 's:^..exec_prefix./lib$:${bindir}:'`
     sbindir=`echo $sbindir |sed -e 's:^..exec_prefix./sbin$:${libdir}:'`
     sysconfdir=`echo $sysconfdir |sed -e 's:^..prefix./etc$:${sbindir}:'`
     libexecdir=`echo $libexecdir |sed -e 's:/libexec$:/system:'`
     # help-files shall be set with --infodir, docprefix is datadir
     docprefix="${datadir}"
     mandir=`echo $mandir \
                             |sed -e 's:^..prefix./man$:${datadir}/info:'`
     includedir=`echo $includedir \
                |sed -e 's:^..prefix./include$:${datadir}/include:'`
     # other state files (but /etc) are moved to datadir
     sharedstatedir=`echo $sharedstatedir \
                     |sed -e 's:^..prefix./com$:${datadir}/default:'`
     localstatedir=`echo $localstatedir \
                     |sed -e 's:^..prefix./var$:${datadir}/current:'`
  ;;
  /usr) result="is /usr-shipped"
     # doc files are left at prefix
     docprefix="${prefix}"
     # state files go under /top
     sysconfdir=`echo $sysconfdir |sed -e 's:^..prefix./etc$:/etc:'`
     sharedstatedir=`echo $sharedstatedir \
                     |sed -e 's:^..prefix./com$:/etc/default:'`
     # $prefix/var is going to end up in /var/lib
     localstatedir=`echo $localstatedir \
                     |sed -e 's:^..prefix./var$:/var/lib:'`
  ;;
  /opt | /opt/*) result="is /opt-package"
     # state files go under /top/prefix
     sysconfdir=`echo $sysconfdir \
                     |sed -e 's:^..prefix./etc$:/etc${prefix}:'`
     sharedstatedir=`echo $sharedstatedir \
                     |sed -e 's:^..prefix./com$:/etc/default${prefix}:'`
     # $prefix/var is going to to be /var$prefix... once again
     localstatedir=`echo $localstatedir \
                     |sed -e 's:^..prefix./var$:/var${prefix}:'`
     # doc files are left at prefix
     docprefix="${prefix}"
  ;;
  *) result="is /local-package"
     # doc files are moved from prefix down to datadir
     docprefix="${datadir}"
     mandir=`echo $mandir \
                     |sed -e 's:^..prefix./man$:${datadir}/man:'`
     infodir=`echo $infodir \
                     |sed -e 's:^..prefix./infodir$:${datadir}/info:'`
     # never use $prefix/com - that is no good idea
     sharedstatedir=`echo $sharedstatedir \
                     |sed -e 's:^..prefix./com$:${sysconfdir}/default:'`
     sysconfdir=`echo $sysconfdir |sed -e 's:^..prefix./etc$:/etc:'`
  ;;
esac
AC_MSG_RESULT($result)
# --------------------------------------------------------
])


AC_PATH_PROG([JTR], [john],"", [$PATH:/usr/sbin])
AC_PATH_PROG([COWPATTY], [cowpatty],"")
AC_PATH_PROG([PYRIT],[pyrit],"")
AC_PATH_PROG([OCLHASHCAT], [oclHashcat-plus64.bin],"")
if test -z "$OCLHASHCAT"; then
	AC_PATH_PROG([OCLHASHCAT], [oclhashcat-plus],"")
fi
AC_PATH_PROG([RCRACK], [rcracki_mt], "")

TMPLOG=/tmp/test.log

if test -n "$JTR"; then
	AC_MSG_CHECKING([john the ripper])
	TESTOUT=/tmp/john.pot
	rm -f "$TESTOUT"
	$JTR --wordlist=test/uword --format=raw-md5 test/hash.md5 --pot="$TESTOUT" &>"$TMPLOG"
	if test ! -f "$TESTOUT"; then
		AC_MSG_RESULT([FAILED])
		AC_MSG_WARN([usually you must install it in SYSTEMWIDE mode.])
		AC_MSG_WARN([program output:])
		cat "$TMPLOG"
		JTR=""
	else
		AC_MSG_RESULT([success])
		rm "$TESTOUT"
	fi
else
	AC_MSG_WARN([Cannot found john the ripper, many features will be disabled.])
fi
if test -n "$COWPATTY"; then
	AC_MSG_CHECKING([coWPAtty])
	$COWPATTY -f test/uword -r test/wpa2psk-MOM1.dump -s MOM1 &>"$TMPLOG"
	PSK=$( grep -oe "MOM12345" "$TMPLOG")
	if test -n "$PSK"; then
		AC_MSG_RESULT([success])
	else
		COWPATTY=""
		AC_MSG_RESULT([FAILED])
		AC_MSG_WARN([program ouput:])
		cat "$TMPLOG"
	fi
else
	COWPATTY=""
	AC_MSG_WARN([Cannot found cowpatty, CPU wpa rainbowtable attack will be disabled.])
fi
if test -n "$OCLHASHCAT"; then
	TESTOUT=/tmp/ocl.out
	AC_MSG_CHECKING([oclhashcat-plus])
	$OCLHASHCAT -m 0 -a 0 -o "$TESTOUT" --outfile-format=3 test/uword test/hash.md5 &>"$TMPLOG"
	PSWD=$(grep -o password "$TESTOUT")
	if test -n "$PSWD"; then
		AC_MSG_RESULT([success])
		rm "$TESTOUT"
	else
		if test -f "$TESTOUT"; then
			rm "$TESTOUT"
		fi
		OCLHASHCAT=""
		AC_MSG_RESULT([FAILED])
		AC_MSG_WARN([program output is:])
		cat "$TMPLOG"
	fi
else
	AC_MSG_WARN([oclhashcat-plus not found.])
fi
if test -n "$PYRIT" ; then
	TESTOUT=/tmp/pyr.out
	AC_MSG_CHECKING([pyrit.])
	$PYRIT -i test/uword -o "$TESTOUT" -r test/wpa2psk-MOM1.dump -e MOM1 	attack_passthrough &>"$TMPLOG"
	PSK=$(grep -o MOM12345 "$TESTOUT")
	if test -n "$PSK"; then
		AC_MSG_RESULT([success])
		rm "$TESTOUT"
	else
		if test -f "$TESTOUT"; then
			rm "$TESTOUT"
		fi
		PYRIT=""
		AC_MSG_RESULT([FAILED])
		AC_MSG_WARN([program output is:])
		cat "$TMPOUT"
	fi
else
	AC_MSG_WARN([cannot find pyrit.])
fi
if test -n "$RCRACK"; then
	AC_MSG_CHECKING([rcracki_mt.])
	AC_MSG_RESULT([FUNCTION NOT AVAILABLE])
else
	AC_MSG_WARN([Cannot find rcracki_mt.])
fi

if test -z "$OCLHASHCAT$PYRIT$JTR$RCRACK$COWPATTY" ; then
	AC_MSG_ERROR([Hei guy! seems that you havn't anything installed on your machine! Please install al least one of the programs above.])
fi
oldprefix="$prefix" # something in the next function set prefix to NONE
AC_SET_DEFAULT_PATHS_SYSTEM
prefix="$oldprefix" # so we restore it to prefious value.
CONFDIR="$prefix$sysconfdir/autocrack"
AC_DEFINE_UNQUOTED([CONFDIR],"$CONFDIR","config dir")
# if you edit the next line remember that if you provide less then (sizeof(struct _bins)/sizeof(char *)) strings, probably the function parser_path will recieve a SIGSEGV signal while try to evaluate the legth of a string that you havn't give..
AC_DEFINE_UNQUOTED([BINS],[	{		"$JTR",		"$COWPATTY",		"$OCLHASHCAT",		"$PYRIT",		"$RCRACK"	}],"external binaries")
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
