AC_INIT([autocrack], [0.0.1], [massimo.dragano@gmail.com])
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
	AC_MSG_RESULT(yes)
else
	CFLAGS="$CFLAGS -g -O2 -ffast-math -fomit-frame-pointer -pipe"
	AC_MSG_RESULT(no)
fi


AC_PATH_PROG([JTR], [john],"", [$PATH:/usr/sbin])
AC_PATH_PROG([COWPATTY], [cowpatty],"")
AC_PATH_PROG([PYRIT],[pyrit],"")
AC_PATH_PROG([OCLHASHCAT], [oclHashcat-plus64.bin],"")
if test -z "$OCLHASHCAT"; then
	AC_PATH_PROG([OCLHASHCAT], [oclhashcat-plus],"")
fi
AC_PATH_PROG([RCRACK], [rcracki_mt], "")


if test -n "$JTR"; then
	echo "Testing john the ripper."
	TESTOUT=/tmp/john.pot
	rm -f "$TESTOUT"
	$JTR --wordlist=test/uword --format=raw-md5 test/hash.md5 --pot="$TESTOUT" &>/dev/null 2>/dev/tty
	if test ! -f "$TESTOUT"; then
		AC_MSG_WARN([john the ripper test failed. usually you must install it in SYSTEMWIDE mode.])
		JTR=""
	else
		rm "$TESTOUT"
	fi
else
	AC_MSG_WARN([Cannot found john the ripper, many features will be disabled.])
fi
if test -n "$COWPATTY"; then
	TESTOUT=/tmp/cow.out
	echo "Testing coWPAtty."
	$COWPATTY -f test/uword -r test/wpa2psk-MOM1.dump -s MOM1 &>/dev/null 1>$TESTOUT
	PSK=$( grep -oe "MOM12345" "$TESTOUT" )
	if test -n "$PSK"; then
		rm "$TESTOUT"
	else
		if test -f "$TESTOUT"; then
			rm "$TESTOUT"
		fi
		COWPATTY=""
		AC_MSG_WARN([Cowpatty test failed.])
	fi
else
	COWPATTY=""
	AC_MSG_WARN([Cannot found cowpatty, CPU wpa rainbowtable attack will be disabled.])
fi
if test -n "$OCLHASHCAT"; then
	TESTOUT=/tmp/ocl.out
	echo "Testing oclhashcat-plus."
	$OCLHASHCAT -m 0 -a 0 -o "$TESTOUT" --outfile-format=3 test/uword test/hash.md5 &>/dev/null 2>/dev/tty
	PSWD=$(grep -o password "$TESTOUT")
	if test -n "$PSWD"; then
		rm "$TESTOUT"
	else
		if test -f "$TESTOUT"; then
			rm "$TESTOUT"
		fi
		OCLHASHCAT=""
		AC_MSG_WARN([oclhashcat-plus test failed.])
	fi
else
	AC_MSG_WARN([oclhashcat-plus not found.])
fi
if test -n "$PYRIT" ; then
	TESTOUT=/tmp/pyr.out
	echo "Testing pyrit."
	$PYRIT -i test/uword -o "$TESTOUT" -r test/wpa2psk-MOM1.dump -e MOM1 	attack_passthrough &>/dev/null 2>/dev/tty
	PSK=$(grep -o MOM12345 "$TESTOUT")
	if test -n "$PSK"; then
		rm "$TESTOUT"
	else
		if test -f "$TESTOUT"; then
			rm "$TESTOUT"
		fi
		PYRIT=""
		AC_MSG_WARN([pyrit test failed.])
	fi
else
	AC_MSG_WARN([cannot find pyrit.])
fi
if test -n "$RCRACK"; then
	echo "Testing rcracki_mt."
else
	AC_MSG_WARN([Cannot find rcracki_mt.])
fi

if test -z "$OCLHASHCAT$PYRIT$JTR$RCRACK$COWPATTY" ; then
	AC_MSG_ERROR([Hei guy! seems that you havn't anything installed on your machine! Please install al least one of the programs above.])
fi
MY_CONFDIR="$sysconfdir/autocrack"
AC_SUBST([MY_CONFDIR])
#AC_DEFINE_UNQUOTED([CONFDIR],["$MY_CONFDIR"],"config dir")
# if you edit the next line remember that if you provide less then (sizeof(struct _bins)/sizeof(char *)) strings, probably the function parser_path will recieve a SIGSEGV signal while try to evaluate the legth of a string that you havn't give..
AC_DEFINE_UNQUOTED([BINS],[	{		"$JTR",		"$COWPATTY",		"$OCLHASHCAT",		"$PYRIT",		"$RCRACK"	}],"external binaries")
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
