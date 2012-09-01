/*
 *	Autocrack - automatically crack everything throught CPU and GPU
 *	Copyright (C) 2012  Massimo Dragano <massimo.dragano@gmail.com>
 *
 *	Autocrack is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *
 *	Autocrack is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with Autocrack.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#ifdef HAVE_CONFIG_H
#	include "config.h"
#	ifndef HAVE_FNMATCH
#		error "this system havn't fnmatch.h"
#	endif
#	ifndef HAVE_WORKING_FORK
#		error	"this system havn't fork() O_o"
#	endif
#	if HAVE_MALLOC != 1
#		error	"this system havn't malloc() O_o"
#	endif
#	if HAVE_REALLOC != 1
#		error	"this system havn't realloc() O_o"
#	endif
#	ifndef HAVE_DIRENT_H
#		error	"this system havn't dirent.h"
#	endif
#	ifndef HAVE_SYS_TYPES_H
#		error	"this system havn't sys/types.h O_o"
#	endif
#	ifndef HAVE_NETINET_IN_H
#		error	"this system havn't netinet/in.h"
#	endif
#	ifndef HAVE_NETDB_H
#		error	"this system havn't netdb.h"
#	endif
#	ifndef HAVE_STDBOOL_H
#		ifndef HAVE__BOOL
#			ifdef __cplusplus
typedef bool _Bool;
#			else
#				define _Bool signed char
#			endif
#		endif
#		define bool _Bool
#		define false 0
#		define true 1
#	else
#		include <stdbool.h>
#	endif
#	ifndef STDC_HEADERS
#		error	"this system havn't string.h O_o"
#	endif
#	ifndef HAVE_UNISTD_H
#		error	"this system havn't unistd.h ( maybe windows ? )"
#	endif
#	ifndef HAVE_SYS_WAIT_H
#		error	"this system havn't sys/wait.h"
#	endif
#	ifdef TIME_WITH_SYS_TIME
# 	include <sys/time.h>
# 	include <time.h>
#	else
# 	ifdef HAVE_SYS_TIME_H
#  		include <sys/time.h>
# 	else
#  		include <time.h>
# 	endif
#	endif
#	ifdef HAVE_TERMIOS_H
# 	include <termios.h>
#	elifndef GWINSZ_IN_SYS_IOCTL
#		error "this system havn't TIOCGWINSZ"
#	endif
#	ifndef HAVE_SYS_SOCKET_H
#		error "this system havn't sys/socket.h O_o"
#	endif
#	ifndef HAVE_REGEX_H
#		error "this system havn't regex.h"
#	endif
#	ifndef HAVE_STDLIB_H
#		error "this system havn't stdlib.h O_o"
#	endif
#	ifndef HAVE_STRING_H
#		error "this system havn't string.h O_o"
#	endif
#	ifndef HAVE_LIBCURL
#		error "this system havn't libcurl installed"
#	endif
#	ifndef HAVE_LIBCRYPTO
#		error "this system havn't crypto libs"
#	endif
#	ifndef HAVE_LIBPTHREAD
#		error "this system havn't pthread.h O_o"
#	endif
#	ifdef STAT_MACROS_BROKEN
#		error	"bad stat macros. ( Tektronix UTekV, Amdahl UTS and Motorola System V/88 )"
#	endif
#elif defined(BINS)
#	warning "no config.h, but ssems that required macros exist...keep going.."
#else
#	error		"no config.h, ./configure script not executed or failed."
#endif/* HAVE_CONFIG_H */


#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fnmatch.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/select.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <math.h>
#include <libgen.h>
#include <regex.h>
#include <sys/stat.h>
#ifdef HAVE_LIBMAGIC
	#include <magic.h>
#endif
#include <netdb.h>
#include <netinet/tcp.h>
#include <curl/curl.h>
#include <time.h>
#include <pthread.h>
#ifdef _WIN32
	#include "conio.h"
#endif
#include "crypto.c"

#define MAX_BUFF 				(PATH_MAX)
#define MAX_LINE				255
#define MAX_HASH				1024
#define MAX_ODB					50
#define MAX_ODB_T				10																				// maximum fields to POST
#define ODB_HEAD				4																					// number of header's line in the file
#define ODB_SEP					"--"
#define ODB_SKIP_RGX		"^[ \t]*#"
#define ODB_SKIP_CHR		'#'
#define ODB_HASH_UP 		"_HASH_"
#define ODB_HASH_DN			"_hash_"
#define ODB_TYPE_UP			"_TYPE_"
#define ODB_TYPE_DN			"_type_"
#define CURL_TIMEOUT		40
#define NET_CHK_TIMEOUT	15000 // ms
#define BOT_RETRY				3
#define WORK_RATIO			2.0																				// (work for GPU) / (work for cpu)
#define TKILL_TIMEOUT		100 // ms
#ifndef DEF_RT_ROOT
	#define DEF_RT_ROOT		"rt"
#endif
#ifndef DEF_WRDLST
	#define DEF_WRDLST		"wordlist"
#endif
#ifndef DEF_ODB
	#define DEF_ODB					"online.db"
#endif
#ifndef MAX_THREADS
	#define MAX_THREADS 20
#endif
#ifndef NULL_FILE
	#define NULL_FILE "/dev/null"
#endif

enum _log_level
{
	quiet,
	error,
	warning,
	info,
	verbose,
	verbose2,
	verbose3,
	debug
};

#define N_TYPE 11

enum _type
{
	NONE,
	LM,
	md5,
	MYSQL3,
	MYSQL,
	NT,
	sha1,   // ...must use lowercase here,
	sha256, // or openssl will joke you.
	sha384,
	sha512,
	UNKNOWN
};

static const char* type_str[] =
{
	"NONE",
	"LM",
	"MD5",
	"MYSQL3",
	"MYSQL",
	"NT",
	"SHA1",
	"SHA256",
	"SHA384",
	"SHA512",
	"UNKNOWN"
};

static const char* type_rgx[] =
{
	".*",
	"^[0-9A-Fa-f]{32}$",
	"^[0-9A-Fa-f]{32}$",
	"^[0-9A-Fa-f]{16}$",
	"^[0-9A-Fa-f]{40}$",
	"^[0-9A-Fa-f]{32}$",
	"^[0-9A-Fa-f]{40}$",
	"^[0-9A-Fa-f]{64}$",
	"^[0-9A-Fa-f]{98}$",
	"^[0-9A-Fa-f]{128}$",
	".*"
};

/* type codes for hashcat */
char	*types_hc_codes[] =
{
	NULL, 	// NONE
	NULL, 	// LM ( not supported )
	"0",		// MD5
	NULL,		// MYSQL3	( not supported )
	"300",	// MYSQL
	"1000",	// NTLM
	"100",	// SHA1
	"1400",	// SHA256
	NULL,		// SHA384 ( not supported )
	NULL,		// SHA512 ( not supported )
	NULL		// UNKNOWN
};

/* type codes for john the ripper */
char	*types_john_codes[] =
{
	NULL, 				// NONE
	"LM", 				// LM
	"raw-md5",		// MD5 - TODO: must add at least md5(md5(pass)) and md5(pass.salt) and md5(md5(pass).salt)
	"mysql",			// MYSQL3	( not supported )
	"mysql-sha1",	// MYSQL
	"NT",					// NTLM
	"raw-sha1",		// SHA1
	NULL,					// SHA256 ( not supported )
	NULL,					// SHA384 ( not supported )
	NULL,					// SHA512 ( not supported )
	NULL					// UNKNOWN
};

enum _word_mode { delete, cpu, gpu, compute }; // used for make_wordlist
enum _state	{ done, running, waiting, parsed, killed }; // thread status

typedef struct _hash
{
	unsigned int id;
	enum _type type;
	char *hash,*plain;
	pthread_mutex_t lock;
	struct _hash *next;
} _hash;

// hashcat capture structure
typedef struct
{
	char          essid[36];

	unsigned char mac1[6];
	unsigned char mac2[6];
	unsigned char nonce1[32];
	unsigned char nonce2[32];

	unsigned char eapol[256];
	int           eapol_size;

	int           keyver;
	unsigned char keymic[16];

} hccap_t;

typedef struct _wpa
{
	unsigned int id;
	char *essid,*key,*genpmk;
	bool manual;
	hccap_t *hccap;
	struct _wpa *next;
}_wpa;

struct t_info
{
	const char 	*bin,*outfile;
	pthread_t 	thread;
	enum _state state;
	struct _hlist { _hash *hash; struct _hlist *next; } *hlist;
	struct _wlist { _wpa *wpa; struct _wlist *next; } *wlist;
	pthread_mutex_t lock;
	struct t_info *next;
};

struct _bins
{
	char 	*jtr,
				*cow,
				*oclhashcat,
				*pyrit,
				*rcrack;
};

// odb tuple
typedef struct _odb_t
{
	const char *name,*value;
	struct _odb_t *next;
} odb_t;

enum _method {GET,POST};

// odb type binding
typedef struct _odb_type
{
	enum _type type;
	const char *value;
	struct _odb_type *next;
} odb_type;

// defining online_db struct
typedef struct _odb
{
	const char *host,*file,*patrn,*detected;
	enum _method method;
	odb_type *types;
	odb_t *tuples;
	pthread_t thread; // the thread that is using this host
	struct _odb *next;
} odb;

struct _globals {
	enum _log_level log_level;
	bool online,rain,dict,gpu;
	char *err_buff;
	const char *essid,*rt_root,*outfile,*pcap,*wordlist,*hccap;
	struct _bins bins;
	struct _wpa *wpa_list;
	odb *odb;
	_hash *hash_list;
	struct t_info *tpool;
};

#define regexpn(s,r,n)									(w_regexp((s),(r),(n+1),__FILE__,__LINE__,__func__))
#define regexp(s,r)											(w_regexp((s),(r),1,__FILE__,__LINE__,__func__))
#define unbind_hash(h)									(w_unbind_h_w((h),NULL,__FILE__,__LINE__))
#define unbind_wpa(w)										(w_unbind_h_w(NULL,(w),__FILE__,__LINE__))
#define wpa_write_out(w)								(w_write_out(NULL,(w),__FILE__,__LINE__,__func__))
#define hash_write_out(h)								(w_write_out((h),NULL,__FILE__,__LINE__,__func__))
#define fflush(s)												({if(isatty(fileno((s)))){fflush((s));}})

// prototypes
void destroy_all();
void *engine_malloc(size_t, const char *, int);
void engine_del_opt();

// pthread mutexes
pthread_mutex_t pool_lock;


// internal online database
odb internal_odb =
(odb)
{
	"www.onlinehashcrack.com","free-hash-reverse.php",
	".*Plain text :[^>]*>([^<]*)<.*","Slow down little bot.",
	POST,
	&(odb_type){md5,NULL,
		&(odb_type){MYSQL,NULL,
			&(odb_type){NT,NULL,
				&(odb_type){sha1,NULL,NULL}
			}
		}
	},
	&(odb_t){"hashToSearch",ODB_HASH_UP,
		&(odb_t){"searchHash","Search",NULL}
	},
	0,
	&(odb){
		"www.tobtu.com","md5.php",
		"[A-Fa-f0-9]{32}:[^:]+:(.+)","Exceeded rate limit try again later.",
		GET,
		&(odb_type){md5,NULL,NULL},
		&(odb_t){"h",ODB_HASH_UP,NULL},
		0,
		&(odb){
			"www.netmd5crack.com","cgi-bin/Crack.py",
			"Plain Text:.+[a-fA-F0-9]{32}.+border>(.+)</td",NULL,
			GET,
			&(odb_type){md5,NULL,NULL},
			&(odb_t){"InputHash",ODB_HASH_UP,NULL},
			0,
			&(odb){
				"www.cmd5.org","",
				"id=\"ctl00_ContentPlaceHolder1_LabelAnswer\">([^<]+)</span>",NULL,
				POST,
				&(odb_type){md5,NULL,
					&(odb_type){MYSQL3,"mysql",
						&(odb_type){MYSQL,"mysql5",
							&(odb_type){NT,"NTLM",
								&(odb_type){sha1,NULL,
									&(odb_type){sha256,NULL,NULL}
								}
							}
						}
					}
				},
				&(odb_t){"ctl00$ContentPlaceHolder1$TextBoxInput",ODB_HASH_DN,
					&(odb_t){"ctl00$ContentPlaceHolder1$InputHashType",ODB_TYPE_DN,NULL}
				},
				0,
				&(odb){
					"tools.benramsey.com","md5/md5.php",
					"<string><!\\[CDATA\\[([^\\]]+)\\]\\]></string>","SLOW DOWN COWBOY!",
					GET,
					&(odb_type){md5,NULL,NULL},
					&(odb_t){"hash",ODB_HASH_DN,NULL},
					0,
					&(odb){
						"md5.gromweb.com","",
						"name=\"string\" value=\"([^\"]+)\" id=\"form_string\"","You made too many queries.",
						GET,
						&(odb_type){md5,NULL,NULL},
						&(odb_t){"md5",ODB_HASH_DN,NULL},
						0,
						&(odb){
							"md5.hashcracking.com","search.php",
							"Cleartext of [a-f0-9]{32} is (.+)",NULL,
							GET,
							&(odb_type){md5,NULL,NULL},
							&(odb_t){"md5",ODB_HASH_DN,NULL},
							0,
							&(odb){
								"md5.thekaine.de","",
								"<td colspan=\"2\"><br><br><b>not found</b></td><td></td>|<td colspan=\"2\"><br><br><b>([^<]+)</b></td><td></td>",NULL,
								GET,
								&(odb_type){md5,NULL,NULL},
								&(odb_t){"hash",ODB_HASH_DN,NULL},
								0,
								&(odb){
									"md5.my-addr.com","md5_decrypt-md5_cracker_online/md5_decoder_tool.php",
									"class='middle_title'>Hashed string</span>: ([^<]+)</div>",NULL,
									POST,
									&(odb_type){md5,NULL,NULL},
									&(odb_t){"md5",ODB_HASH_DN,NULL},
									0,
									&(odb){
										"md5pass.info","",
										"Password - <b>([^<]+)</b>",NULL,
										POST,
										&(odb_type){md5,NULL,NULL},
										&(odb_t){"hash",ODB_HASH_DN,
											&(odb_t){"get_pass","Get+Pass",NULL}
										},
										0,
										&(odb){
											"md5decryption.com","",
											"Decrypted Text: </b>([^<]+)</font>",NULL,
											POST,
											&(odb_type){md5,NULL,NULL},
											&(odb_t){"hash",ODB_HASH_DN,
												&(odb_t){"submit","Descypt+It%21",NULL}
											},
											0,
											&(odb){
												"md5crack.com","crackmd5.php",
												"Found: md5\\(\"(.+)\"\\) = [a-f0-9]{32}</div>",NULL,
												POST,
												&(odb_type){md5,NULL,NULL},
												&(odb_t){"term",ODB_HASH_DN,
													&(odb_t){"crackbtn","Crack+that+hash+baby%21",NULL}
												},
												0,
												&(odb){
													"md5online.net","",
													"<b>[a-f0-9]{32}</b> <br>pass : <b>(.+)</b></p>",NULL,
													POST,
													&(odb_type){md5,NULL,NULL},
													&(odb_t){"pass",ODB_HASH_DN,
														&(odb_t){"option","hash2text",
															&(odb_t){"send","Submit",NULL}
														}
													},
													0,
													&(odb){
														"md5-decrypter.com","",
														"Decrypted text:</b>[ \n]+<b class=\"res\">(.+)</b>",NULL,
														POST,
														&(odb_type){md5,NULL,NULL},
														&(odb_t){"data[Row][cripted]",ODB_HASH_DN,NULL},
														0,
														&(odb){
															"www.authsecu.com","decrypter-dechiffrer-cracker-hash-md5/script-hash-md5.php",
															"correspondante :</p></td>[ \n\t]+<td><p class=\"chapitre---texte-du-tableau-de-niveau-1\">(.+)</p></td>","	cutions du script dans le temps imparti.",
															POST,
															&(odb_type){md5,NULL,NULL},
															&(odb_t){"valeur_bouton","dechiffrage",
																&(odb_t){"champ1","",
																	&(odb_t){"champ2",ODB_HASH_DN,NULL}
																}
															},
															0,
															&(odb){
																"objectif-securite.ch","products.php",
																"</td></tr><tr><td><b>Password:</b></td><td><b>Not found !</b></td></tr></table>|</td></tr><tr><td><b>Password:</b></td><td><b>(.+)</b></td></tr></table>",NULL,
																GET,
																&(odb_type){LM,NULL,
																	&(odb_type){NT,NULL,NULL}
																},
																&(odb_t){"hash",ODB_HASH_DN,NULL},
																0,
																&(odb){
																	"md5.rednoize.com","",
																	"(.+)",NULL,
																	GET,
																	&(odb_type){md5,NULL,
																		&(odb_type){sha1,NULL,NULL}
																	},
																	&(odb_t){"p","",
																		&(odb_t){"s",ODB_TYPE_DN,
																			&(odb_t){"q",ODB_HASH_DN,NULL}
																		}
																	},
																	0,
																	&(odb){
																		"hashchecker.com","index.php",
																		"<td><li>Your md5 hash is :<br><li>[a-f0-9]{32} is <b>(.+)</b> used charlist",NULL,
																		POST,
																		&(odb_type){md5,NULL,NULL},
																		&(odb_t){"search_field",ODB_HASH_DN,
																			&(odb_t){"Submit","search",NULL}
																		},
																		0,
																		&(odb){
																			"joomlaaa.com","component/option,com_md5/Itemid,31/",
																			"<td class='title1'>Equivelant</td>[ \n]*<td class='title1'>not available</td>|<td class='title1'>Equivelant</td>[ \n]*<td class='title1'>(.+)</td>",NULL,
																			POST,
																			&(odb_type){md5,NULL,NULL},
																			&(odb_t){"md5",ODB_HASH_DN,
																				&(odb_t){"decode","Submit",NULL}
																			},
																			0,
																			&(odb){
																				"_type_-lookup.com","index.php",
																				"<td width=\"[0-9 ]+\">(.+)</td>[ \n\t]+<td style=\"[^\"]+\">[a-f0-9]+</td>",NULL,
																				GET,
																				&(odb_type){md5,NULL,
																					&(odb_type){sha1,NULL,
																						&(odb_type){sha256,"sha-256.sha1",NULL}
																					}
																				},
																				&(odb_t){"q",ODB_HASH_DN,NULL},
																				0,
																				&(odb){
																					"md5.myinfosec.net","md5.php",
																					"<center></center>[a-f0-9]{32}:<font color=green>(.+)</font><br></center>",NULL,
																					POST,
																					&(odb_type){md5,NULL,NULL},
																					&(odb_t){"md5hash",ODB_HASH_DN,NULL},
																					0,
																					&(odb){
																						"md5.net","cracker.php",
																						"Result:</strong><br />[ \n\t]+<input type=\"text\" id=\"hash\" size=\"[0-9]+\" value=\"(.+)\"/>",NULL,
																						POST,
																						&(odb_type){md5,NULL,NULL},
																						&(odb_t){"hash",ODB_HASH_DN,NULL},
																						0,
																						&(odb){
																							"md5.noisette.ch","index.php",
																							"[a-f0-9]{32}</a>\" = md5\\(\"(.+)\"\\)</div>",NULL,
																							GET,
																							&(odb_type){md5,NULL,NULL},
																							&(odb_t){"hash",ODB_HASH_DN,NULL},
																							0,
																							&(odb){
																								"md5hood.com","index.php/cracker/crack",
																								"<div class=\"result_true\">(.+)</div>",NULL,
																								POST,
																								&(odb_type){md5,NULL,NULL},
																								&(odb_t){"md5",ODB_HASH_DN,
																									&(odb_t){"submit","Go",NULL}
																								},
																								0,
																								&(odb){
																									"www.stringfunction.com","_type_-decrypter.html",
																									"<textarea class=\"textarea-input-tool-b\" rows=\"[0-9]+\" cols=\"[0-9]+\" name=\"result\">(.+)</textarea>",NULL,
																									POST,
																									&(odb_type){md5,NULL,
																										&(odb_type){sha1,NULL,NULL}
																									},
																									&(odb_t){"string",ODB_HASH_DN,
																										&(odb_t){"submit","Decrypt",
																											&(odb_t){"result","",NULL}
																										}
																									},
																									0,
																									&(odb){
																										"https://goog.li","",
																										"<abbr>plaintext<span><b>(.+)</b></span></abbr>",NULL,// not checked, SSL + wireshark = not good.
																										GET,
																										&(odb_type){md5,"",
																											&(odb_type){MYSQL,"*",
																												&(odb_type){MYSQL3,"",
																													&(odb_type){NT,"",
																														&(odb_type){sha1,"",
																															&(odb_type){sha256,"",
																																&(odb_type){sha384,"",
																																	&(odb_type){sha512,"",NULL}
																																}
																															}
																														}
																													}
																												}
																											}
																										},
																										&(odb_t){"q",ODB_TYPE_DN ODB_HASH_DN,NULL},
																										0,
																										NULL
																									}
																								}
																							}
																						}
																					}
																				}
																			}
																		}
																	}
																}
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
};

