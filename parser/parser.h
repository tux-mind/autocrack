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

#include "cap2hccap.c"

#define P_type(t) 					(parser_type((t),__FILE__,__LINE__))
#define P_hash(t,h) 				(parser_hash((t),(h),__FILE__,__LINE__))
#define P_hash_list() 			(parser_hash_list(__FILE__,__LINE__))
#define P_infile(f) 				(parser_infile((f)))
#define P_essid(e) 					(parser_essid((e),__FILE__,__LINE__))
#define P_rt_root(r) 				(parser_rt_root((r),__FILE__,__LINE__))
#define P_wordlist(w) 			(parser_wordlist((w),__FILE__,__LINE__))
#define P_capture(c) 				(parser_capture((c),__FILE__,__LINE__))
#define P_path(p)						(parser_path((p)))
#define P_odb(f)						(parser_odb((f),__FILE__,__LINE__))
#define P_defaults()				(parser_defaults())
#define P_prog_output(t)		(parser_prog_output((t),__FILE__,__LINE__))
#define P_wpa_list()				(parser_wpa_list())
#define P_online						(parser_online)
#define P_outfile(f)				(parser_outfile((f)))
// prototypes
void parser_rt_root(const char *,const char *,int);
