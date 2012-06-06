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

#define socket(domain, type, protocol) 	(w_socket((domain),(type),(protocol),__FILE__,__LINE__))
#define listen(sockfd, backlog) 				(w_listen((sockfd),(backlog),__FILE__,__LINE__))
#define bind(sockfd, addr, len) 				(w_bind((sockfd),(addr),(len),__FILE__,__LINE__))
#define malloc(bytes) 									(w_malloc((bytes),__FILE__,__LINE__))
#define report_error(msg,p,f,l) 				(w_report_error((msg),__FILE__,__LINE__,__func__,(p),(f),(l)))
#define add_hash(type,hash) 						(w_add_hash((type),(hash),__FILE__,__LINE__))
#define del_hash(h) 										(w_del_hash((h),__FILE__,__LINE__))
#define get_mime(f)											(w_get_mime((f),__FILE__,__LINE__))
#define argcpy(d,s,l)										(w_argcpy((d),(s),(l),__func__,__FILE__,__LINE__))
#define str2low(s) 											(w_str2low((s),__FILE__,__LINE__))
#define str2up(s)												(w_str2up((s),__FILE__,__LINE__))
#define add_odb_t(l,a,e)								(w_add_odb_t((l),(a),(e)))
#define add_odb_type(l,a)								(w_add_odb_type((l),(a)))
#define fgets_fix(s)										(w_fgets_fix((s),__FILE__,__LINE__,__func__))
#define prog_wait(a,f,w)								(w_prog_call((a),(f),(w),__FILE__,__LINE__))
#define prog_call(a,f)									(w_prog_call((a),(f),NULL,__FILE__,__LINE__))
#define make_hash_file(t)								(w_make_hash_file((t),__FILE__,__LINE__,__func__))
#define make_wordlist(m)								(w_make_wordlist((m),__FILE__,__LINE__))
#define get_full_path(f)								(w_get_full_path((f),__FILE__,__LINE__,__func__))
#define tmpnam(s)												(w_tmpnam((s),__FILE__,__LINE__,__func__))
#define add_wpa(e,h)										(w_add_wpa((e),(h),__FILE__,__LINE__))
#define add_wpa_key(t,k)								(w_add_wpa_key((t),(k),__FILE__,__LINE__))
#define bind_thr2hash(t,h)							(w_bind_thr((t),NULL,NONE,(h),__FILE__,__LINE__))
#define bind_thr2htype(t,ht)						(w_bind_thr((t),NULL,(ht),NULL,__FILE__,__LINE__))
#define bind_thr2wpa(t,w)								(w_bind_thr((t),(w),NONE,NULL,__FILE__,__LINE__))
#define unbind_thr(t)										(w_unbind_thr((t)))
#define add_hash_plain(h,hsh,t,p)				(w_add_hash_plain((h),(hsh),(t),(p),__FILE__,__LINE__))
#define report(log, form, arg...)				(w_report_error(globals.err_buff,__FILE__,__LINE__,__func__,(snprintf(globals.err_buff,MAX_BUFF,form,##arg)) & 0,0,(log)))
#define odb_sub_str(s,t,h,l)				(w_odb_sub_str((s),(t),(h),(l),__FILE__,__LINE__))
