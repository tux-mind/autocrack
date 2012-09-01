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

#include "common.h"

extern struct _globals globals;

void w_report_error(const char *msg, const char *file, int line_no, const char *caller, int use_perror, int fatal, enum _log_level call_level)
{
	char format[MAX_BUFF];
	FILE *stream;
	static pthread_t main_thread;
	struct winsize term;
	bool under_main = false;
	static const char *log_level_str[] =
	{
		"quiet",
		"error",
		"warning",
		"info",
		"verbose",
		"verbose2",
		"verbose3",
		"debug",
	};
	static int 	max_level_len = 8,
							max_file_len = 14,
							max_line_len = 4,
							max_func_len = 20;

	if(	msg == NULL) // set main thread number.
	{
		main_thread = pthread_self();
		return;
	}
	else if(call_level > globals.log_level)
		return;
	else if(pthread_equal(pthread_self(),main_thread))
		under_main = true;

	stream = stderr;
	file = basename((char *)file);
	if(use_perror)
	{
		if(globals.log_level == debug)
			snprintf(	format,MAX_BUFF,
								"[%*s:%*d - %-*s] %-*s: \"%s\"",
								max_file_len,file,max_line_len,line_no,max_level_len,log_level_str[call_level],max_func_len,caller,msg);
		else
			snprintf( format,MAX_BUFF,
								"[%-*s]\t\"%s\"",max_level_len,log_level_str[call_level],msg);
		perror(format);
	}
	else
	{
		if(globals.log_level == debug)
			snprintf(	format,MAX_BUFF,
								"[%*s:%*d - %-*s] %-*s: %s",
								max_file_len,file,max_line_len,line_no,max_level_len,log_level_str[call_level],max_func_len,caller,msg);
		else
			snprintf( format,MAX_BUFF,
								"[%-*s]\t%s",max_level_len,log_level_str[call_level],msg);
		if(call_level >= info)
			stream = stdout;
		if(under_main==false)
		{
			ioctl(STDOUT_FILENO, TIOCGWINSZ,&term);
			fprintf(stream,"%-*c\r",term.ws_col,' '); // clean stdout
		}
		fprintf(stream,"%s\n",format);
	}
	fflush(stream);

	if(fatal)
	{
		if(under_main==true)
			destroy_all(); // only if is the main thread
		pthread_exit((void *) EXIT_FAILURE);
	}
	return;
}

int mysend(int sock, const char *buffer, long buffsize)
{
  fd_set fset;
  struct timeval tv;
  int sockStatus,
      bytesSent;
  char  *pos,
        *end;
  unsigned long blockMode;

  /* set socket to non-blocking */

  blockMode = 1;
  ioctl(sock, FIONBIO, &blockMode);

  pos = (char *) buffer;
  end = (char *) buffer + buffsize;

  while (pos < end)
  {
    bytesSent = send(sock, pos, end - pos, 0);
    if ( bytesSent < 0 )
		{
      if (bytesSent == EAGAIN)
        bytesSent = 0;
      else
			{
				w_report_error("",__FILE__,__LINE__,__func__, 1, 0,warning);
        return 0;
			}
		}
    pos += bytesSent;
    if ( pos >= end )
      break;
    FD_ZERO(&fset);
    FD_SET(sock, &fset);
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    sockStatus = select(sock + 1, NULL, &fset, &fset, &tv);
    if (sockStatus <= 0)
      return 0;

  }
  return 1;
}

int w_socket(int domain, int type, int protocol, const char *file, int line_no)
{
        int socket_return;
        socket_return = socket(domain, type, protocol);
        if(socket_return == -1)
					w_report_error("", file, line_no,__func__, 1,1,error);
        return socket_return;
}

int w_bind(int sockfd, struct sockaddr *addr, socklen_t len, const char *file, int line_no)
{
        int bind_return;
        bind_return = bind(sockfd, addr, len);

        if ( bind_return == -1 )
					w_report_error("", file, line_no,__func__, 1, 1, error);
				return bind_return;
}

int w_listen(int sockfd, int backlog, const char *file, int line_no)
{
        int listen_return;
        listen_return = listen(sockfd, backlog);
        if(listen_return == -1)
					w_report_error("", file, line_no,__func__, 1, 0, error);
				return listen_return;
}

void *w_malloc(size_t bytes, const char *file, int line_no)
{
	void *memory = NULL;
	memory = malloc(bytes);
	if (!memory)
		w_report_error("", file, line_no,__func__, 1, 1, error);
	memset(memory,'\0',bytes);
	return memory;
}

void w_tmpnam(char *tmpfile,const char *file, int line_no, const char *caller)
{
	if(tmpnam(tmpfile) == NULL)
		w_report_error("cannot create temporary files.",file,line_no,caller,0,1,error);
	return;
}

char *w_regexp(const char *string, const char *patrn, size_t nmatch, const char *file, int line_no, const char *caller)
{
	int i, w=0, len,begin,end;
	char *word = NULL;
	regex_t rgT;
	regmatch_t *pmatch;

	if( string == NULL || patrn == NULL)
		w_report_error("called with NULL pointer.",file,line_no,caller,0,1,error);
	else if(strlen(string) == 0)
		return NULL;
	else if(nmatch <= 0 || nmatch > 20)
	{
		w_report_error("called with invalid index.",file,line_no,caller,0,0,error);
		return NULL;
	}

	if (regcomp(&rgT,patrn,REG_EXTENDED | REG_NEWLINE) != 0)
	{
		snprintf(globals.err_buff,MAX_BUFF,"bad regex: \"%s\"",patrn);
		w_report_error(globals.err_buff,file,line_no,caller,0,0,error);
		return NULL;
	}

	pmatch = malloc(nmatch*sizeof(regmatch_t));

	if ((regexec(&rgT,string,nmatch,pmatch,0)) == 0)
	{
		begin = (int)pmatch[nmatch-1].rm_so;
		end = (int)pmatch[nmatch-1].rm_eo;
		len = (int) end - begin;
		if(len!=0)
		{
			word=malloc(len+1);
			for (i=begin; i<end; i++)
			{
				word[w] = string[i];
				w++;
			}
			word[w]='\0';
		}
	}
	free(pmatch);
	regfree(&rgT);
	return word;
}

int get_n_cpus()
{
	#ifdef __WIN__
	SYSTEM_INFO sysinfo;
	GetSystemInfo( &sysinfo );
	return sysinfo.dwNumberOfProcessors;
	#elif defined(_SC_NPROCESSORS_ONLN)
	return sysconf( _SC_NPROCESSORS_ONLN);
	#elif defined(__BSD__) || defined(MACOS)
	int mib[4],num;
	size_t len = sizeof(num);

	mib[0] = CTL_HW;
	mib[1] = HW_AVAILCPU;
	sysctl(mib, 2, &num, &len, NULL, 0);
	if(num < 1)
	{
		mib[1] = HW_NCPU;
		sysctl(mib, 2, &num, &len, NULL, 0);
		if(num<1)
			num = 1;
	}
	return num;
	#elif defined(__HPUX__)
	return mpctl(MPC_GETNUMSPUS, NULL, NULL);
	#elif defined(__IRIX__)
	return sysconf(_SC_NPROC_ONLN);
	#else
		#error cannot detect machine architecture.
	#endif
}

char *w_digest(unsigned char *pswd, /*char *salt,*/enum _type type, const char *file, int line_no)
{
	char err_buff[MAX_LINE]; // we must be thread-safe

	switch(type)
	{
		case md5:
			return md5_crypt(pswd);
			break;
		case MYSQL3:
			return mysql3_crypt(pswd);
			break;
		case MYSQL:
			return mysql_crypt(pswd);
			break;
		case NT:
			return ntlm_crypt((char *) pswd);
			break;
		case sha1:
			return sha1_crypt(pswd);
			break;
		case sha256:
			return sha256_crypt(pswd);
			break;
		case sha384:
			return sha384_crypt(pswd);
			break;
		case sha512:
			return sha512_crypt(pswd);
			break;
		default:
			snprintf(err_buff,MAX_LINE,"reverse check for this type \"%s\" is not yet supported.",type_str[type]);
			w_report_error(err_buff,file,line_no,__func__,0,0,warning);
			snprintf(err_buff,MAX_LINE,"given value: %d .",type);
			w_report_error(err_buff,file,line_no,__func__,0,0,debug);
	}

	return "FAIL"; // no digest produce less then 6 chars, so the check will fail.
}

char *w_str2low(const char *arg,const char *file,int line_no)
{
	size_t len;
	char *str,*ptr;

	len = strlen(arg);
	str = w_malloc((len+1)*sizeof(char),file,line_no);
	strncpy(str,arg,len);
	str[len] = '\0';
	for(ptr=str;*ptr!='\n'&&*ptr!='\0';ptr++)
		*ptr = (char) tolower(*ptr);
	*ptr = '\0';
	return str;
}

char *w_str2up(const char *arg,const char *file,int line_no)
{
	size_t len;
	char *str,*ptr;

	len = strlen(arg);
	str = w_malloc((len+1)*sizeof(char),file,line_no);
	strncpy(str,arg,len);
	str[len] = '\0';
	for(ptr=str;*ptr!='\n'&&*ptr!='\0';ptr++)
		*ptr = (char) toupper(*ptr);
	*ptr = '\0';
	return str;
}

void w_write_out(_hash *hash, _wpa *wpa, const char *file, int line_no, const char *caller)
{
	FILE *fd=NULL;
	char buffer[MAX_LINE],*value;
	size_t len;
	bool yet_found;

	if(globals.outfile==NULL)
		return;

	fd = fopen(globals.outfile,"a+"); // all checks are yet done by parser_outfile
	yet_found = false;
	fgets(buffer,MAX_LINE,fd);
	while(!feof(fd) && yet_found == false)
	{
		len = strlen(buffer);
		if(buffer[len-1] == '\n')
		{
			value = regexpn(buffer,"\\$([^$]+)\\$([^:]+):.*",1);
			if(value != NULL)
			{
				if(strncmp(value,"WPA",4))
				{
					if(hash!=NULL)
					{
						free((void *) value);
						value = regexpn(buffer,"\\$([^$]+)\\$([^:]+):.*",2);
						len = strlen(value)+1;
						if(!strncmp(value,hash->hash,len))
							yet_found = true;
					}
				}
				else
				{
					if(wpa!=NULL)
					{
						free((void *) value);
						value = regexpn(buffer,"\\$([^$]+)\\$([^:]+):.*",2);
						len = strlen(value)+1;
						if(!strncmp(value,wpa->essid,len))
							yet_found = true;
					}
				}
				free((void *) value);
			}
		}
		fgets(buffer,MAX_LINE,fd);
	}

	if(yet_found==true)
		return;
	else if(hash != NULL)
		fprintf(fd,"$%s$%s:%s\n",type_str[hash->type],hash->hash,hash->plain);
	else if(wpa != NULL)
		fprintf(fd,"$WPA$%s:%s\n",wpa->essid,wpa->key);
	else
	{
		fclose(fd);
		w_report_error("called with NULL argument.",file,line_no,caller,0,1,error);
	}

	fclose(fd);
	return;
}

void w_bind_thr(struct t_info *thread, _wpa *wpa, enum _type htype, _hash *hash, const char *file, int line_no)
{
	_hash *htmp=NULL;
	struct _hlist *hltmp=NULL,*hlold=NULL;
	struct _wlist *wltmp=NULL;

	pthread_mutex_lock(&pool_lock);

	if(hash != NULL)
	{
		if(thread->hlist ==NULL)
		{
			thread->hlist = w_malloc(sizeof(struct _hlist),__FILE__,__LINE__);
			thread->hlist->hash = hash;
		}
		else
		{
			for(hltmp=thread->hlist;hltmp->next!=NULL;hltmp=hltmp->next);
			hltmp = hltmp->next = w_malloc(sizeof(struct _hlist),__FILE__,__LINE__);
			hltmp->hash = hash;
		}
	}
	else if(wpa!=NULL)
	{
		if(thread->wlist == NULL)
		{
			thread->wlist = w_malloc(sizeof(struct _wlist),__FILE__,__LINE__);
			thread->wlist->wpa = wpa;
		}
		else
		{
			for(wltmp=thread->wlist;wltmp->next!=NULL;wltmp=wltmp->next);
			wltmp = wltmp->next = w_malloc(sizeof(struct _wlist),__FILE__,__LINE__);
			wltmp->wpa = wpa;
		}
	}
	else if(htype == UNKNOWN)
	{
		if(thread->hlist != NULL)
			for(hltmp=thread->hlist;hltmp!=NULL;hlold=hltmp,hltmp=hltmp->next,free(hlold));
		hltmp = thread->hlist = w_malloc(sizeof(struct _hlist),__FILE__,__LINE__);
		for(htmp=globals.hash_list;htmp!=NULL;htmp=htmp->next)
		{
			hltmp->hash = htmp;
			hltmp = hltmp->next = w_malloc(sizeof(struct _hlist),__FILE__,__LINE__);
		}
	}
	else if(htype > NONE && htype < UNKNOWN)
	{
		for(hltmp=thread->hlist;hltmp!=NULL;hlold=hltmp,hltmp=hltmp->next);
		for(htmp=globals.hash_list;htmp!=NULL;htmp=htmp->next)
			if(htmp->type == htype)
			{
				if(hlold==NULL) // first
					hltmp = thread->hlist = w_malloc(sizeof(struct _hlist),__FILE__,__LINE__);
				else
					hltmp = hlold->next = w_malloc(sizeof(struct _hlist),__FILE__,__LINE__);
				hlold = hltmp;
				hltmp->hash = htmp;
			}
	}
	else
	{
		pthread_mutex_unlock(&pool_lock);
		w_report_error("unexcepted call.",file,line_no,__func__,0,1,error);
	}

	pthread_mutex_unlock(&pool_lock);
	return;
}

void w_unbind_thr(struct t_info *thread)
{
	struct _hlist *hltmp=NULL,*hlold=NULL;
	struct _wlist *wltmp=NULL,*wlold=NULL;
	pthread_mutex_unlock(&pool_lock); // avoid deadlocks
	pthread_mutex_lock(&(pool_lock));
	for(hltmp=thread->hlist;hltmp!=NULL;hlold=hltmp,hltmp=hltmp->next,free(hlold));
	for(wltmp=thread->wlist;wltmp!=NULL;wlold=wltmp,wltmp=wltmp->next,free(wlold));
	thread->hlist = NULL;
	thread->wlist = NULL;
	pthread_mutex_unlock(&(pool_lock));
	return;
}

void w_unbind_h_w(_hash *hash, _wpa *wpa, const char *file, int line_no)
{
	struct t_info *ttmp=NULL;
	struct _hlist *hltmp=NULL,*hlold=NULL;
	struct _wlist *wltmp=NULL,*wlold=NULL;

	if(hash==NULL && wpa==NULL)
		w_report_error("unexcepted call.",file,line_no,__func__,0,1,error);

	pthread_mutex_lock(&(pool_lock));
	for(ttmp=globals.tpool;ttmp!=NULL;ttmp=ttmp->next)
	{
		if(ttmp->state != running && ttmp->state != waiting) // thread is already finished, don't check him
			continue;
		if(hash!=NULL)
			for(hlold=NULL,hltmp=ttmp->hlist;hltmp!=NULL;)
				if(hltmp->hash == hash)
				{
					if(hlold == NULL) // first
					{
						ttmp->hlist = hltmp->next;
						free((void *) hltmp);
						hltmp = ttmp->hlist;
					}
					else
					{
						hlold->next = hltmp->next;
						free((void *) hltmp);
						hltmp = hlold->next;
					}
				}
				else
				{
					hlold = hltmp;
					hltmp=hltmp->next;
				}
		if(wpa!=NULL)
			for(wlold=NULL,wltmp=ttmp->wlist;wltmp!=NULL;)
				if(wltmp->wpa == wpa)
				{
					if(wlold==NULL) // first
					{
						ttmp->wlist = wltmp->next;
						free((void *) wltmp);
						wltmp = ttmp->wlist;
					}
					else
					{
						wlold->next = wltmp->next;
						free((void *) wltmp);
						wltmp = wlold->next;
					}
				}
				else
				{
					wlold=wltmp;
					wltmp=wltmp->next;
				}
		if(ttmp->hlist==NULL && ttmp->wlist == NULL) // thread has nothing else to do, KILL him.
		{
			pthread_cancel(ttmp->thread);
			while(pthread_kill(ttmp->thread,0) == 0)
				usleep(10);
			ttmp->state = killed;
		}
	}
	pthread_mutex_unlock(&(pool_lock));
	return;
}

void w_add_hash(enum _type type,const char *hash_arg, const char *file, int line_no)
{
	char *hash=NULL;
	static unsigned int id = 0;
	_hash *tmp;


	if( hash_arg != NULL )
		hash = w_str2low(hash_arg,file,line_no);

	if( hash != NULL && type != NONE )
	{
		if(globals.hash_list!=NULL)
		{
			for(tmp=globals.hash_list;tmp->next!=NULL;tmp=tmp->next);
			tmp = tmp->next = (_hash *) w_malloc(sizeof(_hash),file, line_no);
		}
		else
		{
			tmp = globals.hash_list = (_hash *) w_malloc(sizeof(_hash),file, line_no);
		}
		tmp->next = NULL;
		tmp->type = type;
		tmp->hash = hash;
		tmp->plain = NULL;
		tmp->id = id;
		id++;
	}
	else if( hash != NULL && type == NONE )
	{
		// search the first hash-empty entry
		if(globals.hash_list!=NULL)
		{
			for(tmp=globals.hash_list;tmp->next != NULL && tmp->hash!=NULL ;tmp=tmp->next);
			// if there is no empty-hash entry
			// we create a new entry
			if(tmp->next == NULL && tmp->hash != NULL)
			{
				tmp = tmp->next = (_hash *) w_malloc(sizeof(_hash),file,line_no);
				tmp->next = NULL;
				tmp->type = NONE;
				tmp->plain = NULL;
				tmp->id = id;
				id++;
			}
		}
		else
		{
			tmp = globals.hash_list = (_hash *) w_malloc(sizeof(_hash),file,line_no);
			tmp->next = NULL;
			tmp->type = NONE;
			tmp->plain = NULL;
			tmp->id = id;
			id++;
		}
		tmp->hash = hash;
	}
	else if( hash == NULL && type != NONE )
	{
		//search the first empty-type entry
		if(globals.hash_list!=NULL)
		{
			for(tmp=globals.hash_list;tmp->next != NULL && tmp->type!=NONE ;tmp=tmp->next);
			// if there is no empty-type entry
			// we create a new entry
			if(tmp->next == NULL && tmp->type != NONE )
			{
				tmp = tmp->next = (_hash *) w_malloc(sizeof(_hash),file,line_no);
				tmp->next = NULL;
				tmp->hash = NULL;
				tmp->plain = NULL;
				tmp->id = id;
				id++;
			}
		}
		else
		{
			tmp = globals.hash_list = (_hash *) w_malloc(sizeof(_hash),file,line_no);
			tmp->next = NULL;
			tmp->hash = NULL;
			tmp->plain = NULL;
			tmp->id = id;
			id++;
		}
		tmp->type = type;
	}
	else
	{
		w_report_error("unexcepted call.",file,line_no,__func__,0,0,error);
		if(globals.log_level == debug)
		{
			snprintf(	globals.err_buff, MAX_BUFF, "\ttype:\t\"%s\"", type_str[type] );
			w_report_error(globals.err_buff,file,line_no,__func__,0,0,debug);

			if( hash_arg != NULL )
				snprintf(	globals.err_buff,MAX_BUFF,"\thash:\t\"%s\"",hash_arg);
			else
				snprintf(	globals.err_buff,MAX_BUFF,"\thash:\tNULL");
			w_report_error(globals.err_buff,file,line_no,__func__,0,0,debug);
		}
		w_report_error("quitting...",file,line_no,__func__,0,1,error);
	}
}

void w_del_hash(_hash *del_item, const char *file, int line_no)
{
	_hash *tmp;

	if(del_item == NULL)
		w_report_error("called with NULL pointer.",file,line_no,__func__,0,1,error);
	if(globals.hash_list==NULL)
		w_report_error("global hash_list is empty.",file,line_no,__func__,0,1,error);

	if(del_item != globals.hash_list)
	{
		for(tmp=globals.hash_list;tmp->next != NULL && tmp->next != del_item; tmp=tmp->next);

		if(tmp->next == NULL)
		{
			w_report_error("item to delete is not in hash_list.",file,line_no,__func__,0,0,warning);
			return;
		}
		tmp->next = del_item->next;
	}
	else
		globals.hash_list = del_item->next;

	free((void *) del_item->hash);
	free((void *) del_item);
	return;
}

void w_add_hash_plain(_hash *found_hash, char *hash, struct t_info *thread, char *plain, const char *file, int line_no)
{
	_hash *htmp=NULL;
	struct _hlist *hltmp=NULL;
	size_t len;
	char err_buff[MAX_LINE]; // use an internal error buffer since we can be called by threads

	if(plain == NULL)
		w_report_error("called with NULL argument.",file,line_no,__func__,0,0,error);
	else if(found_hash!=NULL)
		htmp=found_hash;
	else if(thread!=NULL && thread->hlist !=NULL && hash!=NULL) // search only in the binded hashes
	{
		len = strlen(hash)+1;
		for(hltmp=thread->hlist;hltmp!=NULL;hltmp=hltmp->next)
			if(!strncmp(hltmp->hash->hash,hash,len))
				break;
		if(hltmp!=NULL)
			htmp=hltmp->hash;
		else
			htmp=NULL;
	}
	else if(found_hash==NULL && hash!=NULL)
	{
		len = strlen(hash)+1;
		for(htmp=globals.hash_list;htmp!=NULL && strncmp(hash,htmp->hash,len);htmp=htmp->next);
	}

	if(htmp==NULL)
	{
		w_report_error("cannot find hash structure for the find one.",file,line_no,__func__,0,0,error);
		return;
	}
	pthread_mutex_lock(&(htmp->lock));
	len = strlen(plain)+1;
	if(strncmp(htmp->hash,w_digest((unsigned char *) plain,htmp->type,file,line_no),len))
	{
		w_report_error("bad password found!",file,line_no,__func__,0,0,verbose);
		snprintf(err_buff,MAX_LINE,"id  :\t%u",htmp->id);
		w_report_error(err_buff,file,line_no,__func__,0,0,verbose3);
		snprintf(err_buff,MAX_LINE,"type:\t%s",type_str[htmp->type]);
		w_report_error(err_buff,file,line_no,__func__,0,0,verbose2);
		snprintf(err_buff,MAX_LINE,"hash:\t%s",htmp->hash);
		w_report_error(err_buff,file,line_no,__func__,0,0,verbose);
		snprintf(err_buff,MAX_LINE,"bad pswd: \"%s\"",plain);
		w_report_error(err_buff,file,line_no,__func__,0,0,verbose);
	}
	else
	{
		if(htmp->plain != NULL)
		{
			if(strncmp(htmp->plain,plain,len))
			{
				w_report_error("password already found, but with different value.",file,line_no,__func__,0,0,warning);
				snprintf(err_buff,MAX_LINE,"id  :\t%u",htmp->id);
				w_report_error(err_buff,file,line_no,__func__,0,0,verbose2);
				snprintf(err_buff,MAX_LINE,"type:\t%s",type_str[htmp->type]);
				w_report_error(err_buff,file,line_no,__func__,0,0,verbose);
				snprintf(err_buff,MAX_LINE,"hash:\t%s",htmp->hash);
				w_report_error(err_buff,file,line_no,__func__,0,0,verbose);
				snprintf(err_buff,MAX_LINE,"old pswd: \"%s\"",htmp->plain);
				w_report_error(err_buff,file,line_no,__func__,0,0,info);
				snprintf(err_buff,MAX_LINE,"new pswd: \"%s\"",plain);
				w_report_error(err_buff,file,line_no,__func__,0,0,info);
				w_report_error("the new password text will be used.",file,line_no,__func__,0,0,verbose);
			}
			else
			{
				snprintf(err_buff,MAX_LINE,"password \"%s\" found again.",plain);
				w_report_error(err_buff,file,line_no,__func__,0,0,verbose2);
			}
			free((void *) htmp->plain);
			htmp->plain = w_malloc(len*sizeof(char),__FILE__,__LINE__);
			strncpy(htmp->plain,plain,len);
			unbind_hash(htmp);
		}
		else
		{
			w_report_error("found password!",file,line_no,__func__,0,0,info);
			snprintf(err_buff,MAX_LINE,"id  :\t%u",htmp->id);
			w_report_error(err_buff,file,line_no,__func__,0,0,verbose2);
			snprintf(err_buff,MAX_LINE,"type:\t%s",type_str[htmp->type]);
			w_report_error(err_buff,file,line_no,__func__,0,0,verbose);
			snprintf(err_buff,MAX_LINE,"hash:\t%s",htmp->hash);
			w_report_error(err_buff,file,line_no,__func__,0,0,info);
			snprintf(err_buff,MAX_LINE,"pswd:\t%s",plain);
			w_report_error(err_buff,file,line_no,__func__,0,0,info);
			htmp->plain = w_malloc(len*sizeof(char),__FILE__,__LINE__);
			strncpy(htmp->plain,plain,len);
			unbind_hash(htmp);
			hash_write_out(htmp);
		}
	}
	pthread_mutex_unlock(&(htmp->lock));
	return;
}

void print_hash_list()
{
	_hash *tmp=NULL;
	struct _wpa *wpa=NULL;
	unsigned int id_max;
	int type_max,hash_max,plain_max,len,i;
	void *limit[4];
	char line[MAX_BUFF],format[MAX_BUFF],*ptr,*end;


	if(globals.hash_list==NULL && globals.wpa_list == NULL)
		return;
	if(globals.hash_list!=NULL)
	{
		// set minimum values for correct formatting
		id_max = strlen("ID");
		type_max = strlen("TYPE");
		hash_max = strlen("HASH");
		plain_max = strlen("PLAIN TEXT");

		limit[0] = (void *) &id_max;
		limit[1] = (void *) &type_max;
		limit[2] = (void *) &hash_max;
		limit[3] = (void *) &plain_max;

		for(tmp=globals.hash_list;tmp != NULL; tmp=tmp->next)
		{
			if( ( tmp->id / (id_max * 10)) > 0)
				id_max = snprintf(NULL,0,"%d",tmp->id);
			if( tmp->hash != NULL && ( (len=strlen(tmp->hash)) > hash_max ) )
				hash_max = len;
			if( tmp->type != NONE && ( (len=strlen(type_str[tmp->type])) > type_max ) )
				type_max = len;
			if( tmp->plain != NULL && ( (len=strlen(tmp->plain)) > plain_max ) )
				plain_max = len;
		}

		// building line
		// "+-----+---------+----------------------------------------+---------------+"
		ptr=line;
		end= ptr + MAX_BUFF;
		*ptr = '+';
		ptr++;

		// use len as counter
		for(i=0;i<4;i++,*ptr='+',ptr++)
			for(len = 0; len < *((int *) limit[i]) && ptr < end;len++,ptr++)
				*ptr='-';
		*ptr='\n';
		ptr++;
		*ptr='\0';

		snprintf(format,MAX_BUFF,"|%-*s|%-*s|%-*s|%-*s|\n",id_max,"ID",type_max,"TYPE",hash_max,"HASH",plain_max,"PLAIN TEXT");
		printf("\n%s%s%s",line,format,line); // print head
		for(tmp=globals.hash_list;tmp!=NULL;tmp=tmp->next)
		{
			if(tmp->hash == NULL)
				ptr="";
			else
				ptr=tmp->hash;
			if(tmp->plain == NULL)
				end="";
			else
				end=tmp->plain;
			printf("|%-*u|%-*s|%-*s|%-*s|\n",id_max,tmp->id,type_max,type_str[tmp->type],hash_max,ptr,plain_max,end);
		}
		printf("%s",line);
	}

	if(globals.wpa_list!=NULL)
	{
		id_max = strlen("ID");
		hash_max = strlen("ESSID");
		plain_max = strlen("PASSPHRASE");

		limit[0] = (void *) &id_max;
		limit[1] = (void *) &hash_max;
		limit[2] = (void *) &plain_max;

		for(wpa=globals.wpa_list;wpa != NULL; wpa=wpa->next)
		{
			if( ( wpa->id / (id_max * 10)) > 0)
				id_max = log10(wpa->id);
			if( wpa->essid != NULL && ( (len=strlen(wpa->essid)) > hash_max ) )
				hash_max = len;
			if( wpa->key != NULL && ( (len=strlen(wpa->key)) > plain_max ) )
				plain_max = len;
		}

		// building line
		// "+-----+---------+----------------------------------------+---------------+"
		ptr=line;
		end= ptr + MAX_BUFF;
		*ptr = '+';
		ptr++;

		// use len as counter
		for(i=0;i<3;i++,*ptr='+',ptr++)
			for(len = 0; len < *((int *) limit[i]) && ptr < end;len++,ptr++)
				*ptr='-';
		*ptr='\n';
		ptr++;
		*ptr='\0';

		snprintf(format,MAX_BUFF,"|%-*s|%-*s|%-*s|\n",id_max,"ID",hash_max,"ESSID",plain_max,"PASSPHRASE");
		printf("\n%s%s%s",line,format,line);

		for(wpa=globals.wpa_list;wpa!=NULL;wpa=wpa->next)
		{
			if(wpa->essid==NULL)
				ptr="";
			else
				ptr=wpa->essid;
			if(wpa->key==NULL)
				end="";
			else
				end=wpa->key;
			printf("|%-*u|%-*s|%-*s|\n",id_max,wpa->id,hash_max,ptr,plain_max,end);
		}

		printf("%s",line);
	}
	return;
}

void print_type_list()
{
	int i;

	printf("Supported hash:\n");
	// exclude NONE and UNKNOWN
	for (i=1;i<(N_TYPE-1);i++)
		printf("\t%s\n",type_str[i]);
	destroy_all();
	exit(EXIT_SUCCESS);
	return;
}

char *find_file(const char *indirectory, const char *file)
{
	struct dirent *d;
	DIR *dir;
	char 	*file_path,
				*match,
				*directory;
	int found=0;

	file_path = malloc(NAME_MAX*sizeof(char));
	match = malloc(NAME_MAX*sizeof(char));
	directory = malloc(NAME_MAX*sizeof(char));
	strncpy(directory,indirectory,NAME_MAX);
	if(directory[strlen(indirectory)-1] != '/')
		strncat(directory,"/",1);
	strncpy(file_path,"",NAME_MAX);


	if( (dir = opendir(directory)) == NULL )
		return NULL;

	// first search in the top directory
	while( ( d = readdir(dir) ) != NULL && !found)
		if(	d->d_type != DT_DIR &&
				fnmatch(file,d->d_name,FNM_PATHNAME) == 0 )
		{
			snprintf(file_path,NAME_MAX,"%s%s",directory,d->d_name);
			found = 1;
		}


	closedir(dir);
	if(found)
	{
		free(match);
		free(directory);
		return file_path;
	}
	free((void *) file_path);
	dir = opendir(directory);

	// scan all subdirectory ( not "." and ".." )
	while( ( d = readdir(dir) ) != NULL && !found)
		if(	d->d_type == DT_DIR &&
				strncmp(d->d_name,".",NAME_MAX) &&
				strncmp(d->d_name,"..",NAME_MAX))
		{
			snprintf(match,NAME_MAX,"%s%s",directory,d->d_name);
			if( (file_path = find_file(match,file)) != NULL )
				found = 1;
		}

	free(match);
	free(directory);
	closedir(dir);

	if(found)
		return file_path;
	else
		return NULL;
}

char *w_get_full_path( const char *arg, const char *file,int line_no,const char *caller)
{
	char *fpath,*buffer;
	size_t len;
	bool found;

	fpath = buffer = NULL;
	found = false;

	if(arg==NULL)
		w_report_error("called with NULL argument.",file,line_no,__func__,0,1,error);
	else if((len=strlen(arg)) <= 0)
		w_report_error("try to resolve path for an empty string.",file,line_no,caller,0,0,warning);
	else if(len >= PATH_MAX)
	{
		w_report_error("!!! SECURITY BREACH !!!",file,line_no,caller,0,0,quiet);
		w_report_error("try to resolve path for a too large filename.",file,line_no,caller,0,1,error);
	}
	else
	{
		fpath = w_malloc((PATH_MAX+1)*sizeof(char),__FILE__,__LINE__);
		buffer = w_malloc((PATH_MAX+1)*sizeof(char),__FILE__,__LINE__);
		strncpy(buffer,arg,PATH_MAX);
		if(realpath(buffer,fpath) == NULL) // arg isn't a full path
		{
			if(getcwd(fpath,PATH_MAX) == NULL)
				w_report_error("getcwd()",file,line_no,caller,1,0,error);
			else
			{
				snprintf(buffer,PATH_MAX,"%s/%s",fpath,arg);
				snprintf(globals.err_buff,MAX_BUFF,"\"%s\"",buffer);
				if(realpath(buffer,fpath) == NULL)
				{
					w_report_error("while try to resolve absolute pathname:",file,line_no,caller,0,0,verbose);
					w_report_error(globals.err_buff,file,line_no,caller,1,0,error);
				}
				else
					found = true;
			}
		}
		else
			found = true;
	}

	if(found == true)
	{
		len = strlen(fpath)+1;
		strncpy(buffer,fpath,PATH_MAX);
		free((void *) fpath);
		fpath = malloc(len*sizeof(char));
		strncpy(fpath,buffer,len);
	}
	else if(fpath!=NULL)
	{
		free((void *) fpath);
		fpath = NULL;
	}

	if(buffer!=NULL)
		free((void *) buffer);

	return fpath;
}

char *find_genpmk(const char *essid)
{
	static char *wpa_rt_root=NULL;
	char *buffer,*file=NULL;

	if(essid == NULL)
	{
		if(wpa_rt_root!=NULL)
			free((void *) wpa_rt_root);
		return NULL;
	}
	else if(globals.rain == false || globals.rt_root == NULL)
		return NULL;
	else if(wpa_rt_root==NULL) // first call
	{
		if((buffer = find_file(globals.rt_root,"SSID.txt")) != NULL)
		{
			wpa_rt_root = w_get_full_path(dirname(buffer),__FILE__,__LINE__,__func__);
			free((void *) buffer);
		}
		else
		{
			w_report_error("cannot find wpa rainbowtable root.",__FILE__,__LINE__,__func__,0,0,verbose);
			w_report_error("maybe you don't have the \"SSID.txt\" file inside the wpa rainbowtable root.",__FILE__,__LINE__,__func__,0,0,verbose2);
		}
	}

	if((buffer = find_file(wpa_rt_root,essid)) != NULL)
	{
		file = w_get_full_path(buffer,__FILE__,__LINE__,__func__);
		free((void *) buffer);
	}
	else
		file = NULL;
	return file;
}

void w_add_wpa(char *essid, hccap_t *hccap, const char *file, int line_no)
{
	struct _wpa *iter=NULL,*prev=NULL;
	size_t elen;
	bool yet_loaded;

	if(essid == NULL)
		w_report_error("called with NULL argument.",file,line_no,__func__,0,0,error);
	else if((elen = strlen(essid)) == 0 || elen > 32)
	{
		snprintf(globals.err_buff,MAX_BUFF,"invalid essid \"%s\".",essid);
		w_report_error(globals.err_buff,file,line_no,__func__,0,0,warning);
	}
	else
	{
		elen++; // space for '\0'
		yet_loaded = false;
		for(iter=globals.wpa_list;iter!=NULL && strncmp(iter->essid,essid,elen);prev=iter,iter=iter->next);

		if(iter != NULL)
			yet_loaded = true;
		else if(prev == NULL) // wpa_list is empty
		{
			iter = globals.wpa_list = w_malloc(sizeof(struct _wpa),file,line_no);
			iter->id = 0;
		}
		else // no AP matched
		{
			prev->next = iter = w_malloc(sizeof(struct _wpa),file,line_no);
			iter->id = prev->id +1;
		}

		if( hccap != NULL)
		{
			if(iter->hccap==NULL)
				iter->hccap = w_malloc(sizeof(hccap_t),file,line_no);
			else
			{
				snprintf(globals.err_buff,MAX_BUFF,"reloading capture data for essid \"%s\".",iter->essid);
				w_report_error(globals.err_buff,file,line_no,__func__,0,0,verbose2);
				yet_loaded = true;
			}
			memcpy(iter->hccap,hccap,sizeof(hccap_t));
		}
		else
			iter->manual=true;

		if(iter->essid==NULL)
		{
			iter->essid = w_malloc(elen*sizeof(char),__FILE__,__LINE__);
			strncpy(iter->essid,essid,elen);
		}

		if(iter->genpmk == NULL)
			iter->genpmk = find_genpmk(iter->essid);

		if(yet_loaded == false)
		{
			snprintf(globals.err_buff,MAX_BUFF,"essid \"%s\" loaded.",iter->essid);
			w_report_error(globals.err_buff,file,line_no,__func__,0,0,info);
		}
	}

	return;
}

/* compute the keymic with supplied key, and compare with the found one.
 * part of this code is taken from aircrack-ng suite */
bool test_wpa_key(hccap_t *wpa, char *key)
{
	int i;
	uchar pmk[128];

	uchar pke[100];
	uchar ptk[80];
	uchar mic[20];

	/* pre-compute the key expansion buffer */
	memcpy( pke, "Pairwise key expansion", 23 );
	if( memcmp( wpa->mac2, wpa->mac1, 6 ) < 0 )	{
		memcpy( pke + 23, wpa->mac2, 6 );
		memcpy( pke + 29, wpa->mac1, 6 );
	} else {
		memcpy( pke + 23, wpa->mac1, 6 );
		memcpy( pke + 29, wpa->mac2, 6 );
	}
	if( memcmp( wpa->nonce1, wpa->nonce2, 32 ) < 0 ) {
		memcpy( pke + 35, wpa->nonce1, 32 );
		memcpy( pke + 67, wpa->nonce2, 32 );
	} else {
		memcpy( pke + 35, wpa->nonce2, 32 );
		memcpy( pke + 67, wpa->nonce1, 32 );
	}

	calc_pmk( key, wpa->essid, pmk );
	for (i = 0; i < 4; i++)
	{
		pke[99] = i;
		HMAC(EVP_sha1(), pmk, 32, pke, 100, ptk + i * 20, NULL);
	}

	if(wpa->keyver == 1)
		HMAC(EVP_md5(), ptk, 16, wpa->eapol, wpa->eapol_size, mic, NULL);
	else
		HMAC(EVP_sha1(), ptk, 16, wpa->eapol, wpa->eapol_size, mic, NULL);

	if(memcmp(mic,wpa->keymic,16) == 0)
		return true;
	return false;
}

void w_add_wpa_key(struct t_info *thread, char *key, const char *file, int line_no)
{
	struct _wlist *wltmp=NULL;
	size_t len;
	bool bad_key;

	if( key == NULL || thread==NULL)
		w_report_error("called with NULL argument.",file,line_no,__func__,0,0,error);
	else if(globals.wpa_list == NULL || thread->wlist == NULL)
		w_report_error("trying to add wpa key, but wpa_list is empty.",file,line_no,__func__,0,0,verbose);
	else if((len = strlen(key)) < 8 || len > 32 )
	{
		snprintf(globals.err_buff,MAX_BUFF,"invalid wpa key: \"%s\".",key);
		w_report_error(globals.err_buff,file,line_no,__func__,0,0,warning);
	}
	else
	{
		len++; // for comparing also the '\0'
		for(wltmp=thread->wlist;wltmp!=NULL;wltmp=wltmp->next)
		{
			bad_key=false;
			if(wltmp->wpa->key!=NULL)
				if(!strncmp(wltmp->wpa->key,key,len))
					continue;
				else
					bad_key=true; // old key were yet checked with test_wpa_key()
			else if(test_wpa_key(wltmp->wpa->hccap,key)==false)
				continue;

			if(bad_key==true)
			{
				w_report_error("found false positive.",file,line_no,__func__,0,0,verbose);
				snprintf(globals.err_buff,MAX_BUFF,"essid:\t\"%s\"",wltmp->wpa->essid);
				w_report_error(globals.err_buff,file,line_no,__func__,0,0,verbose3);
				snprintf(globals.err_buff,MAX_BUFF,"key  :\t\"%s\"",key);
				w_report_error(globals.err_buff,file,line_no,__func__,0,0,verbose2);
			}
			else
			{
				w_report_error("found wpa passphrase!",file,line_no,__func__,0,0,info);
				snprintf(globals.err_buff,MAX_BUFF,"id   :\t%u",wltmp->wpa->id);
				w_report_error(globals.err_buff,file,line_no,__func__,0,0,verbose2);
				snprintf(globals.err_buff,MAX_BUFF,"essid:\t\"%s\"",wltmp->wpa->essid);
				w_report_error(globals.err_buff,file,line_no,__func__,0,0,info);
				snprintf(globals.err_buff,MAX_BUFF,"key  :\t\"%s\"",key);
				w_report_error(globals.err_buff,file,line_no,__func__,0,0,info);
				pthread_mutex_lock(&pool_lock);
				wltmp->wpa->key = w_malloc(len*sizeof(char),file,line_no);
				strncpy(wltmp->wpa->key,key,len);
				pthread_mutex_unlock(&pool_lock);
				unbind_wpa(wltmp->wpa);
				wpa_write_out(wltmp->wpa);
			}
		}
	}
	return;
}

void free_wpa(struct _wpa *delete)
{
	if(delete->essid != NULL)
		free((void *) delete->essid);
	if(delete->key != NULL)
		free((void *) delete->key);
	if(delete->hccap !=NULL)
		free((void *) delete->hccap);
	if(delete->genpmk!=NULL)
		free((void *) delete->genpmk);
	free((void *) delete);
	return;
}

char *w_fgets_fix(char *string, const char *file, int line_no, const char *caller)
{
	char *ptr;

	if(string == NULL)
		w_report_error("called with NULL pointer.",file,line_no,caller,0,1,error);

	for(ptr=string;*ptr!='\n'&&*ptr!='\0';ptr++);
	*ptr='\0';
	return string;
}

#ifdef HAVE_LIBMAGIC
const char *w_get_mime(const char *arg, const char *file, int line_no)
{
	const char *buff;
	static char *magic_full=NULL;
	size_t len;
	magic_t magic_cookie;

	if(arg == NULL)
		free(magic_full);
	else if ((magic_cookie = magic_open(MAGIC_MIME) ) == NULL)
		w_report_error("unable to initialize magic library.",__FILE__,__LINE__,__func__,0,1,error);
	else if (magic_load(magic_cookie, NULL) != 0)
	{
		magic_close(magic_cookie);
		snprintf(globals.err_buff,MAX_BUFF,"cannot load magic database - %s .",magic_error(magic_cookie));
		w_report_error(globals.err_buff,__FILE__,__LINE__,__func__,0,1,error);
	}
	else
	{
		buff = magic_file(magic_cookie, arg);
		len = strlen(buff);
		magic_full = realloc(magic_full,(len+1)*sizeof(char));
		strncpy(magic_full,buff,len);
		magic_full[len] = '\0';
		magic_close(magic_cookie);
	}
	return (const char*) magic_full;
}
#endif

void w_argcpy(const char **dst, const char *arg, size_t max_len, const char *func, const char *file,int line_no)
{
	char *tmp;
	size_t arg_len;

	if(arg == NULL)
		w_report_error("called with NULL argument.",file,line_no,__func__,0,1,error);
	else if( (arg_len=strlen(arg)) > max_len )
	{
		snprintf(globals.err_buff,MAX_BUFF,"argument for function \"%s\", is more then %d chars.",func,(int)max_len);
		w_report_error(globals.err_buff,file,line_no,__func__,0,0,error);
		w_report_error("security breach.",file,line_no,__func__,0,1,error);
	}
	else
	{
		tmp = malloc((arg_len+1)*sizeof(char));
		strncpy(tmp,arg,arg_len);
		tmp[arg_len] = '\0';
		if( *dst != NULL)
			free((void *) *dst);
		*dst = tmp;
	}

	return;
}

static void execv_cleanup(void *arg)
{
	struct _clean { struct t_info *self; int child_pid; } clean = *((struct _clean *) arg);
	if(clean.child_pid > 0) // into the parent process
		kill(clean.child_pid,9); // destroy child
	remove(clean.self->outfile); // we has been destroyed, so delete the output file.
	pthread_mutex_unlock(&(pool_lock)); // ensure to unlock global thread pool lockdown
}

static void *thread_execv(void *arg)
{
	int newout;
	const char *outfile;
	struct _clean { struct t_info *self; int child_pid; } mem;
	char *safe_env[] = { NULL };

	mem.child_pid = -1;
	mem.self = NULL;

	for(mem.self=globals.tpool;mem.self!=NULL;mem.self=mem.self->next)
		if(pthread_equal(mem.self->thread,pthread_self()))
			break;

	if(mem.self==NULL)
		w_report_error("cannot find myself into global threads pool.",__FILE__,__LINE__,__func__,0,1,debug);
	else if(mem.self->outfile == NULL) // no outfile specified, will redirect stdout to a file.
	{
		pthread_mutex_lock(&(pool_lock));
		outfile = mem.self->outfile = engine_malloc(L_tmpnam*sizeof(char),__FILE__,__LINE__);
		w_tmpnam((char *) outfile,__FILE__,__LINE__,__func__);
		pthread_mutex_unlock(&(pool_lock));
	}
	else // redirect stdout to "/dev/null" or "nul"
		outfile = NULL_FILE;

	pthread_cleanup_push(execv_cleanup, &mem);

	if(mem.self->state != running)
	{
		pthread_mutex_lock(&(pool_lock));
		mem.self->state = running;
		pthread_mutex_unlock(&(pool_lock));
	}

	fflush(stdout);

	if((mem.child_pid = fork()) == 0) // create a cpoy of this small thread, instead of a copy of the entire server.
	{
	 	newout = open(outfile, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP );
		dup2(newout,STDOUT_FILENO);
		// print program stderr only if globals.log_level == debug
		if(globals.log_level < debug)
			dup2(newout,STDERR_FILENO);
		close(newout);
		execve(*((char **) arg),(char **) arg, safe_env);
		pthread_exit(&(mem.child_pid)); // child must exit if execv fail.
	}
	else if(mem.child_pid == -1)
		w_report_error("cannot create process.",__FILE__,__LINE__,__func__,0,0,error);
	else
		waitpid(mem.child_pid,NULL,0);
	mem.child_pid = -1;
	pthread_mutex_lock(&pool_lock);
	mem.self->state = done;
	pthread_mutex_unlock(&pool_lock);
	pthread_cleanup_pop(0);
	pthread_exit(&(mem.child_pid));
}

static void wait_cleanup(void *arg)
{
	free(arg);
	pthread_mutex_unlock(&pool_lock);
}

static void *thread_wait(void *arg)
{
	struct { pthread_t wait; char **args; } *my_arg = arg;
	char **tmp_args;

	usleep(1000 * 1000); // initial wait is bigger
	pthread_cleanup_push(wait_cleanup,(void *) my_arg);
	pthread_mutex_lock(&pool_lock);
	while(pthread_kill(my_arg->wait,0)==0)
	{
		pthread_mutex_unlock(&pool_lock);
		usleep(10 * 1000);
		pthread_mutex_lock(&pool_lock);
	}
	pthread_mutex_unlock(&pool_lock);
	tmp_args = my_arg->args;
	pthread_cleanup_pop(1);
	thread_execv((void *) tmp_args);
	return NULL;
}

static void wait_first_cleanup(void *arg)
{
	pthread_mutex_unlock(&pool_lock);
}

static void *thread_wait_first(void *arg)
{
	int run_before,run_now;
	struct t_info *self=NULL,*ttmp=NULL;

	pthread_cleanup_push(wait_first_cleanup,NULL);

	pthread_mutex_lock(&pool_lock);
	// count how many threads are running
	for(run_before=0,ttmp=globals.tpool;ttmp!=NULL;ttmp=ttmp->next)
	{
		if(ttmp->state == running)
			run_before++;
		else if(pthread_equal(pthread_self(),ttmp->thread))
			self = ttmp;
	}

	pthread_mutex_unlock(&pool_lock);

	if(self==NULL)
		w_report_error("cannot find myself in the thread pool.",__FILE__,__LINE__,__func__,0,1,error);

	run_now=run_before;

	usleep(100 * 1000);

	while(run_now>=run_before)
	{
		pthread_mutex_unlock(&pool_lock);
		usleep(10 * 1000);
		pthread_mutex_lock(&pool_lock);
		for(run_now=0,ttmp=globals.tpool;ttmp!=NULL;ttmp=ttmp->next)
			if(ttmp->state == running)
				run_now++;
	}
	self->state = running;
	pthread_mutex_unlock(&pool_lock);
	pthread_cleanup_pop(0);
	thread_execv(arg);
	pthread_exit(&self);
}

struct t_info *w_prog_call(char **args, char *outfile, struct t_info *wait, const char *file, int line_no)
{
	int num,run;
	static int cores=-1;
	struct { pthread_t wait; char **args; } *wait_args;
	struct t_info *ttmp=NULL,*told=NULL;

	if(cores==-1) // first call
		cores = get_n_cpus();
	pthread_mutex_lock(&pool_lock);

	for(run=num=0,ttmp=globals.tpool;ttmp!=NULL;num++,told=ttmp,ttmp=ttmp->next)
		if(ttmp->state == running)
			run++;

	if(num>=MAX_THREADS)
	{
		w_report_error("max number of threads reached.",file,line_no,__func__,0,0,error);
		pthread_mutex_unlock(&pool_lock);
		return NULL;
	}
	else if(told==NULL) // this is the first thread
		globals.tpool = ttmp = w_malloc(sizeof(struct t_info),__FILE__,__LINE__);
	else
		ttmp = told->next = w_malloc(sizeof(struct t_info),__FILE__,__LINE__);

	ttmp->bin = *args;
	ttmp->outfile = outfile;

	if(wait==NULL)
	{
		if(run < cores)
		{
			ttmp->state = running;
			pthread_create(&(ttmp->thread),NULL,thread_execv, (void *) args);
		}
		else
		{
			ttmp->state = waiting;
			pthread_create(&(ttmp->thread), NULL, thread_wait_first, (void *) args);
		}
	}
	else
	{
		ttmp->state = waiting;
		// that memory location will freed by the thread when it have finish to copy the pointers
		wait_args = w_malloc(sizeof(pthread_t) + sizeof(char **),__FILE__,__LINE__);
		wait_args->wait = wait->thread;
		wait_args->args = args;
		pthread_create(&(ttmp->thread),NULL,thread_wait,(void *) wait_args);
	}
	pthread_mutex_unlock(&pool_lock);
	return ttmp;
}

static size_t memory_writer(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct _mem
	{
		char *memory;
		size_t size;
	} *mem = (struct _mem *)userp;

	while((mem->memory = realloc(mem->memory, mem->size + realsize + 1)) == NULL && errno == EINPROGRESS )
		usleep(10);
	if (mem->memory == NULL)
		w_report_error("memory_writer",__FILE__,__LINE__,__func__,1,1,error);

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

odb_t *w_add_odb_t( odb_t *list, const char *arg, int entry)
{
	odb_t *tmp;
	const static size_t odb_t_len = sizeof(odb_t);
	size_t arg_len;
	char *ptr,*buff;
	static const char *clean_patrn = "([^ \t]+([ \t]+[^ \t]+)*)"; // remove spaces from right and left

	tmp = list;

	if(arg == NULL)
		snprintf(globals.err_buff,MAX_BUFF,"called with NULL argument.");
	else if(entry > (MAX_ODB_T + ODB_HEAD ))
		snprintf(globals.err_buff,MAX_BUFF,"too much tuples.");
	else if((arg_len=strlen(arg)) == 0)
		snprintf(globals.err_buff,MAX_BUFF,"line is empty.");
	else if((ptr = strchr(arg,'=')) == NULL)
		snprintf(globals.err_buff,MAX_BUFF,"no '=' symbol in entry #%d",entry);
	else
	{
		if(tmp == NULL)
			tmp = list = w_malloc(odb_t_len,__FILE__,__LINE__);
		else
		{
			for(tmp=list;tmp->next!=NULL;tmp=tmp->next);
			tmp=tmp->next=w_malloc(odb_t_len,__FILE__,__LINE__);
			tmp->next = NULL;
		}
		buff = w_malloc((arg_len+1) * sizeof(char),__FILE__,__LINE__);
		strncpy(buff,arg,(ptr - arg));
		buff[ptr - arg] = '\0';
		tmp->name = regexp(buff,clean_patrn);

		ptr++;
		strncpy(buff,ptr,(arg_len - (ptr - arg)));
		buff[arg_len - (ptr - arg)] = '\0';
		tmp->value = regexp(buff,clean_patrn);
		free((void *) buff);
	}
	return list;
}

odb_type *w_add_odb_type(odb_type *list, char *arg)
{
	odb_type *tmp=NULL;
	enum _type t;
	size_t len;
	char *equal,*buff,*buff2;
	static const char *clean_patrn = "([^ \t]+([ \t]+[^ \t]+)*)"; // remove spaces from right and left

	buff=buff2=NULL;
	if(arg != NULL)
	{
		len = strlen(arg);
		if(len>0)
		{
			len++;
			buff = regexp(arg,clean_patrn);
			if(buff!=NULL)
			{
				if((equal = strchr(buff,'=')) == NULL || (buff2 = regexp(equal+1,clean_patrn)) !=NULL)
				{
					if(equal!=NULL)
						*equal = '\0';
					for(t=NONE+1;t<UNKNOWN;t++)
						if(!strncmp(type_str[t],buff,len))
							break;
					if(t!=UNKNOWN)
					{
						if(list == NULL)
							tmp = list = w_malloc(sizeof(odb_type),__FILE__,__LINE__);
						else
						{
							for(tmp=list;tmp->next!=NULL;tmp=tmp->next);
							tmp = tmp->next = w_malloc(sizeof(odb_type),__FILE__,__LINE__);
						}
						tmp->next = NULL;
						tmp->value = NULL;
						tmp->type = t;

						if(equal != NULL)
							tmp->value = buff2;
					}
					else
						snprintf(globals.err_buff,MAX_BUFF,"type \"%s\" not supported.",arg);
				}
				else
					snprintf(globals.err_buff,MAX_BUFF,"invalid value for type %s at entry #2.",arg);
			}
			else
				strncpy(globals.err_buff,"void type at entry #2.",MAX_BUFF);
		}
		else
			strncpy(globals.err_buff,"called with emtpy argument at entry #2.",MAX_BUFF);
	}
	else
		strncpy(globals.err_buff,"called with NULL argument at entry #2.",MAX_BUFF);

	if(tmp!=NULL)
	{
		if(tmp->value==NULL && buff2 != NULL)
			free((void *) buff2);
	}
	else if(buff2!=NULL)
		free((void *) buff2);
	if(buff!=NULL)
		free((void *) buff);


	return list;
}

/* max_len should be the size of *str char array, otherwise BUFFER OVERFLOW will come
 * this version perform only one substitution for ODB_*  */
void w_odb_sub_str(char *str, odb_type *type, _hash *hash, size_t max_len, const char *file, int line_no)
{
	char *buff,*to_free,*start;

	if(str==NULL || type == NULL || hash == NULL || max_len == 0)
		w_report_error("called with NULL argument.",file,line_no,__func__,0,1,error);
	buff = w_malloc(max_len*sizeof(char),__FILE__,__LINE__);
	if((start = strstr(str,ODB_HASH_UP)) != NULL)
	{
		to_free = w_str2up(hash->hash,__FILE__,__LINE__);
		snprintf(buff,max_len,"%.*s%s%s",(int) (start-str),str,to_free,start+strlen(ODB_HASH_UP));
		free((void *) to_free);
		strcpy(str,buff);// size is check before with snprintf(str,-> max_len <-
	}
	if((start = strstr(str,ODB_HASH_DN))!=NULL)
	{
		snprintf(buff,max_len,"%.*s%s%s",(int) (start-str),str,hash->hash,start+strlen(ODB_HASH_DN));//hash->hash is yet lowercase
		strcpy(str,buff);
	}
	if(type->value != NULL) // use custom defined type substitition
	{
		if((start = strstr(str,ODB_TYPE_UP)) != NULL || (start = strstr(str,ODB_TYPE_DN))!=NULL)
		{
			snprintf(buff,max_len,"%.*s%s%s",(int) (start-str),str,type->value,start+strlen(ODB_TYPE_DN));
			strcpy(str,buff);
		}
	}
	else
	{
		if((start = strstr(str,ODB_TYPE_UP))!=NULL)
		{
			snprintf(buff,max_len,"%.*s%s%s",(int) (start-str),str,type_str[type->type],start+strlen(ODB_TYPE_UP));
			strcpy(str,buff);
		}
		if((start=strstr(str,ODB_TYPE_DN))!=NULL)
		{
			to_free = w_str2low(type_str[type->type],__FILE__,__LINE__);
			snprintf(buff,max_len,"%.*s%s%s",(int) (start-str),str,to_free,start+strlen(ODB_TYPE_DN));
			free((void *) to_free);
			strcpy(str,buff);
		}
	}
	free((void *) buff);
	return;
}

void free_odb(odb *record)
{
	odb_t *t_tmp,*t_old;
	odb_type *tp_tmp,*tp_old;

	if(record->host!=NULL)
		free((void *) record->host);
	if(record->file!=NULL)
		free((void *) record->file);
	if(record->patrn!=NULL)
		free((void *) record->patrn);
	if(record->detected!=NULL)
		free((void *) record->detected);
	for(t_tmp=record->tuples;t_tmp!=NULL;)
	{
		t_old=t_tmp;
		t_tmp=t_old->next;
		if(t_old->name != NULL)
			free((char *) t_old->name);
		if(t_old->value != NULL)
			free((char *) t_old->value);
		free(t_old);
	}
	for(tp_tmp=record->types;tp_tmp!=NULL;)
	{
		tp_old=tp_tmp;
		tp_tmp=tp_old->next;
		if(tp_old->value != NULL)
			free((void *) tp_old->value);
		free(tp_old);
	}
	free(record);
	return;
}

const char *w_make_hash_file( enum _type type, const char *file, int line_no, const char *caller)
{
	struct my_hash { char *hash; struct my_hash *next; } *list=NULL, *iter=NULL, *old = NULL;
	struct my_tmp {char *name; struct my_tmp *next; } *tmp_iter=NULL, *tmp_old=NULL;
	static struct my_tmp *tmp_db=NULL;
	char *tmp_name;
	struct _hash *htmp=NULL;
	FILE *fp;

	if(type == NONE) // remove temporary files and free tmp_db.
	{
		for(tmp_iter=tmp_db;tmp_iter!=NULL;tmp_old=tmp_iter,tmp_iter=tmp_iter->next,free((void *) tmp_old))
			if(tmp_iter->name!=NULL)
			{
				if(remove(tmp_iter->name) != 0)
					w_report_error("unable to remove temporary file.",__FILE__,__LINE__,__func__,0,0,error);
				free((void *) tmp_iter->name);
			}
		return NULL;
	}

	// find the first match
	for(htmp=globals.hash_list;htmp!=NULL;htmp=htmp->next)
		if((htmp->type == type || type == UNKNOWN) && htmp->plain == NULL)
			break;

	if(htmp==NULL)
		return NULL;

	iter = list = w_malloc(sizeof(struct my_hash),__FILE__,__LINE__);
	iter->hash = htmp->hash;
	iter->next = NULL;

	// fill list with matched hash.
	for(htmp=htmp->next;htmp != NULL; htmp=htmp->next)
		if((htmp->type == type || type == UNKNOWN) && htmp->plain == NULL)
		{
			iter = iter->next = w_malloc(sizeof(struct my_hash),__FILE__,__LINE__);
			iter->hash = htmp->hash;
			iter->next = NULL;
		}

	fp = NULL;
	tmp_name = w_malloc((L_tmpnam+1)*sizeof(char),__FILE__,__LINE__);
	w_tmpnam(tmp_name,file,line_no,__func__);
	if((fp = fopen(tmp_name,"w")) == NULL)
		w_report_error("unable to create temporary file.",file,line_no,caller,0,0,error);
	else
	{
		for(iter=list;iter!= NULL;free(old))
		{
			fprintf(fp,"%s\n",iter->hash);
			old = iter;
			iter = iter->next;
		}
		fclose(fp);
		if(tmp_db == NULL)
			tmp_iter = tmp_db = w_malloc(sizeof(struct my_tmp),__FILE__,__LINE__);
		else
		{
			for(tmp_iter=tmp_db;tmp_iter->next!=NULL;tmp_old=tmp_iter,tmp_iter=tmp_iter->next);
			tmp_iter = tmp_iter->next = w_malloc(sizeof(struct my_tmp),__FILE__,__LINE__);
		}
		tmp_iter->next = NULL;
		tmp_iter->name = tmp_name;
		return (const char *) tmp_name;
	}

	if(tmp_name != NULL)
		free(tmp_name);
	for(iter=list;iter!=NULL;free(old))
	{
		old = iter;
		iter = iter->next;
	}

	return NULL;
}

const char *w_make_wordlist( enum _word_mode mode, const char *file, int line_no)
{
	static char *word_cpu=NULL,*word_gpu=NULL;
	char line[MAX_LINE];
	FILE *cfp,*gfp,*wfp;
	bool skip_line;
	unsigned int cln,gln,lines;
	size_t len;

	if(mode == delete)
	{
		if(word_cpu!=NULL)
		{
			if(remove(word_cpu) == -1)
				w_report_error(word_cpu,file,line_no,__func__,1,0,error);
			free((void *) word_cpu);
			word_cpu = NULL;
		}
		if(word_gpu!=NULL)
		{
			if(remove(word_gpu) == -1)
				w_report_error(word_gpu,file,line_no,__func__,1,0,error);
			free((void *) word_gpu);
			word_gpu = NULL;
		}
	}
	else if(globals.wordlist==NULL)
		w_report_error("no wordlist to parse.",file,line_no,__func__,0,0,error);
	else if(mode == compute && word_cpu == NULL && word_gpu == NULL)
	{
		word_cpu = malloc(L_tmpnam*sizeof(char));
		word_gpu = malloc(L_tmpnam*sizeof(char));

		w_tmpnam(word_cpu,file,line_no,__func__);
		w_tmpnam(word_gpu,file,line_no,__func__);

		if((cfp = fopen(word_cpu,"w")) == NULL)
			w_report_error(word_cpu,file,line_no,__func__,1,1,error);
		if((gfp = fopen(word_gpu,"w")) == NULL)
			w_report_error(word_gpu,file,line_no,__func__,1,1,error);
		wfp = fopen(globals.wordlist,"r"); // parser_wordlist has yet check this before.
		cln=gln=lines=0;
		skip_line = false;
		fgets(line,MAX_LINE,wfp);
		while(!feof(wfp))
		{
			lines++;
			len = strlen(line);
			if(skip_line == false && (len==0 || (len == 1 && line[len-1] == '\n')))
			{
				snprintf(globals.err_buff,MAX_BUFF,"in \"%s\" line #%d is empty.",basename((char *) globals.wordlist),lines);
				w_report_error(globals.err_buff,__FILE__,__LINE__,__func__,0,0,verbose);
			}
			else if(line[len-1] != '\n' && skip_line == false)
			{
				snprintf(globals.err_buff,MAX_BUFF,"in \"%s\" line #%d is longer then #%d characters and will be skipped.",basename((char *) globals.wordlist),lines,MAX_LINE);
				w_report_error(globals.err_buff,__FILE__,__LINE__,__func__,0,0,warning);
				skip_line = true;
			}
			else if(line[len-1] == '\n' && skip_line == true)
				skip_line = false;
			else if(skip_line == false)
			{
				if(gln > (WORK_RATIO * cln))
				{
					fprintf(cfp,"%s",line);
					cln++;
				}
				else
				{
					fprintf(gfp,"%s",line);
					gln++;
				}
			}
			fgets(line,MAX_LINE,wfp);
		}
		fclose(wfp);
		fclose(cfp);
		fclose(gfp);
	}
	else if( mode == cpu )
		return word_cpu;
	else if( mode == gpu )
		return word_gpu;
	else
		w_report_error("unexcepted call.",file,line_no,__func__,0,0,error);

	return NULL;
}

void destroy_all()
{
	_hash *tmp=NULL,*old=NULL;
	odb *otmp=NULL,*oold=NULL;
	struct t_info *ttmp=NULL,*told=NULL;
	_wpa *wold=NULL,*wtmp=NULL;
	char **ptr;
	int i,n_bins,n_sleep=0;
	bool force_shutdown = false;

	//use i for store maximum loop count
	i = TKILL_TIMEOUT * 100;
	// first of all kill our childs
	for(ttmp=globals.tpool;ttmp!=NULL;)
	{
		if(ttmp->outfile!=NULL)
			remove(ttmp->outfile);
		w_unbind_thr(ttmp);
		if(ttmp->thread!=0)
		{
			for(pthread_cancel(ttmp->thread);pthread_kill(ttmp->thread,0)==0 && n_sleep < i;n_sleep++)
				usleep(10);
			if(n_sleep == i)
			{
				snprintf(globals.err_buff,MAX_BUFF,"could not kill child with LWPID=%lu.",(unsigned long int) ttmp->thread);
				w_report_error(globals.err_buff, __FILE__, __LINE__, __func__, 0, 0, error);
				force_shutdown = true;
			}
			else
				pthread_join(ttmp->thread,NULL);
		}
		told=ttmp;
		ttmp=ttmp->next;
		free((void *) told);
	}

	engine_del_opt();

	n_bins = sizeof(struct _bins)/sizeof(char*);

	// destroy (char *) if they exist
	if(globals.err_buff!= NULL)
		free((void *) globals.err_buff);
	if(globals.essid != NULL)
		free((void *) globals.essid);
	if(globals.rt_root != NULL)
		free((void *) globals.rt_root);
	if(globals.outfile != NULL)
		free((void *) globals.outfile);
	if(globals.wordlist != NULL)
		free((void *) globals.wordlist);
	if(globals.hccap != NULL)
	{
		if(remove(globals.hccap) != 0)
			w_report_error(globals.hccap,__FILE__,__LINE__,__func__,1,0,error);
		free((void *) globals.hccap);
	}
	if(globals.pcap != NULL)
	{
		if(remove(globals.pcap) != 0)
			w_report_error(globals.pcap,__FILE__,__LINE__,__func__,1,0,error);
		free((void *) globals.pcap);
	}

	for(i=0, (ptr = (char**) &(globals.bins));
			i<n_bins; i++ , ptr++ )
		if(*ptr != NULL)
			free(*ptr);

	// destroy hash_list
	for(tmp=globals.hash_list;tmp != NULL;)
	{
		old = tmp;
		tmp=tmp->next;
		if(old->hash != NULL)
			free((void *) old->hash);
		if(old->plain != NULL)
			free((void *) old->plain);
		free(old);
	}

	if(globals.odb!= &internal_odb)
		for(otmp=globals.odb;otmp!=NULL;otmp=otmp->next,free_odb(oold))
			oold=otmp;

	for(wtmp=globals.wpa_list;wtmp!=NULL;wtmp=wtmp->next,free_wpa(wold))
		wold=wtmp;
#ifdef HAVE_LIBMAGIC
	w_get_mime(NULL,__FILE__,__LINE__);
#endif
	w_make_wordlist(delete,__FILE__,__LINE__);
	w_make_hash_file(NONE,__FILE__,__LINE__,__func__);
	find_genpmk(NULL);

	//reset globals in order to prevent double frees if recalled
	i = globals.log_level;
	memset(&globals,0,sizeof(struct _globals));
	globals.log_level = i;

	//if a child cannot be killed, suicide
	if(force_shutdown == true)
	{
		w_report_error("karakiri for make sure killing childs.",__FILE__,__LINE__,__func__,0,0,verbose);
		raise(SIGTERM); // kaboom
	}
	return;
}

void signal_handler(int signum)
{
	w_report_error("recieved SIGINT.",__FILE__,__LINE__,__func__,0,1,error);
	//if we are here after a 'fatal' report something orrible is happend, so suicide.
	raise(SIGTERM);
}

#include "common_macro.h"