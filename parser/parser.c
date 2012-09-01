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

#include "parser.h"

extern struct _globals globals;

enum _type parser_type(const char *arg, const char *file,int line_no)
{
	char *str;
	enum _type i;
	size_t len;

	if(arg==NULL)
		w_report_error("called with NULL argument.",file,line_no,__func__,0,1,error);

	// convert type to uppercase
	str = str2up(arg);
	len = strlen(arg);

	// search type in type_str
	for( i=NONE+1; i<UNKNOWN; i++)
		if( len == strlen(type_str[i]) && !strncmp(type_str[i],str,len))
			break;
	free((void *) str);
	if(i<UNKNOWN)
		return i;
	report(warning,"type \"%s\" is unknown.",arg);
	return UNKNOWN;
}

const char *parser_hash(enum _type type, const char* arg, const char *file, int line_no)
{
	char *str;
	enum _type i;

	if(arg == NULL)
		w_report_error("called with NULL argument.",file,line_no,__func__,0,1,error);

	if(type > NONE && type < UNKNOWN)
		str = regexp(arg,type_rgx[type]);
	else
		//try all regex against given hash
		for(i=NONE+1;i<UNKNOWN && ( str = regexp(arg,type_rgx[i]) ) == NULL ;i++);

	if ( str == NULL )
	{
		w_report_error("bad hash",file,line_no,__func__,0,0,verbose2);
		report(verbose2,"\thash: %s",arg);
		report(verbose3,"\ttype: %s",type_str[type]);
	}

	return str;
}

void parser_hash_list(const char *file, int line_no)
{
	_hash *tmp,*old;
	enum _type cur_type;
	size_t len;
	FILE *fout;
	char buffer[MAX_LINE],*value,*hashtest;

	if(globals.hash_list == NULL)
		return;

	for(tmp=globals.hash_list;tmp!=NULL;)
	{
		hashtest = NULL;
		if( tmp->type >= UNKNOWN || tmp->type <= NONE )
		{
			if(tmp->hash != NULL)
			{
				report(info,"unknown type for hash \"%s\" .",tmp->hash);
				snprintf(	globals.err_buff,MAX_BUFF,"hash: \"%s\" deleted.",tmp->hash);
			}
			else
			{
				report(info,"missing hash for entry #%u .", tmp->id);
				snprintf(	globals.err_buff,MAX_BUFF,"entry #%u deleted.",tmp->id);
			}
			old=tmp;
			tmp = tmp->next;
			w_del_hash(old,file,line_no);
			w_report_error(globals.err_buff,file,line_no,__func__,0,0,warning);
		}
		else if( (hashtest = (char *) parser_hash(tmp->type,tmp->hash,file,line_no)) == NULL )
		{
			report(info,"hash \"%s\" is not in \"%s\" format.",tmp->hash,type_str[tmp->type]);
			report(warning,"hash \"%s\" deleted.",tmp->hash);
			old=tmp;
			tmp = tmp->next;
			w_del_hash(old,file,line_no);
		}
		else
		{
			free((void *) hashtest);
			tmp = tmp->next;
		}
	}

	if(globals.outfile!=NULL && (fout = fopen(globals.outfile,"r")) != NULL) // check for hash that are already found
	{
		fgets(buffer,MAX_LINE,fout);
		while(!feof(fout))
		{
			len = strlen(buffer);
			if(buffer[len-1] == '\n')
			{
				value = regexpn(buffer,"\\$([^$]+)\\$([^:]+):(.*)",1);
				if(value != NULL)
				{
					if(strncmp(value,"WPA",4) && (cur_type=P_type(value))!=UNKNOWN)
					{
						free((void *) value);
						value = regexpn(buffer,"\\$([^$]+)\\$([^:]+):(.*)",2);
						len = strlen(value)+1;
						for(tmp=globals.hash_list;tmp!=NULL;tmp=tmp->next)
							if(tmp->type == cur_type && !strncmp(tmp->hash,value,len))
							{
								report(verbose2,"hash \"%s\" already found.",tmp->hash);
								tmp->plain = regexpn(buffer,"\\$([^$]+)\\$([^:]+):(.*)",3);
								break;
							}
					}
					free((void *) value);
				}
			}
			fgets(buffer,MAX_LINE,fout);
		}
		fclose(fout);
	}

	return;
}

void parser_infile(const char *infile)
{
	FILE *fin;
	char line[MAX_LINE],buffer[MAX_LINE],*type,*path,*prehash;
	const char *hash,*patrn="^\\$([a-zA-Z0-9]+)\\$([a-fA-F0-9]+)$";
	enum _type my_type;
	int inline_no;
	bool first_error;
	struct stat infile_stat; // were you known that fopen() can open directories ?? uff!

	path = type = prehash = NULL; // if a stat error occours we need to be sure that char pointers are NULL
	hash = NULL;
	if(infile == NULL)
		report_error("called with NULL argument.",0,1,error);
	else if(stat(infile, &infile_stat) != 0)
		report_error(infile,1,0,error);
	else if(!S_ISREG(infile_stat.st_mode))
		report(error,"\"%s\" is not a regular file.",infile);
	else if(	(path =	get_full_path(infile)) == NULL ||
						access(path,R_OK) ||
						(fin = fopen(path,"r")) == NULL
				 )
		report_error(infile,1,0,error);
	else
	{
		inline_no = 0;
		first_error = true;
		my_type = UNKNOWN;

		fgets( line, MAX_LINE, fin);
		while( !feof(fin) )
		{
			inline_no++;

			fgets_fix(line);
			hash = type = NULL;
			buffer[0] = '\0';
			if((type = regexpn(line,patrn,1)) == NULL || (prehash = regexpn(line,patrn,2)) == NULL)
				strncpy(buffer,"format error.",MAX_LINE);
			else if( (my_type = P_type(type) ) == UNKNOWN )
				strncpy(buffer,"unknown type.",MAX_LINE);
			else if((hash = P_hash(my_type,prehash)) == NULL)
				snprintf(buffer,MAX_LINE,"hash \"%s\" not in \"%s\" format.",prehash,type_str[my_type]);
			else
				add_hash(my_type,hash);
			fgets( line, MAX_LINE, fin);

			if(buffer[0] != '\0')
			{
				if(first_error==true)
				{
					report(warning,"in file \"%s\":",infile);
					first_error=false;
				}
				report(warning,"\tat line #%d: %s",inline_no,buffer);
			}

			if(type!=NULL)
				free((void *) type);
			if(prehash!=NULL)
				free((void *) prehash);
			if(hash!=NULL)
				free((void *) hash);
		}
		fclose(fin);
	}

	if(path!=NULL)
		free(path);

	return;
}

void parser_outfile(const char *arg)
{
	struct stat out_stat;
	char *path=NULL;
	FILE *fout;

	if(arg == NULL)
		report_error("called with NULL argument.",0,1,error);
	else if(stat(arg,&out_stat) == 0)
	{
		if(S_ISREG(out_stat.st_mode))
		{
			path = get_full_path(arg);
			if(access(path,W_OK) == 0)
				argcpy(&(globals.outfile),path,strlen(path)+1);
			else
				report_error(path,1,0,error);
		}
		else
			report(error,"file \"%s\" isn't a regular file.",arg);
	}
	else if(errno == ENOENT)
	{
		if((fout = fopen(arg,"w+")) != NULL)
		{
			fclose(fout);
			parser_outfile(arg); // restart
		}
		else
			report_error(arg,1,0,error);
	}
	else
		report_error(arg,1,0,error);

	if(path!=NULL)
		free((void *) path);

	return;
}

void parser_essid(const char *arg, const char *file, int line_no)
{
	if(arg == NULL)
		w_report_error("called with NULL argument.",file,line_no,__func__,0,1,error);
	else
		add_wpa((char *) arg,NULL);
	return;

}

void parser_rt_root(const char *arg, const char *file, int line_no)
{
	struct stat rt_root_stat;
	struct _wpa *iter=NULL;

	if(arg == NULL)
		w_report_error("called with NULL argument.",file,line_no,__func__,0,1,error);
	else if(stat(arg,&rt_root_stat) != 0) // if couldn't get argument stats
		w_report_error(arg,file,line_no,__func__,1,0,error);
	else if(!S_ISDIR(rt_root_stat.st_mode)) // if isn't a directory or a link
	{
		snprintf(	globals.err_buff,MAX_BUFF,
							"\"%s\" is not a directory.",arg);
		report_error(globals.err_buff,0,0,error);
	}
	else if(access(arg,R_OK) != 0) // if cannot access to argument
		report(error,"\"%s\" ",arg);
	else
	{
		globals.rt_root = (const char *) get_full_path(arg);
		if(globals.wpa_list != NULL)
			for(iter=globals.wpa_list;iter!=NULL;iter=iter->next)
				P_essid((const char *) iter->essid);
		return;
	}

	if(globals.rt_root == NULL && globals.rain == true) // if there is no rt_root
	{
		report_error("switching OFF rainbow tables features.",0,0,info);
		globals.rain = false;
	}
	return;
}

void parser_wordlist(const char *arg, const char *file, int line_no)
{
	struct stat wrd_stat;
#ifdef HAVE_LIBMAGIC
	const char *target_mime = "text/plain;";
#endif


	if(arg == NULL)
		report_error("called with NULL argument.",0,1,error);
	else if( stat(arg,&wrd_stat) ) // if can't get file stats
		w_report_error(arg,file,line_no,__func__,1,0,error);
	else if( S_ISREG(wrd_stat.st_mode) == 0 ) // if isn't a regular file
		report(error,"\"%s\" is not a regular file.",arg);
	else if( access(arg,R_OK) != 0)
		w_report_error(arg,file,line_no,__func__,1,0,error);
	else
	{
#ifdef HAVE_LIBMAGIC
		if(strncmp(get_mime(arg),target_mime,strlen(target_mime)) != 0)
			report(warning,"\"%s\" is not a \"%s\" file.",arg,target_mime);
#endif

		if(globals.dict == false)
		{
			report_error("switching ON dictionary features...",0,0,info);
			globals.dict = true;
		}
		globals.wordlist = (const char *) get_full_path(arg);
	}

	if(globals.wordlist == NULL )
	{
		w_report_error("switching OFF dictionary features.",file,line_no,__func__,0,0,info);
		globals.dict = false;
	}
	return;
}

void parser_capture(const char *arg, const char*file, int line_no)
{
	struct stat cap_stat;

	if(arg == NULL)
		report_error("called with NULL argument.",0,1,error);
	else if( stat(arg,&cap_stat) ) // if can't get file stats
		w_report_error(arg,file,line_no,__func__,1,0,error);
	else if( S_ISREG(cap_stat.st_mode) == 0 ) // if isn't a regular file
		report(warning,"\"%s\" is not a regular file.",arg);
	else if( access(arg,R_OK) != 0)
		w_report_error(arg,file,line_no,__func__,1,0,error);
	else
		cap2hccap(arg); // it add essid and hccap to globals.wpa_list, and setup globals.pcap

	return;
}

void parser_path(const char *argv0 )
{
	char 	my_path[PATH_MAX],
				bin_path[PATH_MAX],
				*buff,
				**ptr,
				*bins[] = BINS ; // provided by ./configure
	int		i,n_bins;
	size_t len;

	if(realpath(argv0,my_path) == NULL)
		report_error(argv0,1,1,error);
	buff = dirname(my_path); // use as buffer
	if(buff!=my_path) // maybe realpath do yet it's work
		strncpy(my_path,buff,PATH_MAX);

	n_bins = sizeof(struct _bins) / sizeof(char *);
	memset(&(globals.bins),0,sizeof(struct _bins));

	for(i=0;i<n_bins;i++)
	{
		if(strlen(*(bins+i)) == 0) // if the binary were not found by autoconf
			continue;
		strncpy(globals.err_buff,*(bins+i),PATH_MAX); // use globals.err_buff as buffer 'couse realpath() modify the input string
		if( realpath(globals.err_buff,bin_path) == NULL) // remove extra symbols ( [./..] ) and test file existence
		{
			// if bins[i] isn't a full path
			snprintf(globals.err_buff,PATH_MAX,"%s/%s",my_path,*(bins+i));
			if(realpath(globals.err_buff,bin_path) == NULL)
			{
				report_error(globals.err_buff,1,1,error);
				continue;
			}
		}

		if( access(bin_path,X_OK) )
			report_error(bin_path,1,1,error);
		else
		{
			len = strlen(bin_path) + 1;
			ptr = (char **) &globals.bins;
			ptr += i;
			*ptr = malloc(len*sizeof(char));
			strncpy(*ptr,bin_path,len);
		}
	}
	return;
}

static void parser_online_cleanup(void *arg)
{
	int sockfd = *((int *) arg);
	if(sockfd!=-1)
		close(sockfd);
}

void *parser_online(void *garbage)
{
	int sockfd,val;
	sockfd = -1;
	struct addrinfo *result, hints;
	pthread_cleanup_push(parser_online_cleanup, &sockfd); // call parser_online_cleanup() if someone want to kill us.
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	memset(&hints,0,sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if(getaddrinfo("google.com","80",&hints,&result) == 0)
	{
		/* try to connect only to the first addrinfo */
		if((sockfd = socket(result->ai_family,result->ai_socktype,result->ai_protocol)) != -1)
		{
			val = 1;
			if(result->ai_protocol == IPPROTO_TCP)
				setsockopt(sockfd,result->ai_protocol,TCP_NODELAY, (char *) &val, sizeof(val));
			if(setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR, (char *) &val, sizeof(val)) == 0)
			{
				if(connect(sockfd,result->ai_addr,result->ai_addrlen) == 0)
					val = 0;
				else
					val=errno;
			}
			else
				val=errno;
		}
		else
			val=errno;
	}
	else
		val=-1;

	// execute celanup function ( if don't do this an extra '{' is insert by pthread_cleanup_push )
	pthread_cleanup_pop(1);
	pthread_exit((void *) val);
}

int parser_odb_head(char *line, int entry, odb *record)
{
	size_t line_len;
	int exit = EXIT_FAILURE;
	char *buff;
	static const char *url_patrn = "([a-zA-Z0-9:#%;$()~_?=.&\\-]+)/([a-zA-Z0-9:/#%;$()~_=.&\\-]*)([?])?";


	if(line == NULL || record == NULL)
		snprintf(globals.err_buff,MAX_BUFF,"called with NULL argument.");
	else if(entry < 1 || entry > ODB_HEAD)
		snprintf(globals.err_buff,MAX_BUFF,"called with invalid index.");
	else if((line_len=strlen(line)) == 0 && entry != 4)
		snprintf(globals.err_buff,MAX_BUFF,"line is empty.");
	else
	{
		exit = EXIT_SUCCESS;
		switch(entry)
		{
			case 1:
							if((record->host = regexpn(line,url_patrn,1)) == NULL)
							{
								strncpy(globals.err_buff,"bad URL at entry #1.",MAX_BUFF);
								exit = EXIT_FAILURE;
							}
							else
							{
								record->file = regexpn(line,url_patrn,2);
								buff = regexpn(line,url_patrn,3);
								if(buff!=NULL)
								{
									free(buff);
									record->method = GET;
								}
								else
									record->method = POST;
							}
							break;
			case 2:
							for(record->types = NULL, buff = strtok(line,","); buff != NULL && exit == EXIT_SUCCESS; buff = strtok(NULL,",") )
							{
								if(strchr(buff,ODB_SKIP_CHR)!=NULL) // comment has been found
									break;
								globals.err_buff[0] = '\0';
								record->types = add_odb_type(record->types,buff);
								if(globals.err_buff[0] != '\0')
									exit = EXIT_FAILURE;
							}
							break;
			case 3:
							argcpy(&(record->patrn),line,line_len);
							break;
			case 4:
							if(line_len==0)
								record->detected = NULL;
							else
								argcpy(&(record->detected),line,line_len);
							break;
			default:
							report_error("!!!SECURITY BREACH!!!",0,1,quiet);
		}
	}
	return exit;
}

void parser_odb( const char *arg, const char *file, int line_no )
{
	odb *otmp=NULL,*oold=NULL;
	int ec,ln,count;
	size_t odb_len,sep_len,str_len;
	bool good;
	struct stat odb_stat;
#ifdef HAVE_LIBMAGIC
	const char *target_mime = "text/plain;";
#endif
	char *line,*tmp_err_buff,*buff;
	FILE *db_file;

	line = tmp_err_buff = buff = NULL;

	if(arg == NULL)
		report_error("called with NULL argument.",0,1,error);
	else if(globals.odb != NULL)
		report_error("online servers database yet loaded.",0,0,warning);
	else if( stat(arg,&odb_stat) ) // if can't get file stats
		w_report_error(arg,file,line_no,__func__,1,0,error);
	else if( S_ISREG(odb_stat.st_mode) == 0 ) // if isn't a regular file
		report(warning,"\"%s\" is not a regular file.",arg);
	else if( access(arg,R_OK) != 0 || (db_file = fopen(arg,"r")) == NULL)
		w_report_error(arg,file,line_no,__func__,1,0,error);
	else
	{
#ifdef HAVE_LIBMAGIC
		if(strncmp(get_mime(arg),target_mime,strlen(target_mime)) != 0)
			report(info,"\"%s\" is not a \"%s\" file.",arg,target_mime);
#endif
		odb_len = sizeof(odb);
		sep_len = strlen(ODB_SEP);
		tmp_err_buff = malloc((MAX_BUFF+1) * sizeof(char));
		line = malloc((MAX_LINE+1) * sizeof(char));
		ln=count=ec=0;
		otmp=globals.odb=malloc(odb_len);

		while(count<MAX_ODB && !feof(db_file))
		{
			fgets(line,MAX_LINE,db_file);
			ln++;

			good=false;
			if((str_len=strlen(line)) == 0)
				strncpy(tmp_err_buff,"line is empty.",MAX_BUFF);
			else if(line[str_len-1] != '\n' && !feof(db_file))
			{
				snprintf(tmp_err_buff,MAX_BUFF,"line is longer then #%d chars and has been igored.",MAX_LINE);
				while(!feof(db_file) && line[str_len-1] != '\n')
				{
					fgets(line,MAX_LINE,db_file);
					ln++;
					if((str_len=strlen(line)) == 0)
						report_error("!!!SECURITY BREACH!!!",0,1,error);
				}
			}
			else
			{
				fgets_fix(line);
				good=true;
			}

			if(good==false)
			{
				report(warning,"at line #%d: %s",ln,tmp_err_buff);
				continue;
			}

			good=false;
			if((buff = regexp(line,ODB_SKIP_RGX))!=NULL)
				free((void *) buff);
			else if(!strncmp(line,ODB_SEP,sep_len)) // check omtp concsistency.
			{
				if(otmp->host == NULL || otmp->file == NULL || otmp->patrn == NULL || otmp->types == NULL || otmp->tuples == NULL)
				{
					free_odb(otmp);
					if(oold==NULL) // first
						globals.odb = otmp = malloc(odb_len);
					else
						otmp = oold->next = malloc(odb_len);
				}
				else
				{
					count++;
					oold=otmp;
					otmp=otmp->next=malloc(odb_len);
				}
				ec=0;
			}
			else
				good=true;

			if(good==false)
				continue;
			good=false;
			ec++;
			if(ec <= ODB_HEAD)
			{
				if(parser_odb_head(line,ec,otmp)!=EXIT_SUCCESS)
					strncpy(tmp_err_buff,globals.err_buff,MAX_BUFF);
				else
					good=true;
			}
			else
			{
				globals.err_buff[0]='\0';
				otmp->tuples = add_odb_t(otmp->tuples,line,ec);
				if(globals.err_buff[0]!='\0')
					strncpy(tmp_err_buff,globals.err_buff,MAX_BUFF);
				else
					good=true;
			}

			if(good==false)
				report(warning,"at line #%d: %s",ln,tmp_err_buff);
		}
		fclose(db_file);
	}

	// check otmp consintency
	if(otmp!=NULL && (otmp->host == NULL || otmp->file == NULL || otmp->patrn == NULL || otmp->types == NULL || otmp->tuples == NULL))
	{
		if(oold==NULL)//first
			globals.odb=NULL;
		else
			oold->next = NULL;
		free_odb(otmp);
	}

	if(tmp_err_buff!=NULL)
		free((void *) tmp_err_buff);
	if(line!=NULL)
		free((void *) line);

	// globals flags Handler
	if(globals.odb==NULL && globals.online != false)
	{
		report_error("switching OFF online features.",0,0,info);
		globals.online=false;
	}

	return;
}

void parser_wpa_list()
{
	struct _wpa *iter=NULL,*prev=NULL;

	for(iter=globals.wpa_list;iter!=NULL;iter=iter->next)
		if(iter->manual==true)
			break;
	if(iter==NULL)
		return; // exit if no essid has been manually added

	// delete AP which has been auto-founded or without valid handshake
	for(iter=globals.wpa_list;iter!=NULL;)
		if(iter->manual==false || iter->hccap == NULL)
		{
			if(prev==NULL) // iter is globals.wpa_list
			{
				globals.wpa_list = iter->next;
				free_wpa(iter);
				iter = globals.wpa_list;
				prev = NULL;
			}
			else
			{
				prev->next = iter->next;
				free_wpa(iter);
				iter = prev->next;
			}
		}
		else
		{
			prev = iter;
			iter = iter->next;
		}

	return;
}

void parser_jtr(struct t_info *thread)
{
	FILE *fp;
	unsigned int line_no;
	static const char *pattern="\\$([a-f0-9]+):(.*)";
	char *line,*found_hash,*found_pswd;
	bool first_error;

	if(thread->hlist == NULL) // there's nothing to do here without hash to compare.
		return;
	else if((fp = fopen(thread->outfile,"r")) == NULL)
	{
		if(errno == ENOENT) // JTR don't found anything
			return;
		else
			report_error(thread->outfile,1,0,error);
	}
	else
	{
		line_no = 0;
		line = malloc((MAX_LINE+1)*sizeof(char));
		first_error = true;
		fgets(line,MAX_LINE,fp);
		fgets_fix(line);
		while(!feof(fp))
		{
			line_no++;
			if((found_hash = regexpn(line,pattern,1)) != NULL)
			{
				if((found_pswd = regexpn(line,pattern,2)) != NULL)
				{
					add_hash_plain(NULL,found_hash,thread,found_pswd);
					free(found_pswd);
				}
				free(found_hash);
			}
			else
			{
				if(first_error==true)
				{
					report_error("john the ripper output file is corrupted or invalid.",0,0,error);
					first_error=false;
				}
				report(verbose,"\tline #%d is wrong.",line_no);
			}
			fgets(line,MAX_LINE,fp);
			fgets_fix(line);
		}
		fclose(fp);
		free(line);
	}
	return;
}

void parser_cow(struct t_info *thread)
{
	FILE *fp;
	char *line,*pswd;
	static const char *pattern="The PSK is \"(.*)\"\\.";

	if(globals.wpa_list == NULL)
		return;
	else if((fp = fopen(thread->outfile,"r")) == NULL)
		report_error(thread->outfile,1,0,error);
	else
	{
		pswd = NULL;
		line = malloc(MAX_LINE*sizeof(char));
		fgets(line,MAX_LINE,fp);
		fgets_fix(line);
		while(!feof(fp))
		{
			if((pswd = regexpn(line,pattern,1)) != NULL)
				if(strlen(pswd) == 0)
				{
					free((void *) pswd);
					pswd = NULL;
				}
				else
					add_wpa_key(thread,pswd);
			free((void *) pswd);
			pswd = NULL;
			fgets(line,MAX_LINE,fp);
			fgets_fix(line);
		}
		fclose(fp);
		free((void *) line);
	}
	return;
}

void parser_ocl(struct t_info *thread)
{
	FILE *fp;
	unsigned int line_no;
	static const char *pattern="^([a-fA-F0-9]+):(.+)$";
	char *line,*found_hash,*found_pswd;
	bool first_error;

	if(thread->hlist == NULL) // there's nothing to do here without hash to compare.
		return;
	else if((fp = fopen(thread->outfile,"r")) == NULL)
	{
		if(errno == ENOENT) // OCL don't found anything
			return;
		else
			report_error(thread->outfile,1,0,error);
	}
	else
	{
		line_no = 0;
		first_error = true;
		line = malloc((MAX_LINE+1)*sizeof(char));
		fgets(line,MAX_LINE,fp);
		fgets_fix(line);
		while(!feof(fp))
		{
			line_no++;
			if((found_hash = regexpn(line,pattern,1)) != NULL)
			{
				if((found_pswd = regexpn(line,pattern,2)) != NULL)
				{
					add_hash_plain(NULL,found_hash,thread,found_pswd);
					free(found_pswd);
				}
				free(found_hash);
			}
			else
			{
				if(first_error==true)
				{
					report_error("oclhashcat output file is corrupted or invalid.",0,0,error);
					first_error=false;
				}
				report(verbose,"\tline #%d is wrong.",line_no);
			}
			fgets(line,MAX_LINE,fp);
			fgets_fix(line);
		}
		fclose(fp);
		free(line);
	}
	return;
}

void parser_pyrit(struct t_info *thread)
{
	char *line;
	FILE *fp;

	if((fp = fopen(thread->outfile,"r")) == NULL)
	{
		if(errno == ENOENT)
			return;
		else
			report_error(thread->outfile,1,0,error);
	}
	else
	{
		line = malloc(MAX_LINE*sizeof(char));
		do // pyrit don't write '\n' at the and of file, so the last line is read but EOF is reached.
		{
			fgets(line,MAX_LINE,fp);
			fgets_fix(line);
			if(strlen(line) > 0)
				add_wpa_key(thread,line);
		}
		while(!feof(fp));
		fclose(fp);
		free((void *) line);
	}
	return;
}

void parser_rcrack(struct t_info *thread)
{
	const char *patrn = "^([a-fA-F0-9]+):(.*):[a-fA-F0-9]+$";
	char line[MAX_LINE],*pswd,*hash;
	FILE *fd;
	int ln;
	size_t len;
	bool first_error;

	if((fd = fopen(thread->outfile,"r")) == NULL)
	{
		report_error(thread->outfile,1,0,error);
		return;
	}
	line[0] = '\0';
	first_error=true;
	do
	{
		fgets(line,MAX_LINE,fd);
		ln++;
		globals.err_buff[0] = '\0';
		if((len = strlen(line)) == 0 && ln == 1)
			strncpy(globals.err_buff,"file is empty.",MAX_LINE);
		else if(len==0 && !feof(fd))
			snprintf(globals.err_buff,MAX_BUFF,"\tline #%d is empty.",ln);
		else if(len == MAX_LINE)
			snprintf(globals.err_buff,MAX_BUFF,"\tline #%d is more long then #%d chars and will be skipped.",ln,MAX_LINE);
		else
		{
			fgets_fix(line);
			pswd = regexpn(line,patrn,2);
			if(pswd!=NULL)
			{
				hash = regexpn(line,patrn,1); // cannot be NULL
				add_hash_plain(NULL,hash,thread,pswd);
				free((void *) pswd);
				free((void *) hash);
			}
			else
				snprintf(globals.err_buff,MAX_BUFF,"\tline #%d not in rcrack format, maybe file is corrupted.",ln);
		}
		if(globals.err_buff[0] != '\0')
		{
			if(first_error==true)
			{
				strncpy(line,globals.err_buff,MAX_LINE);
				report(verbose,"in file \"%s\":",thread->outfile);
				report_error(line,0,0,verbose);
				first_error=false;
			}
			else
				report_error(globals.err_buff,0,0,verbose);
		}
	}while(!feof(fd));
	fclose(fd);

	return;
}

void parser_prog_output(struct t_info *thread, const char *file, int line_no)
{
	if(thread==NULL)
		w_report_error("called with NULL argument.",file,line_no,__func__,0,1,error);
	else if(thread->bin == NULL || thread->outfile == NULL)
		return;
	else if(thread->bin == globals.bins.jtr)
		parser_jtr(thread);
	else if(thread->bin == globals.bins.cow)
		parser_cow(thread);
	else if(thread->bin == globals.bins.oclhashcat)
		parser_ocl(thread);
	else if(thread->bin == globals.bins.pyrit)
		parser_pyrit(thread);
	else if(thread->bin == globals.bins.rcrack)
		parser_rcrack(thread);
	else
		w_report_error("unknown program to parse.",file,line_no,__func__,0,0,warning);
	return;
}

void parser_defaults()
{
	char buff[MAX_BUFF];

	if(globals.hash_list==NULL)
	{
		globals.online=false;
		if(globals.wpa_list==NULL)
			globals.rain = globals.dict = false;
	}

	if(globals.rain != false && globals.bins.cow == NULL && globals.bins.rcrack == NULL)
	{
		report_error("cannot find programs that can be used for rainbow table crack.",0,0,verbose2);
		report_error("switching OFF rainbowtables attacks.",0,0,verbose);
		globals.rain = false;
	}
	if(globals.bins.oclhashcat == NULL &&  globals.bins.pyrit == NULL)
	{
		if(globals.gpu!=false)
		{
			report_error("no oclhashcat-plus or pyrit found on your system by './configure'.",0,0,warning);
			report_error("switching OFF GPU features.",0,0,info);
			globals.gpu = false;
		}
		if(globals.bins.jtr == NULL && globals.bins.cow == NULL)
			globals.dict = false;
	}

	if(globals.dict == true && globals.wordlist == NULL )
	{
		snprintf(buff,MAX_BUFF,"%s/%s",CONFDIR,DEF_WRDLST);
		P_wordlist(buff);
	}

	if(globals.rain == true && globals.rt_root == NULL )
	{
		snprintf(buff,MAX_BUFF,"%s/%s",CONFDIR,DEF_RT_ROOT);
		P_rt_root(buff);
	}

	if(globals.online == true && globals.odb == NULL)
	{
		snprintf(buff,MAX_BUFF,"%s/%s",CONFDIR,DEF_ODB);
		if(access(buff,R_OK)) // if cannot read file
			globals.odb = &internal_odb;
		else
			P_odb(buff);
	}
	return;
}
