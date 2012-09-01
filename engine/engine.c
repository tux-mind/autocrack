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

#include "engine.h"

extern struct _globals globals;

struct engine_settings
{
	struct { struct {const char *cpu,*gpu;} hash,wpa; } dict;
	unsigned int 	mem_counter;	// number of addresses to free
	void *to_free[MAX_POINTERS];
}	E_opt;

/* keep a trace of allocated memory into E_opt.to_free */
void *engine_malloc(size_t bytes, const char *file, int line_no)
{
	if(E_opt.mem_counter >= MAX_POINTERS)
	{
		engine_del_opt();
		report(verbose,"more then #%d memory locations has been allocated.",MAX_POINTERS);
		report_error("memory overload!",0,1,error);
	}
	return E_opt.to_free[E_opt.mem_counter++] = malloc(bytes);
}

/* GPU binaries must run alone, otherwise GPU will overheat and the program will crash. */
void gpu_handler( char **args, char *outfile, struct _wpa *wpa, enum _type hash_type)
{
	static struct my_call { char *bin, *outfile, **args; struct _wpa *wpa; enum _type htype; struct my_call *next; } *call_db=NULL;
	struct my_call *iter=NULL,*prev=NULL;
	static int n_args=0;
	struct t_info *told=NULL;

	if(args==NULL) // start attack
	{
		if(n_args<=0)
			return;
		for(iter=call_db;iter!=NULL;prev=iter,iter=iter->next,free((void *) prev))
		{
			told = prog_wait(iter->args,iter->outfile,told); // calling prog_wait with told==NULL is equal to prog_call
			if(iter->wpa==NULL)
				bind_thr2htype(told,iter->htype);
			else
				bind_thr2wpa(told,iter->wpa);
		}
		return;
	}

	if(call_db==NULL)
		iter = call_db = malloc(sizeof(struct my_call));
	else
	{
		for(iter=call_db;iter->next!=NULL;iter=iter->next);
		iter = iter->next = malloc(sizeof(struct my_call));
	}

	iter->args = args;
	iter->bin = *args;
	iter->outfile = outfile;
	iter->wpa = wpa;
	iter->htype = hash_type;
	iter->next = NULL;
	n_args++;

	return;
}

void rain_hash_cpu_crack()
{
	char *outfile, **args;
	const char *infile;
	int threads;
	size_t len;
	struct t_info *iter=NULL;

	if((infile = make_hash_file(UNKNOWN)) == NULL)
		return;
	outfile = E_malloc(L_tmpnam*sizeof(char));
	tmpnam(outfile);
	for(threads=get_n_cpus(),iter=globals.tpool;iter!=NULL && threads>1;iter=iter->next)
		if(iter->state == running)
			threads--;

	len = snprintf(NULL,0,"%d",threads)+1;
	args = E_malloc(9*sizeof(char *));
	args[0] = (char *) globals.bins.rcrack;
	args[1] = "-l";
	args[2] = (char *) infile;
	args[3] = "-t";
	args[4] = E_malloc(len*sizeof(char));
	snprintf(args[4],len,"%d",threads);
	args[5] = "-o";
	args[6] = outfile;
	args[7] = (char *) globals.rt_root;
	args[8] = NULL;
	iter = prog_call(args,outfile);
	bind_thr2htype(iter,UNKNOWN);

	return;
}

void rain_wpa_cpu_crack(_wpa *wpa)
{
	char **args;

	args = E_malloc(8*sizeof(char *));
	args[0] = globals.bins.cow;
	args[1] = "-s";
	args[2] = wpa->essid;
	args[3] = "-r";
	args[4] = (char *) globals.pcap;
	args[5] = "-d";
	args[6] = wpa->genpmk;

	bind_thr2wpa(prog_call(args,NULL),wpa);

	return;
}

void dict_wpa_cpu_crack(const char *wordlist, struct _wpa *wpa)
{
	char **args;
	struct t_info *thread;

	args = E_malloc(8*sizeof(char *));
	args[0] = globals.bins.cow;
	args[1] = "-f";
	args[2] = (char *) wordlist;
	args[3] = "-r";
	args[4] = (char *) globals.pcap;
	args[5] = "-s";
	args[6] = wpa->essid;
	args[7] = NULL;

	thread = prog_call(args,NULL); // redirect stdout
	bind_thr2wpa(thread,wpa);
	return;
}

void dict_wpa_gpu_crack(const char *wordlist, struct _wpa *wpa)
{
	char ***ocl_args,**pyr_args,*outfile;


	outfile = E_malloc(L_tmpnam*sizeof(char));
	tmpnam(outfile);

	if(globals.bins.oclhashcat != NULL)
	{
		/* oclhashcat-plus -m 2500 -a 0/1 -o oufile --outfile-format=3 infile.hccap wordlist */

		ocl_args = E_malloc(2*sizeof(char **));
		ocl_args[0] = E_malloc(11*sizeof(char *));
		ocl_args[1] = E_malloc(11*sizeof(char *));
		ocl_args[0][0] = ocl_args[1][0] = (char *) globals.bins.oclhashcat;
		ocl_args[0][1] = ocl_args[1][1] = "-m";
		ocl_args[0][2] = ocl_args[1][2] = "2500";
		ocl_args[0][3] = ocl_args[1][3] = "-a";
		ocl_args[0][4] = "0";
		ocl_args[1][4] = "1";
		ocl_args[0][5] = ocl_args[1][5] = "-o";
		ocl_args[0][6] = outfile;
		outfile = E_malloc(L_tmpnam*sizeof(char));
		tmpnam(outfile);
		ocl_args[1][6] = outfile;
		ocl_args[0][7] = ocl_args[1][7] = "--outfile-format=3";
		ocl_args[0][8] = ocl_args[1][8] = (char *) globals.hccap;
		ocl_args[0][9] = ocl_args[1][9] = (char *) wordlist;
		ocl_args[0][10] = ocl_args[1][10] = NULL;

		wpa_gpu_handler(ocl_args[0],ocl_args[0][6],wpa);
		wpa_gpu_handler(ocl_args[1],ocl_args[1][6],wpa);
	}
	else
	{
		/* pyrit -r file.pcap -i wordlist -o outfile attack_passthrough */

		pyr_args = E_malloc(11*sizeof(char *));
		pyr_args[0] = (char *) globals.bins.pyrit;
		pyr_args[1] = "-r";
		pyr_args[2] = (char *) globals.pcap;
		pyr_args[3] = "-i";
		pyr_args[4] = (char *) wordlist;
		pyr_args[5] = "-o";
		pyr_args[6] = outfile;
		pyr_args[7] = "-e";
		pyr_args[8] = wpa->essid;
		pyr_args[9] = "attack_passthrough";
		pyr_args[10] = NULL;
		wpa_gpu_handler(pyr_args,outfile,wpa);
	}

	return;
}

void dict_hash_cpu_crack(const char *wordlist)
{
	char ***args,*outfile;
	const char *infile;
	int j;
	enum _type i;
	size_t len;
	struct t_info *thread;

	report_error("starting dictionary hash crack using CPU.",0,0,info);

	// N_TYPE count also NONE and UNKNOWN that not concern us. ( we keep one more for the NULL pointer)
	args = E_malloc((N_TYPE-1)*sizeof(char **));
	thread=NULL; // passing 'NULL' to prog_wait make it work as prog_call
	for(i=NONE+1,j=0;i<UNKNOWN;i++)
		if( types_john_codes[i] != NULL && (infile = make_hash_file(i)) != NULL)
		{
			outfile = E_malloc(L_tmpnam*sizeof(char));
			tmpnam(outfile);
			args[j] = E_malloc(6*sizeof(char *)); // that set args[j][5] = NULL
			args[j][0] = globals.bins.jtr;
			len = strlen(wordlist)+12;
			args[j][1] = E_malloc(len*sizeof(char));
			snprintf(args[j][1],len,"--wordlist=%s",wordlist);
			len = strlen(types_john_codes[i])+10;
			args[j][2] = E_malloc(len*sizeof(char));
			snprintf(args[j][2],len,"--format=%s",types_john_codes[i]);
			len = strlen(outfile)+7;
			args[j][3] = E_malloc(len*sizeof(char));
			snprintf(args[j][3],len,"--pot=%s",outfile);
			args[j][4] = (char *) infile;
			thread = prog_wait(args[j],outfile,thread);
			bind_thr2htype(thread,(enum _type) i);
			j++;
		}

	if(j==0)
		report_error("no hash can be cracked via dictionary using CPU.",0,0,warning);
	return;
}

void dict_hash_gpu_crack(const char *wordlist)
{
	char ***args,*outfile;
	const char *infile;
	int j;
	enum _type i;

	report_error("starting dictionary hash crack using CPU.",0,0,info);

	args = E_malloc(N_TYPE*sizeof(char **));
	for(i=NONE+1,j=0;i<UNKNOWN;i++)
		if( types_hc_codes[i] != NULL && (infile = make_hash_file(i)) != NULL)
		{
			outfile = E_malloc(L_tmpnam*sizeof(char));
			tmpnam(outfile);
			args[j] = E_malloc(9*sizeof(char *));
			args[j][0] = globals.bins.oclhashcat;
			args[j][1] = "-m";
			args[j][2] = (char *) types_hc_codes[i];
			args[j][3] = "-o";
			args[j][4] = outfile;
			args[j][5] = "--outfile-format=3";
			args[j][6] = (char *) infile;
			args[j][7] = (char *) wordlist;
			args[j][8] = NULL;
			hash_gpu_handler(args[j],outfile,i);
			j++;
		}

	if(j==0)
		report_error("no hash can be cracked via dictionary using GPU.",0,0,warning);

	return;
}

void rt_crack()
{
	_wpa *wtmp=NULL;

	if(globals.hash_list!=NULL && globals.bins.rcrack != NULL)
	{
		report_error("starting rainbowtable attack against hashes.",0,0,info);
		rain_hash_cpu_crack();
	}
	//find the first handshake with a valid genpmk file.
	for(wtmp=globals.wpa_list;wtmp!=NULL && wtmp->genpmk==NULL;wtmp=wtmp->next);
	if(wtmp!=NULL && globals.bins.cow != NULL)
	{
		report_error("starting rainbowtable attack against wpa handshakes.",0,0,info);
		//skip the first check.
		rain_wpa_cpu_crack(wtmp);
		for(wtmp=wtmp->next;wtmp!=NULL;wtmp=wtmp->next)
			if(wtmp->genpmk!=NULL)
				rain_wpa_cpu_crack(wtmp);
	}
	return;
}

void dict_crack()
{
	struct _wpa *wpa_cur=NULL;

	if(E_opt.dict.hash.cpu != NULL)
		dict_hash_cpu_crack(E_opt.dict.hash.cpu);
	if(E_opt.dict.hash.gpu != NULL)
		dict_hash_gpu_crack(E_opt.dict.hash.gpu);
	if(E_opt.dict.wpa.cpu != NULL)
	{
		report_error("starting dictionary wpa crack using CPU.",0,0,info);
		for(wpa_cur=globals.wpa_list;wpa_cur!=NULL;wpa_cur=wpa_cur->next)
			dict_wpa_cpu_crack(E_opt.dict.wpa.cpu, wpa_cur);
	}
	if(E_opt.dict.wpa.gpu != NULL)
	{
		report_error("starting dictionary wpa crack using GPU.",0,0,info);
		if(globals.bins.oclhashcat!=NULL)
			dict_wpa_gpu_crack(E_opt.dict.wpa.gpu,NULL); /* and probably also oclhashcat wont a specific essid...or a single hccap file for every AP */
		else
			for(wpa_cur=globals.wpa_list;wpa_cur!=NULL;wpa_cur=wpa_cur->next)
				dict_wpa_gpu_crack(E_opt.dict.wpa.gpu,wpa_cur);
	}

	if(E_opt.dict.hash.gpu != NULL || E_opt.dict.wpa.gpu != NULL)
		start_gpu();
	return;
}

static void online_thread_cleanup(void *arg)
{
	struct _free_me
	{
		struct curl_slist *headerlist;
		struct curl_httppost *formpost;
		CURL *curl;
		struct _mem
		{
			char *memory;
			size_t size;
		} chunk;
		char *pswd;
		const char *value;
	} mem = *((struct _free_me *) arg);

	// this can happen: add_hash_plain => unbind_hash => pthread_mutex_lock
	pthread_mutex_unlock(&pool_lock);
	if(mem.formpost!=NULL)
		curl_formfree(mem.formpost);
	if(mem.headerlist!=NULL)
		curl_slist_free_all(mem.headerlist);
	if(mem.curl!=NULL)
		curl_easy_cleanup(mem.curl);
	if(mem.chunk.memory!=NULL)
		free((void *) mem.chunk.memory);
	if(mem.pswd!=NULL)
		free((void *) mem.pswd);
	if(mem.value != NULL)
		free((void *) mem.value);
}

void *online_crack_thread(void *garbage)
{
	struct curl_httppost *lastptr=NULL;
	static const char buf[] = "Expect:";//us
	CURLcode res;
	int i,a;
	//long timeout = CURL_TIMEOUT;
	char url[MAX_LINE],buffer[MAX_LINE]; // must use an internal buffer since globals.err_buff isn't for threads
	const char *agent;
	float rnd_gap;
	odb *self=NULL;
	odb_t *ttmp=NULL;
	odb_type *tp_tmp=NULL;
	_hash *htmp=NULL;

	/* this function use an huge amount of memory,
	 * so we must free it all if someone cancel this thread.*/
	struct _free_me
	{
		struct curl_slist *headerlist;
		struct curl_httppost *formpost;
		CURL *curl;
		struct _mem
		{
			char *memory;
			size_t size;
		} chunk;
		char *pswd, *value;
	} mem;

	memset(&mem,0,sizeof(struct _free_me));
	mem.chunk.memory = NULL; // must be sure ont this thing!

	pthread_cleanup_push(online_thread_cleanup, &mem); // look parser_online for help on this function.

	for(self=globals.odb;self!=NULL && !pthread_equal(pthread_self(),self->thread);self=self->next);

	mem.curl = curl_easy_init();

	if(self==NULL)
		report_error("cannot find myself in the online servers database.",0,1,error);
	if(mem.curl == NULL)
		report_error("unable to init libcurl Handler.",0,1,error);

	mem.headerlist = curl_slist_append(mem.headerlist, buf);
	mem.chunk.memory = malloc(1);
	mem.chunk.size = 0;
	srand(time(NULL));

	for(a=0,htmp=globals.hash_list;htmp!=NULL;htmp=htmp->next,a++)
	{
		if((agent = uagents[a])==NULL)
			agent = uagents[(a=0)];
		for(tp_tmp = self->types;tp_tmp!=NULL && tp_tmp->type != htmp->type; tp_tmp = tp_tmp->next);

		if(tp_tmp == NULL || htmp->type != tp_tmp->type || htmp->plain != NULL)
			continue;

		snprintf(url,MAX_LINE-1,"%s/%s",self->host,self->file);
		odb_sub_str(url,tp_tmp,htmp,MAX_LINE);
		if(self->method==GET)
		{
			curl_easy_setopt(mem.curl, CURLOPT_REFERER, url);
			strncat(url,"?",1);
		}
		mem.value = malloc(MAX_LINE*sizeof(char));
		for(ttmp=self->tuples;ttmp;ttmp=ttmp->next)
		{
			strncpy(mem.value,ttmp->value,MAX_LINE);
			odb_sub_str(mem.value,tp_tmp,htmp,MAX_LINE);

			if(self->method == POST)
				curl_formadd(&(mem.formpost), &lastptr,
									CURLFORM_COPYNAME, ttmp->name,
									CURLFORM_COPYCONTENTS, mem.value,
									CURLFORM_END);
			else
			{
				strncpy(buffer,url,MAX_LINE);
				snprintf(url,MAX_LINE,"%s%s=%s&",buffer,ttmp->name,mem.value);
			}
		}
		free((void *) mem.value);
		mem.value = NULL;
		if(self->method==POST)
			curl_easy_setopt(mem.curl, CURLOPT_HTTPPOST, mem.formpost);
		else
		{
			url[strlen(url)-1]='\0'; // remove the last '&'
			curl_easy_setopt(mem.curl, CURLOPT_POST, 0);
		}
		curl_easy_setopt(mem.curl, CURLOPT_WRITEFUNCTION, memory_writer);
		curl_easy_setopt(mem.curl, CURLOPT_URL, url);
		curl_easy_setopt(mem.curl, CURLOPT_FOLLOWLOCATION, 1);
		curl_easy_setopt(mem.curl, CURLOPT_WRITEDATA, (void *)&(mem.chunk));
		curl_easy_setopt(mem.curl, CURLOPT_USERAGENT, agent);
		curl_easy_setopt(mem.curl, CURLOPT_TIMEOUT, CURL_TIMEOUT);
		curl_easy_setopt(mem.curl, CURLOPT_CONNECTTIMEOUT , CURL_TIMEOUT/2);
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,NULL); // cannot cancel now, or we will lost memory
		for(i=0;i<BOT_RETRY && (res = curl_easy_perform(mem.curl)) != CURLE_OK; i++)
		{
			pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,NULL);
			snprintf(buffer,MAX_LINE,"on host \"%s\": %s.",self->host,curl_easy_strerror(res));
			report_error(buffer,0,0,error);
			sleep(2);
			pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,NULL);
		}
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,NULL);
		if(i==BOT_RETRY)
			continue;
		mem.pswd = regexpn(mem.chunk.memory,self->patrn,1);
		// try to avoid bot detection
		for(i=0;i<BOT_RETRY && mem.pswd == NULL && self->detected != NULL && strstr(mem.chunk.memory,self->detected) != NULL;i++)
		{
			if(i==0)
			{
				snprintf(buffer,MAX_LINE,"defeating anti-bot system on host \"%s\".",self->host);
				report_error(buffer,0,0,verbose);
			}
			rnd_gap = (float) rand() / RAND_MAX;
			usleep(((4+i+rnd_gap)*1000000));
			snprintf(buffer,MAX_LINE,"retry #%d.",i+1);
			report_error(buffer,0,0,verbose3);
			pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,NULL);
			res = curl_easy_perform(mem.curl);
			pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,NULL);
			if(res!=CURLE_OK)
			{
				snprintf(buffer,MAX_LINE,"on host \"%s\": %s.",self->host,curl_easy_strerror(res));
				report_error(buffer,0,0,error);
				continue;
			}
			mem.pswd = regexpn(mem.chunk.memory,self->patrn,1);
		}
		if(self->method==POST)
		{
			curl_formfree(mem.formpost);
			mem.formpost=NULL;
			lastptr=NULL;
		}
		if( (mem.chunk.memory = realloc(mem.chunk.memory,1)) == NULL)
			report_error("realloc()",1,1,error);
		mem.chunk.size = 0;
		if(mem.pswd != NULL)
		{
			snprintf(buffer,MAX_LINE,"found \"%s\" on host \"%s\".",mem.pswd,self->host);
			report_error(buffer,0,0,debug);
			// avoid multiple adds, maybe while we get online content another thraed have yet found it.
			if(htmp->plain==NULL)
				add_hash_plain(htmp,NULL,NULL,	mem.pswd);
			free((void *) mem.pswd);
			mem.pswd = NULL;
		}
		sleep(2); // wait 2 senconds
	}

	pthread_cleanup_pop(1);

	pthread_exit(&i);// don't care about the value.
}

static void online_crack_cleanup(void *arg)
{
	struct t_info *self = (struct t_info *) arg;
	bool kill_done;
	odb *otmp=NULL;
	for(otmp=globals.odb;otmp!=NULL;otmp=otmp->next)
		if(otmp->thread != 0) // if thread is running
			pthread_cancel(otmp->thread);
	for(kill_done=false;kill_done==false;usleep(10))
		for(kill_done=true,otmp=globals.odb;otmp!=NULL && kill_done == true;otmp=otmp->next)
			if(otmp->thread != 0 && pthread_kill(otmp->thread,0) == 0)
				kill_done = false;
	for(otmp=globals.odb;otmp!=NULL;otmp->thread=0,otmp=otmp->next)
		if(otmp->thread!=0) // thread is already done, we kill it before
			pthread_join(otmp->thread,NULL);
	curl_global_cleanup();
	self->state = done;
}

void *online_crack_handler(void *garbage)
{
	odb *otmp=NULL;
	struct t_info *self;
	curl_global_init(CURL_GLOBAL_ALL);

	for(self=globals.tpool;self!=NULL && !pthread_equal(self->thread,pthread_self());self=self->next);

	pthread_cleanup_push(online_crack_cleanup,self);
	// start attack
	for(otmp=globals.odb;otmp!=NULL;otmp=otmp->next)
		pthread_create(&(otmp->thread),NULL,online_crack_thread,NULL);
	// wait that all threads finish
	for(otmp=globals.odb;otmp!=NULL;otmp->thread=0,otmp=otmp->next)
		if(otmp->thread!=0)
			pthread_join(otmp->thread,NULL);

	self->state = done;
	pthread_cleanup_pop(0);
	curl_global_cleanup();
	pthread_exit(&self);
}

void online_crack()
{
	enum _type cur_type;
	struct t_info *online_thr=NULL;
	odb *otmp=NULL;
	odb_type *tp_tmp=NULL;
	bool en_types[N_TYPE];

	pthread_mutex_lock(&pool_lock);
	if(globals.tpool==NULL)
		online_thr = globals.tpool = malloc(sizeof(struct t_info));
	else
	{
		for(online_thr=globals.tpool;online_thr->next!=NULL;online_thr=online_thr->next);
		online_thr = online_thr->next = malloc(sizeof(struct t_info));
	}
	memset(online_thr,0,sizeof(struct t_info));
	online_thr->state = running;
	pthread_mutex_unlock(&pool_lock);
	report_error("starting online crack.",0,0,info);
	memset(&en_types,(int) ((bool) false),N_TYPE*sizeof(bool));
	for(otmp=globals.odb;otmp!=NULL;otmp=otmp->next)
			for(tp_tmp=otmp->types;tp_tmp!=NULL;tp_tmp=tp_tmp->next)
				en_types[tp_tmp->type] = true; // fill enabled_types with all types that can be cracked online.
	for(cur_type=(NONE+1);cur_type<UNKNOWN;cur_type++)
		if(en_types[cur_type] == true)
			bind_thr2htype(online_thr,cur_type);
	pthread_create(&(online_thr->thread),NULL,online_crack_handler,NULL);
	return;
}

void engine_init_opt()
{
	// init memory
	memset(&(E_opt),0,sizeof(struct engine_settings));

	// check globals binaries and flags for divide the workload between GPU and CPU
	if(globals.dict==true)
	{
		make_wordlist(compute);
		if(globals.gpu==true)
		{
			if(globals.bins.jtr!=NULL && globals.bins.cow!=NULL)
			{
				if(globals.bins.oclhashcat!=NULL)
				{
					E_opt.dict.hash.cpu = E_opt.dict.wpa.cpu = make_wordlist(cpu);
					E_opt.dict.hash.gpu = E_opt.dict.wpa.gpu = make_wordlist(gpu);
				}
				else // pyrit is present, because globals.gpu == true
				{
					E_opt.dict.hash.cpu = globals.wordlist;
					E_opt.dict.wpa.cpu = make_wordlist(cpu);
					E_opt.dict.wpa.gpu = make_wordlist(gpu);
				}
			}
			else if(globals.bins.jtr!=NULL)
			{
				if(globals.bins.oclhashcat!=NULL)
				{
					E_opt.dict.hash.cpu = make_wordlist(cpu);
					E_opt.dict.hash.gpu = make_wordlist(gpu);
					E_opt.dict.wpa.gpu = globals.wordlist;
				}
				else
				{
					E_opt.dict.hash.cpu = globals.wordlist;
					E_opt.dict.wpa.gpu = globals.wordlist;
				}
			}
			else if(globals.bins.cow != NULL)
			{
				if(globals.bins.oclhashcat!=NULL)
				{
					E_opt.dict.hash.gpu = globals.wordlist;
					E_opt.dict.wpa.cpu = make_wordlist(cpu);
					E_opt.dict.wpa.gpu = make_wordlist(gpu);
				}
				else
				{
					E_opt.dict.wpa.cpu = make_wordlist(cpu);
					E_opt.dict.wpa.gpu = make_wordlist(gpu);
				}
			}
			else
			{
				if(globals.bins.oclhashcat!=NULL)
				{
					E_opt.dict.hash.gpu = globals.wordlist;
					E_opt.dict.wpa.gpu = globals.wordlist;
				}
				else
					E_opt.dict.wpa.gpu = globals.wordlist;
			}
		}
		else // no pyrit or oclhashcat available
		{
			if(globals.bins.jtr!=NULL && globals.bins.cow!=NULL)
				E_opt.dict.hash.cpu = E_opt.dict.wpa.cpu = globals.wordlist;
			else if(globals.bins.jtr!=NULL)
				E_opt.dict.hash.cpu = globals.wordlist;
			else if(globals.bins.cow!=NULL)
				E_opt.dict.wpa.cpu = globals.wordlist;
		}

		if(globals.hash_list==NULL)
			E_opt.dict.hash.cpu = E_opt.dict.hash.gpu = NULL;
		if(globals.wpa_list==NULL)
			E_opt.dict.wpa.cpu = E_opt.dict.wpa.gpu = NULL;

	}
	return;
}

void engine_del_opt()
{
	while(E_opt.mem_counter > 0)
		free(E_opt.to_free[--E_opt.mem_counter]);
	return;
}

void engine()
{
	int iter,run,active;
	struct t_info *ttmp=NULL;
	struct winsize term;
	bool print_status;

	engine_init_opt();

	if(globals.rain == true)
		rt_crack();
	if(globals.online == true)
		online_crack();
	if(globals.dict == true)
		dict_crack();


	for(active=0,ttmp=globals.tpool;ttmp!=NULL;ttmp=ttmp->next)
		if(ttmp->state!=done)
			active++;
	if(globals.log_level >= info && isatty(STDOUT_FILENO))
		print_status = true;
	else
		print_status = false;
	for(;active>0;usleep(250 * 1000))
	{
		if(print_status == true)
		{
			ioctl(STDOUT_FILENO, TIOCGWINSZ,&term);
			printf("%-*c\r",term.ws_col,' '); // clean stdout
			fflush(stdout);
		}

		pthread_mutex_lock(&pool_lock);
		for(run=active=0,ttmp=globals.tpool;ttmp!=NULL;)
		{
			if(ttmp->state == done)
			{
				//pthread_join(ttmp->thread,NULL);
				if(ttmp->bin != NULL && ttmp->outfile != NULL) // otherwise is online_crack
				{
					pthread_mutex_unlock(&pool_lock);
					P_prog_output(ttmp);
					remove(ttmp->outfile);
					ttmp->outfile=NULL; // so destroy_all don't try to remove this
					pthread_mutex_lock(&pool_lock);
				}
				ttmp->state = parsed;
			}
			else
			{
				if(ttmp->state == running)
				{
					run++;
					active++;
				}
				else if(ttmp->state == waiting)
					active++;
				ttmp = ttmp->next;
			}
		}
		pthread_mutex_unlock(&pool_lock);

		if(print_status == true)
		{
			ioctl(STDOUT_FILENO, TIOCGWINSZ,&term);
			iter = printf("running threads: %d/%d",run,active);
			printf("%-*c\r",(term.ws_col)-iter,' ');
			fflush(stdout);
		}
	}
	if(print_status == true)
	{
		ioctl(STDOUT_FILENO, TIOCGWINSZ,&term);
		printf("%-*c\r",term.ws_col,' '); // clean stdout
	}

	return;
}