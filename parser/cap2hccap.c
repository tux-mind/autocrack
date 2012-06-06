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

#ifdef UINT16
	#define u_int16_t UINT16;
#endif
#include "pcap.h"
#include "byteorder.h"
#define BROADCAST (uchar*)"\xFF\xFF\xFF\xFF\xFF\xFF"
#define SWAP32(x)       \
    x = ( ( ( x >> 24 ) & 0x000000FF ) | \
          ( ( x >>  8 ) & 0x0000FF00 ) | \
          ( ( x <<  8 ) & 0x00FF0000 ) | \
          ( ( x << 24 ) & 0xFF000000 ) );
/* workaround for arm compiling */
#ifndef O_BINARY
	#define O_BINARY 0
#endif
#ifndef F_SETFL
	#define F_SETFL 4
#endif
#ifndef O_NONBLOCK
	#define O_NONBLOCK 04000
#endif
typedef struct
{
	int off1;
	int off2;
	void *buf1;
	void *buf2;
}
read_buf;

struct wpa_hdsk
{
	unsigned char stmac[6];
	unsigned char snonce[32];
	unsigned char anonce[32];
	unsigned char keymic[16];
	unsigned char eapol[256];
	int eapol_size;
	int keyver;
	int state;
};

struct	apoint
{
	unsigned char bssid[6];
	char essid[33];
	int crypt;
	struct	station *st_lst;
	hccap_t	wpa;
	struct pcap_pkthdr pkts[5];
	struct	apoint *next;
};

struct station
{
	unsigned char mac[6];
	struct apoint 	*parent;
	struct wpa_hdsk	wpa;
	struct station	*next;
};

struct good_pkt
{
	struct pcap_pkthdr *pkh;
	struct good_pkt *next;
};

int atomic_read( read_buf *rb, int fd, int len, void *buf )
{
	int n;

	if( rb->buf1 == NULL )
	{
		rb->buf1 = malloc( 65536 );
		rb->buf2 = malloc( 65536 );

		rb->off1 = 0;
		rb->off2 = 0;
	}

	if( len > 65536 - rb->off1 )
	{
		rb->off2 -= rb->off1;

		memcpy( rb->buf2, rb->buf1 + rb->off1, rb->off2 );
		memcpy( rb->buf1, rb->buf2, rb->off2 );

		rb->off1 = 0;
	}

	if( rb->off2 - rb->off1 >= len )
	{
		memcpy( buf, rb->buf1 + rb->off1, len );
		rb->off1 += len;
		return( 1 );
	}
	else
	{
		n = read( fd, rb->buf1 + rb->off2, 65536 - rb->off2 );

		if( n <= 0 )
			return( 0 );

		rb->off2 += n;

		if( rb->off2 - rb->off1 >= len )
		{
			memcpy( buf, rb->buf1 + rb->off1, len );
			rb->off1 += len;
			return( 1 );
		}
	}

	return( 0 );
}

void add_pkh(struct good_pkt **list, struct pcap_pkthdr *pkh)
{
	struct good_pkt *iter=NULL,*prev=NULL;
	size_t pkh_sz;

	static uchar ZERO[32] =
	"\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00";

	pkh_sz = sizeof(struct pcap_pkthdr);

	if(!memcmp(pkh,ZERO,pkh_sz))
		return;

	if(*list==NULL)
	{
		*list = iter = malloc(sizeof(struct good_pkt));
		iter->pkh = malloc(pkh_sz);
		memcpy(iter->pkh,pkh,pkh_sz);
		iter->next = NULL;
		return;
	}

	for(iter=*list;iter!=NULL && memcmp(iter->pkh,pkh,pkh_sz);prev=iter,iter=iter->next);
	if(iter!=NULL) // pkh is already in list
		return;
	prev->next = iter = malloc(sizeof(struct good_pkt));
	iter->pkh = malloc(pkh_sz);
	memcpy(iter->pkh,pkh,pkh_sz);
	iter->next=NULL;
	return;
}

void del_pkh(struct good_pkt **list, struct pcap_pkthdr *pkh)
{
	struct good_pkt *iter=NULL,*prev=NULL;
	size_t pkh_sz;

	pkh_sz = sizeof(struct pcap_pkthdr);

	if((iter=*list)==NULL)
		return;
	while(iter!=NULL)
		if(!memcmp(iter->pkh,pkh,pkh_sz))
			if(prev==NULL) // remove the first item of the list
			{
				prev = iter;
				*list = iter = iter->next;
				free((void *) prev->pkh);
				free((void *) prev);
				prev = NULL;
			}
			else
			{
				prev->next = iter->next;
				free((void *) iter->pkh);
				free((void *) iter);
				iter=prev->next;
			}
		else
		{
			prev=iter;
			iter=iter->next;
		}
	return;
}

void write_pcap(struct good_pkt *good_pkts, const char *file)
{
	int fd,outfile,n;
	read_buf rb;
	uchar *buffer,*h80211;
	struct pcap_pkthdr pkh;
	struct good_pkt *iter=NULL,*prev=NULL;
	struct pcap_file_header pfh;
	size_t pkh_sz;

	pkh_sz = sizeof(struct pcap_pkthdr);

	// errors not checked, because the caller check them first. ( except globals.pcap )
	memset( &rb, 0, sizeof( rb ) );
	fd = open( file, O_RDONLY | O_BINARY );
	atomic_read( &rb, fd, 24, &pfh );

	if(globals.pcap==NULL)
	{
		globals.pcap = malloc(L_tmpnam*sizeof(char));
		tmpnam((char *) globals.pcap);
		if((outfile = open(globals.pcap,O_BINARY | O_CREAT | O_WRONLY , S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)) == -1)
		{
			report_error(globals.pcap,1,0,error);
			return;
		}
		write(outfile,&pfh,sizeof(pfh));
	}
	else if((outfile = open(globals.pcap,O_BINARY | O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)) == -1)
	{
		report_error(globals.pcap,1,0,error);
		return;
	}

	buffer = malloc(65536);

	while( atomic_read( &rb, fd, sizeof( pkh ), &pkh ))
	{
		atomic_read( &rb, fd, pkh.caplen, buffer );

		h80211 = buffer;

		if( pfh.linktype == LINKTYPE_PRISM_HEADER )
		{
			if( h80211[7] == 0x40 )
				n = 64;
			else
			{
				n = *(int *)( h80211 + 4 );
				if( pfh.magic == TCPDUMP_CIGAM )
					SWAP32( n );
			}
			if( n < 8 || n >= (int) pkh.caplen )
				continue;
			h80211 += n; pkh.caplen -= n;
		}

		if( pfh.linktype == LINKTYPE_RADIOTAP_HDR )
		{
			n = *(unsigned short *)( h80211 + 2 );
			if( n <= 0 || n >= (int) pkh.caplen )
				continue;
			h80211 += n; pkh.caplen -= n;
		}

		if( pfh.linktype == LINKTYPE_PPI_HDR )
		{
			n = le16_to_cpu(*(unsigned short *)( h80211 + 2));
			if( n <= 0 || n>= (int) pkh.caplen )
				continue;
			if ( n == 24 && le16_to_cpu(*(unsigned short *)(h80211 + 8)) == 2 )
				n = 32;
			if( n <= 0 || n>= (int) pkh.caplen )
				continue;
			h80211 += n; pkh.caplen -= n;
		}

		if( pkh.caplen < 24 )
			continue;
		for(iter=good_pkts;iter!=NULL;iter=iter->next)
			if(!memcmp(iter->pkh,&pkh,pkh_sz))
				break;
		if(iter!=NULL)
		{
			write(outfile,&pkh,pkh_sz);
			write(outfile,buffer,pkh.caplen);
			del_pkh(&good_pkts,&pkh);
		}
	}

	close(fd);
	close(outfile);
	free((void *) buffer);
	for(iter=good_pkts;iter!=NULL;prev=iter,iter=iter->next,free((void *) prev))
		free((void *) iter->pkh);
	if(rb.buf1!=NULL)
		free((void *) rb.buf1);
	if(rb.buf2!=NULL)
		free((void *) rb.buf2);
	return;
}

void cap2hccap(const char *arg)
{
	int fd, n, z;
	read_buf rb;
	FILE 	*fp_hccap;
	uchar *buffer,
				*h80211,
				*p;
	char	*name_hccap;
	static uchar ZERO[32] =
	"\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00";
	unsigned char bssid[6],dest[6],stmac[6];

	struct pcap_pkthdr pkh;
	struct good_pkt *good_pkts=NULL;
	struct pcap_file_header pfh;
	struct apoint		*ap_lst=NULL,*ap_cur,*ap_prev;
	struct station	*st_cur,*st_prev;
	size_t pkh_sz;

	pkh_sz = sizeof(struct pcap_pkthdr);

	memset( &rb, 0, sizeof( rb ) );
	fd = 0;

	buffer = (uchar *) malloc( 65536 );

	h80211 = buffer;
	globals.err_buff[0] = '\0';

	if( arg == NULL )
		report_error("called with NULL argument.",0,1,error);
	else if( ( fd = open( arg, O_RDONLY | O_BINARY ) ) < 0 )
		strncpy(globals.err_buff, arg,MAX_BUFF);
	else if( ! atomic_read( &rb, fd, 4, &pfh ) )
		strncpy(globals.err_buff, arg,MAX_BUFF);
	else if( pfh.magic != TCPDUMP_MAGIC && pfh.magic != TCPDUMP_CIGAM )
		snprintf(globals.err_buff,MAX_BUFF,"file \"%s\" is not a valid pcap file.", arg);
	else if( ! atomic_read( &rb, fd, 20, (uchar *) &pfh + 4 ) )
		snprintf(globals.err_buff,MAX_BUFF,"reading header from file \"%s\".", arg);
	else if( fcntl( fd, F_SETFL, O_NONBLOCK ) < 0 )
		snprintf(globals.err_buff,MAX_BUFF,"setting non blocking access on file \"%s\".", arg);
	else
	{
		if( pfh.magic == TCPDUMP_CIGAM )
			SWAP32( pfh.linktype );

		if( pfh.linktype != LINKTYPE_IEEE802_11 &&
				pfh.linktype != LINKTYPE_PRISM_HEADER &&
				pfh.linktype != LINKTYPE_RADIOTAP_HDR &&
				pfh.linktype != LINKTYPE_PPI_HDR )
			snprintf(globals.err_buff,MAX_BUFF,"file \"%s\" is not a 802.11 (wireless) capture.", arg);
	}

	if(globals.err_buff[0] != '\0')
	{
		if(strncmp(globals.err_buff,arg,MAX_BUFF) == 0)
		{
			snprintf(globals.err_buff,MAX_BUFF,"\"%s\"",arg);
			report_error(globals.err_buff,1,0,error);
		}
		else
			report_error(globals.err_buff,0,0,error);

		if(fd != 0)
			close(fd);
		free(buffer);
		if(rb.buf1!=NULL)
			free(rb.buf1);
		if(rb.buf2!=NULL)
			free(rb.buf2);
		return;
	}

	while( atomic_read( &rb, fd, sizeof( pkh ), &pkh ))
	{
		if( pfh.magic == TCPDUMP_CIGAM )
			SWAP32( pkh.caplen );

		if( pkh.caplen <= 0 || pkh.caplen > 65535 )
		{
			report_error("invalid packet capture length.",0,0,error);
			report_error("probably capture file is corrupted.",0,0,verbose);
			break;
		}

		if( ! atomic_read( &rb, fd, pkh.caplen, buffer ) )
		{
			report_error("cannot read packet data.",0,0,error);
			break;
		}

		h80211 = buffer;

		if( pfh.linktype == LINKTYPE_PRISM_HEADER )
		{
			/* remove the prism header */

			if( h80211[7] == 0x40 )
				n = 64;
			else
			{
				n = *(int *)( h80211 + 4 );

				if( pfh.magic == TCPDUMP_CIGAM )
					SWAP32( n );
			}

			if( n < 8 || n >= (int) pkh.caplen )
				continue;

			h80211 += n; pkh.caplen -= n;
		}

		if( pfh.linktype == LINKTYPE_RADIOTAP_HDR )
		{
			/* remove the radiotap header */

			n = *(unsigned short *)( h80211 + 2 );

			if( n <= 0 || n >= (int) pkh.caplen )
				continue;

			h80211 += n; pkh.caplen -= n;
		}

		if( pfh.linktype == LINKTYPE_PPI_HDR )
		{
			/* Remove the PPI header */

			n = le16_to_cpu(*(unsigned short *)( h80211 + 2));

			if( n <= 0 || n>= (int) pkh.caplen )
				continue;

			/* for a whole Kismet logged broken PPI headers */
			if ( n == 24 && le16_to_cpu(*(unsigned short *)(h80211 + 8)) == 2 )
				n = 32;

			if( n <= 0 || n>= (int) pkh.caplen )
				continue;

			h80211 += n; pkh.caplen -= n;
		}

		/* skip packets smaller than a 802.11 header */

		if( pkh.caplen < 24 )
			continue;

		/* skip (uninteresting) control frames */

		if( ( h80211[0] & 0x0C ) == 0x04 )
			continue;

		/* locate the access point's MAC address */

		switch( h80211[1] & 3 )
		{
			case  0: memcpy( bssid, h80211 + 16, 6 ); break;  //Adhoc
			case  1: memcpy( bssid, h80211 +  4, 6 ); break;  //ToDS
			case  2: memcpy( bssid, h80211 + 10, 6 ); break;  //FromDS
			case  3: memcpy( bssid, h80211 + 10, 6 ); break;  //WDS -> Transmitter taken as BSSID
		}

		switch( h80211[1] & 3 )
		{
			case  0: memcpy( dest, h80211 +  4, 6 ); break;  //Adhoc
			case  1: memcpy( dest, h80211 + 16, 6 ); break;  //ToDS
			case  2: memcpy( dest, h80211 +  4, 6 ); break;  //FromDS
			case  3: memcpy( dest, h80211 + 16, 6 ); break;  //WDS -> Transmitter taken as BSSID
		}

		if( memcmp( bssid, BROADCAST, 6 ) == 0 )
			continue;

		/* locate the station MAC in the 802.11 header */

		memcpy(stmac,BROADCAST,6); // used as flag

		switch( h80211[1] & 3 )
		{
			case  0: 	memcpy( stmac, h80211 + 10, 6 ); break;
			case  1: 	memcpy( stmac, h80211 + 10, 6 ); break;
			case  2:
								if( (h80211[4]%2) == 0 ) /* if is a broadcast packet */
									memcpy( stmac, h80211 +  4, 6 );
								break;
		}

		/* search if access point already exist */

		ap_prev = NULL;
		ap_cur = ap_lst;
		for(ap_cur=ap_lst;ap_cur!=NULL;ap_prev=ap_cur,ap_cur=ap_cur->next)
			if( ! memcmp( ap_cur->bssid, bssid, 6 ) )
				break;

		if(ap_cur == NULL)
		{
			ap_cur = malloc(sizeof(struct apoint));
			if(ap_lst == NULL)
				ap_lst = ap_cur;
			else
				ap_prev->next = ap_cur;

			memcpy(ap_cur->bssid,bssid,6);
			ap_cur->crypt = -1;
		}

		/* search if station already exist */

		st_cur = NULL;

		if(memcmp(stmac,BROADCAST,6) != 0 && memcmp(ap_cur->bssid, stmac,6) != 0)
		{

			for(st_prev = NULL, st_cur=ap_cur->st_lst;
					st_cur != NULL; st_prev = st_cur, st_cur = st_cur->next)
				if( ! memcmp( st_cur->mac, stmac, 6) )
					break;

			/* if it's a new supplicant, add it */

			if( st_cur == NULL )
			{
				st_cur = malloc(sizeof(struct station));

				if( ap_cur->st_lst == NULL )
					ap_cur->st_lst = st_cur;
				else
					st_prev->next = st_cur;

				memcpy( st_cur->mac, stmac, 6 );
			}
		}

		/* packet parsing: Beacon or Probe Response */

		if( h80211[0] == 0x80 ||
				h80211[0] == 0x50 )
		{
			if( ap_cur->crypt < 0 )
				ap_cur->crypt = ( h80211[34] & 0x10 ) >> 4;

			p = h80211 + 36;

			while( p < h80211 + pkh.caplen )
			{
				if( p + 2 + p[1] > h80211 + pkh.caplen )
					break;

				if( p[0] == 0x00 && p[1] > 0 && p[2] != '\0' )
				{
					/* found a non-cloaked ESSID */
					if(!memcmp(&(ap_cur->pkts[0]),ZERO,pkh_sz))
						memcpy(&(ap_cur->pkts[0]),&pkh,pkh_sz);
					n = ( p[1] > 32 ) ? 32 : p[1];
					memset( ap_cur->essid, 0, 33 );
					memcpy( ap_cur->essid, p + 2, n );
				}
				p += 2 + p[1];
			}
		}

		/* packet parsing: Association Request */

		if( h80211[0] == 0x00 )
		{
			p = h80211 + 28;
			while( p < h80211 + pkh.caplen )
			{
				if( p + 2 + p[1] > h80211 + pkh.caplen )
					break;
				if( p[0] == 0x00 && p[1] > 0 && p[2] != '\0' )
				{
					if(!memcmp(&(ap_cur->pkts[0]),ZERO,pkh_sz))
						memcpy(&(ap_cur->pkts[0]),&pkh,pkh_sz);
					n = ( p[1] > 32 ) ? 32 : p[1];
					memset( ap_cur->essid, 0, 33 );
					memcpy( ap_cur->essid, p + 2, n );
				}
				st_cur->wpa.state = 0;
				p += 2 + p[1];
			}
		}

		/* packet parsing: Association Response */

		if( h80211[0] == 0x10 )
			if(st_cur != NULL)
				st_cur->wpa.state = 0;

		/* check if data and station isn't the bssid */

		if( ( h80211[0] & 0x0C ) != 0x08 || st_cur == NULL )
			continue;

		/* check minimum size */

		z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;
		if ( ( h80211[0] & 0x80 ) == 0x80 )
			z+=2; /* 802.11e QoS */

		if( z + 16 > (int) pkh.caplen )
			continue;

		/* check the SNAP header to see if data is WEP encrypted */

		if( ( h80211[z] != h80211[z + 1] || h80211[z + 2] != 0x03 ) && (h80211[z + 3] & 0x20) != 0)
			ap_cur->crypt = 3;

		/* no encryption */
		if( ap_cur->crypt < 0 )
			ap_cur->crypt = 0;

		z += 6;

		/* check ethertype == EAPOL */

		if( h80211[z] != 0x88 || h80211[z + 1] != 0x8E )
			continue;

		z += 2;

		/* type == 3 (key), desc. == 254 (WPA) or 2 (RSN) */

		if( h80211[z + 1] != 0x03 ||
			( h80211[z + 4] != 0xFE && h80211[z + 4] != 0x02 ) )
			continue;

		ap_cur->crypt = 3;		 /* set WPA */

		/* frame 1: Pairwise == 1, Install == 0, Ack == 1, MIC == 0 */

		if( ( h80211[z + 6] & 0x08 ) != 0 &&
			( h80211[z + 6] & 0x40 ) == 0 &&
			( h80211[z + 6] & 0x80 ) != 0 &&
			( h80211[z + 5] & 0x01 ) == 0 )
		{
			memcpy( st_cur->wpa.anonce, &h80211[z + 17], 32 );
			memcpy(&(ap_cur->pkts[1]),&pkh,pkh_sz);
			/* authenticator nonce set */
			st_cur->wpa.state = 1;
		}

		/* frame 2 or 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1 */

		if(( h80211[z + 6] & 0x08 ) != 0 &&
			( h80211[z + 6] & 0x40 ) == 0 &&
			( h80211[z + 6] & 0x80 ) == 0 &&
			( h80211[z + 5] & 0x01 ) != 0 )
		{
			if( memcmp( &h80211[z + 17], ZERO, 32 ) != 0 )
			{
				memcpy( st_cur->wpa.snonce, &h80211[z + 17], 32 );
				memcpy(&(ap_cur->pkts[2]),&pkh,pkh_sz);
				/* supplicant nonce set */
				st_cur->wpa.state |= 2;
			}

			if( (st_cur->wpa.state & 4) != 4 )
			{
				/* copy the MIC & eapol frame */

				st_cur->wpa.eapol_size = ( h80211[z + 2] << 8 )
					+   h80211[z + 3] + 4;

				if ((int)pkh.len - z < st_cur->wpa.eapol_size )
					// Ignore the packet trying to crash us.
					continue;

				memcpy( st_cur->wpa.keymic, &h80211[z + 81], 16 );
				memcpy( st_cur->wpa.eapol,  &h80211[z], st_cur->wpa.eapol_size );
				memset( st_cur->wpa.eapol + 81, 0, 16 );

				/* eapol frame & keymic set */
				memcpy(&(ap_cur->pkts[4]),&pkh,pkh_sz);
				st_cur->wpa.state |= 4;

				/* copy the key descriptor version */

				st_cur->wpa.keyver = h80211[z + 6] & 7;
			}
		}

		/* frame 3: Pairwise == 1, Install == 1, Ack == 1, MIC == 1 */

		if( ( h80211[z + 6] & 0x08 ) != 0 &&
			( h80211[z + 6] & 0x40 ) != 0 &&
			( h80211[z + 6] & 0x80 ) != 0 &&
			( h80211[z + 5] & 0x01 ) != 0 )
		{
			if( memcmp( &h80211[z + 17], ZERO, 32 ) != 0 )
			{
				memcpy( st_cur->wpa.anonce, &h80211[z + 17], 32 );

								 /* authenticator nonce set */
				memcpy(&(ap_cur->pkts[3]),&pkh,pkh_sz);
				st_cur->wpa.state |= 1;
			}

			if( (st_cur->wpa.state & 4) != 4 )
			{
				/* copy the MIC & eapol frame */

				st_cur->wpa.eapol_size = ( h80211[z + 2] << 8 )
					+   h80211[z + 3] + 4;

				if ((int)pkh.len - z < st_cur->wpa.eapol_size )
					continue;

				memcpy( st_cur->wpa.keymic, &h80211[z + 81], 16 );
				memcpy( st_cur->wpa.eapol,  &h80211[z], st_cur->wpa.eapol_size );
				memset( st_cur->wpa.eapol + 81, 0, 16 );

				/* eapol frame & keymic set */
				memcpy(&(ap_cur->pkts[4]),&pkh,pkh_sz);
				st_cur->wpa.state |= 4;

				/* copy the key descriptor version */

				st_cur->wpa.keyver = h80211[z + 6] & 7;
			}
		}

		if( st_cur->wpa.state == 7 )
		{
			/* got one valid handshake */
			/* TODO: write this handshake only if it's quality ( how to know it ? ) is better then the previous one. */

			memcpy (&(ap_cur->wpa.essid),      &ap_cur->essid,          sizeof (ap_cur->essid));
			memcpy (&(ap_cur->wpa.mac1),       &ap_cur->bssid,          sizeof (ap_cur->bssid));
			memcpy (&(ap_cur->wpa.mac2),       &stmac,      						sizeof (st_cur->wpa.stmac));
			memcpy (&(ap_cur->wpa.nonce1),     &st_cur->wpa.snonce,     sizeof (st_cur->wpa.snonce));
			memcpy (&(ap_cur->wpa.nonce2),     &st_cur->wpa.anonce,     sizeof (st_cur->wpa.anonce));
			memcpy (&(ap_cur->wpa.eapol),      &st_cur->wpa.eapol,      sizeof (st_cur->wpa.eapol));
			memcpy (&(ap_cur->wpa.eapol_size), &st_cur->wpa.eapol_size, sizeof (st_cur->wpa.eapol_size));
			memcpy (&(ap_cur->wpa.keyver),     &st_cur->wpa.keyver,     sizeof (st_cur->wpa.keyver));
			memcpy (&(ap_cur->wpa.keymic),     &st_cur->wpa.keymic,     sizeof (st_cur->wpa.keymic));
			if(memcmp(ap_cur->essid,ZERO,32)) // if a valid essid has been found for this handshake.
				for(n=0;n<5;n++)
					add_pkh(&good_pkts,&(ap_cur->pkts[n]));
			memset(&(ap_cur->pkts), 0, 5*sizeof(struct pcap_pkthdr));
			/* reset wpa handshake completation */
			st_cur->wpa.state = 0;
		}
	}

	/* find the first valid handshake */
	for(ap_cur=ap_lst;ap_cur!=NULL;ap_prev=ap_cur,ap_cur=ap_cur->next,free((void *) ap_prev))
	{
		if( memcmp(&(ap_cur->wpa), ZERO, 32) != 0)
			break;
		for(st_cur=ap_cur->st_lst;st_cur!=NULL;st_prev=st_cur,st_cur=st_cur->next,free((void *) st_prev));
	}

	name_hccap = NULL;
	if(ap_cur!=NULL)
	{
		if(globals.hccap==NULL)
		{
			name_hccap = malloc(L_tmpnam*sizeof(char));
			tmpnam(name_hccap);
			argcpy((const char **) &(globals.hccap),name_hccap,L_tmpnam+1);
		}
		else
		{
			pkh_sz = strlen(globals.hccap)+1;
			argcpy((const char **) &name_hccap,globals.hccap,pkh_sz);
		}
		if(good_pkts!=NULL)
			write_pcap(good_pkts,arg);
	}

	/* write unique handshakes to file and free access point data */
	for(;ap_cur!=NULL;ap_prev=ap_cur,ap_cur=ap_cur->next,free((void *) ap_prev))
	{
		if(memcmp(&(ap_cur->wpa), ZERO, 32) != 0)
		{
			/* there is a valid handshake for this access point */
			snprintf(globals.err_buff,MAX_BUFF,"found handshake for \"%s\".",ap_cur->wpa.essid);
			report_error(globals.err_buff,0,0,verbose);
			add_wpa(ap_cur->wpa.essid,&(ap_cur->wpa));

			if( (fp_hccap = fopen(name_hccap,"a")) == NULL)
				report_error(name_hccap,1,0,error);
			else if(fwrite(&(ap_cur->wpa),sizeof(hccap_t),1,fp_hccap) != 1)
			{
				snprintf(globals.err_buff,MAX_BUFF,"failed to write on file \"%s\".",name_hccap);
				report_error(globals.err_buff,0,0,error);
			}
			else
			{
				if(globals.hccap==NULL)
					argcpy(&(globals.hccap),name_hccap,L_tmpnam);
				fclose(fp_hccap);
				fp_hccap = NULL;
			}
			if(fp_hccap != NULL)
				fclose(fp_hccap);
		}
		for(st_cur=ap_cur->st_lst;st_cur!=NULL;st_prev=st_cur,st_cur=st_cur->next,free((void *) st_prev));
	}

	if(name_hccap!=NULL)
		free((void *) name_hccap);

	if(rb.buf1 != NULL)
	{
		free(rb.buf1);
		rb.buf1 = NULL;
	}
	if(rb.buf2 != NULL)
	{
		free(rb.buf2);
		rb.buf2 = NULL;
	}
	if(buffer != NULL)
	{
		free((void *) buffer);
		buffer = NULL;
	}

	return;

}
