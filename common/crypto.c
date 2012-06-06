#include "crypto.h"

/* derive the PMK from the passphrase and the essid.
 * this function is taken from aircrack-ng suite.
 */
void calc_pmk( char *key, char *essid_pre, uchar pmk[40] )
{
	int i, j, slen;
	uchar buffer[65];
	char essid[33+4];
	SHA_CTX ctx_ipad;
	SHA_CTX ctx_opad;
	SHA_CTX sha1_ctx;

	memset(essid, 0, sizeof(essid));
	memcpy(essid, essid_pre, strlen(essid_pre));
	slen = strlen( essid ) + 4;

	/* setup the inner and outer contexts */

	memset( buffer, 0, sizeof( buffer ) );
	strncpy( (char *) buffer, key, sizeof( buffer ) - 1 );

	for( i = 0; i < 64; i++ )
		buffer[i] ^= 0x36;

	SHA1_Init( &ctx_ipad );
	SHA1_Update( &ctx_ipad, buffer, 64 );

	for( i = 0; i < 64; i++ )
		buffer[i] ^= 0x6A;

	SHA1_Init( &ctx_opad );
	SHA1_Update( &ctx_opad, buffer, 64 );

	/* iterate HMAC-SHA1 over itself 8192 times */

	essid[slen - 1] = '\1';
	HMAC(EVP_sha1(), (uchar *)key, strlen(key), (uchar*)essid, slen, pmk, NULL);
	memcpy( buffer, pmk, 20 );

	for( i = 1; i < 4096; i++ )
	{
		memcpy( &sha1_ctx, &ctx_ipad, sizeof( sha1_ctx ) );
		SHA1_Update( &sha1_ctx, buffer, 20 );
		SHA1_Final( buffer, &sha1_ctx );

		memcpy( &sha1_ctx, &ctx_opad, sizeof( sha1_ctx ) );
		SHA1_Update( &sha1_ctx, buffer, 20 );
		SHA1_Final( buffer, &sha1_ctx );

		for( j = 0; j < 20; j++ )
			pmk[j] ^= buffer[j];
	}

	essid[slen - 1] = '\2';
	HMAC(EVP_sha1(), (uchar *)key, strlen(key), (uchar*)essid, slen, pmk+20, NULL);
	memcpy( buffer, pmk + 20, 20 );

	for( i = 1; i < 4096; i++ )
	{
		memcpy( &sha1_ctx, &ctx_ipad, sizeof( sha1_ctx ) );
		SHA1_Update( &sha1_ctx, buffer, 20 );
		SHA1_Final( buffer, &sha1_ctx );

		memcpy( &sha1_ctx, &ctx_opad, sizeof( sha1_ctx ) );
		SHA1_Update( &sha1_ctx, buffer, 20 );
		SHA1_Final( buffer, &sha1_ctx );

		for( j = 0; j < 20; j++ )
			pmk[j + 20] ^= buffer[j];
	}
}

char *ntlm_crypt(char *key)
{
	int i,j;
	int length=strlen(key);
	unsigned int 	nt_buffer[16],
								a,b,c,d,sqrt2,sqrt3,n,
								output[4];
	static char hex_format[33];
	char itoa16[16] = "0123456789abcdef";

	memset(nt_buffer,0,16*sizeof(unsigned int));
	//The length of key need to be <= 27
	for(i=0;i<length/2;i++)
		nt_buffer[i] = key[2*i] | (key[2*i+1]<<16);

	//padding
	if(length%2==1)
		nt_buffer[i] = key[length-1] | 0x800000;
	else
		nt_buffer[i]=0x80;
	//put the length
	nt_buffer[14] = length << 4;

	output[0] = a = 0x67452301;
	output[1] = b = 0xefcdab89;
	output[2] = c = 0x98badcfe;
	output[3] = d = 0x10325476;
	sqrt2 = 0x5a827999;
	sqrt3 = 0x6ed9eba1;

	/* Round 1 */
	a += (d ^ (b & (c ^ d)))  +  nt_buffer[0]  ;a = (a << 3 ) | (a >> 29);
	d += (c ^ (a & (b ^ c)))  +  nt_buffer[1]  ;d = (d << 7 ) | (d >> 25);
	c += (b ^ (d & (a ^ b)))  +  nt_buffer[2]  ;c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a)))  +  nt_buffer[3]  ;b = (b << 19) | (b >> 13);

	a += (d ^ (b & (c ^ d)))  +  nt_buffer[4]  ;a = (a << 3 ) | (a >> 29);
	d += (c ^ (a & (b ^ c)))  +  nt_buffer[5]  ;d = (d << 7 ) | (d >> 25);
	c += (b ^ (d & (a ^ b)))  +  nt_buffer[6]  ;c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a)))  +  nt_buffer[7]  ;b = (b << 19) | (b >> 13);

	a += (d ^ (b & (c ^ d)))  +  nt_buffer[8]  ;a = (a << 3 ) | (a >> 29);
	d += (c ^ (a & (b ^ c)))  +  nt_buffer[9]  ;d = (d << 7 ) | (d >> 25);
	c += (b ^ (d & (a ^ b)))  +  nt_buffer[10] ;c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a)))  +  nt_buffer[11] ;b = (b << 19) | (b >> 13);

	a += (d ^ (b & (c ^ d)))  +  nt_buffer[12] ;a = (a << 3 ) | (a >> 29);
	d += (c ^ (a & (b ^ c)))  +  nt_buffer[13] ;d = (d << 7 ) | (d >> 25);
	c += (b ^ (d & (a ^ b)))  +  nt_buffer[14] ;c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a)))  +  nt_buffer[15] ;b = (b << 19) | (b >> 13);

	/* Round 2 */
	a += ((b & (c | d)) | (c & d)) + nt_buffer[0] +sqrt2; a = (a<<3 ) | (a>>29);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[4] +sqrt2; d = (d<<5 ) | (d>>27);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[8] +sqrt2; c = (c<<9 ) | (c>>23);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[12]+sqrt2; b = (b<<13) | (b>>19);

	a += ((b & (c | d)) | (c & d)) + nt_buffer[1] +sqrt2; a = (a<<3 ) | (a>>29);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[5] +sqrt2; d = (d<<5 ) | (d>>27);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[9] +sqrt2; c = (c<<9 ) | (c>>23);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[13]+sqrt2; b = (b<<13) | (b>>19);

	a += ((b & (c | d)) | (c & d)) + nt_buffer[2] +sqrt2; a = (a<<3 ) | (a>>29);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[6] +sqrt2; d = (d<<5 ) | (d>>27);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[10]+sqrt2; c = (c<<9 ) | (c>>23);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[14]+sqrt2; b = (b<<13) | (b>>19);

	a += ((b & (c | d)) | (c & d)) + nt_buffer[3] +sqrt2; a = (a<<3 ) | (a>>29);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[7] +sqrt2; d = (d<<5 ) | (d>>27);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[11]+sqrt2; c = (c<<9 ) | (c>>23);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[15]+sqrt2; b = (b<<13) | (b>>19);

	/* Round 3 */
	a += (d ^ c ^ b) + nt_buffer[0]  +  sqrt3; a = (a << 3 ) | (a >> 29);
	d += (c ^ b ^ a) + nt_buffer[8]  +  sqrt3; d = (d << 9 ) | (d >> 23);
	c += (b ^ a ^ d) + nt_buffer[4]  +  sqrt3; c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + nt_buffer[12] +  sqrt3; b = (b << 15) | (b >> 17);

	a += (d ^ c ^ b) + nt_buffer[2]  +  sqrt3; a = (a << 3 ) | (a >> 29);
	d += (c ^ b ^ a) + nt_buffer[10] +  sqrt3; d = (d << 9 ) | (d >> 23);
	c += (b ^ a ^ d) + nt_buffer[6]  +  sqrt3; c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + nt_buffer[14] +  sqrt3; b = (b << 15) | (b >> 17);

	a += (d ^ c ^ b) + nt_buffer[1]  +  sqrt3; a = (a << 3 ) | (a >> 29);
	d += (c ^ b ^ a) + nt_buffer[9]  +  sqrt3; d = (d << 9 ) | (d >> 23);
	c += (b ^ a ^ d) + nt_buffer[5]  +  sqrt3; c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + nt_buffer[13] +  sqrt3; b = (b << 15) | (b >> 17);

	a += (d ^ c ^ b) + nt_buffer[3]  +  sqrt3; a = (a << 3 ) | (a >> 29);
	d += (c ^ b ^ a) + nt_buffer[11] +  sqrt3; d = (d << 9 ) | (d >> 23);
	c += (b ^ a ^ d) + nt_buffer[7]  +  sqrt3; c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + nt_buffer[15] +  sqrt3; b = (b << 15) | (b >> 17);

	output[0] += a;
	output[1] += b;
	output[2] += c;
	output[3] += d;
	//Iterate the integer
	for(i=0;i<4;i++)
		for(j=0,n=output[i];j<4;j++)
		{
			unsigned int convert=n%256;
			hex_format[i*8+j*2+1]=itoa16[convert%16];
			convert=convert/16;
			hex_format[i*8+j*2+0]=itoa16[convert%16];
			n=n/256;
		}
	//null terminate the string
	hex_format[33]=0;
	return hex_format;
}

char *md5_crypt(unsigned char *string)
{
	unsigned char *digest;
	static char hex_format[33];
	int i;
	digest = MD5(string,strlen((char *) string),NULL);
	for(i=0;i<16;i++)
		sprintf(&hex_format[i*2],"%02x",(unsigned int) digest[i]);
	hex_format[32] = '\0';
	return hex_format;
}

char *sha1_crypt(unsigned char *string)
{
	unsigned char *digest;
	static char hex_format[41];
	int i;
	digest = SHA1(string,strlen((char *) string),NULL);
	for(i=0;i<20;i++)
		sprintf(&hex_format[i*2],"%02x",(unsigned int) digest[i]);
	hex_format[40] = '\0';
	return hex_format;
}

char *sha256_crypt(unsigned char *string)
{
	static char hex_format[65];
	unsigned char hash[SHA256_DIGEST_LENGTH];
	int i;
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, string, strlen((char *) string));
	SHA256_Final(hash, &sha256);
	for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
			sprintf(&hex_format[i*2], "%02x", (unsigned int) hash[i]);
	hex_format[64] = '\0';
	return hex_format;
}

char *sha384_crypt(unsigned char *string)
{
	static char hex_format[99];
	unsigned char hash[SHA384_DIGEST_LENGTH];
	int i;
	SHA512_CTX sha384;
	SHA384_Init(&sha384);
	SHA384_Update(&sha384, string, strlen((char *) string));
	SHA384_Final(hash, &sha384);
	for(i=0;i<SHA384_DIGEST_LENGTH;i++)
		sprintf(&hex_format[i*2],"%02x",(unsigned int) hash[i]);
	hex_format[98] = '\0';
	return hex_format;
}

char *sha512_crypt(unsigned char *string)
{
	static char hex_format[129];
	unsigned char hash[SHA512_DIGEST_LENGTH];
	int i;
	SHA512_CTX sha512;
	SHA512_Init(&sha512);
	SHA512_Update(&sha512, string, strlen((char *) string));
	SHA512_Final(hash, &sha512);
	for(i=0;i<SHA512_DIGEST_LENGTH;i++)
		sprintf(&hex_format[i*2],"%02x",(unsigned int) hash[i]);
	hex_format[128] = '\0';
	return hex_format;
}

char *mysql3_crypt(unsigned char *password)
{
	static char hex_format[17];
	register unsigned long nr=1345345333L, add=7, nr2=0x12345671L;
	unsigned long tmp,result[2];
	for (; *password; password++) {
			if (*password == ' ' || *password == '\t')
					continue;           /* skip space in password */
			tmp  = (unsigned long) *password;
			nr  ^= (((nr & 63) + add) * tmp) + (nr << 8);
			nr2 += (nr2 << 8) ^ nr;
			add += tmp;
	}
	result[0] =  nr & (((unsigned long) 1L << 31) -1L); /* Don't use sign bit (str2int) */;
	result[1] = nr2 & (((unsigned long) 1L << 31) -1L);
	sprintf(hex_format,"%08lx%08lx",result[0],result[1]);
	hex_format[16]='\0';
	return hex_format;
}

char *mysql_crypt(unsigned char *string)
{
	unsigned char stage1[20],*digest;
	static char hex_format[41];
	int i;
	memcpy(&stage1,SHA1(string,strlen((char *) string),NULL),20);
	digest = SHA1(stage1,20,NULL);
	for(i=0;i<20;i++)
		sprintf(&hex_format[i*2],"%02x",(unsigned int) digest[i]);
	hex_format[40] = '\0';
	return hex_format;
}