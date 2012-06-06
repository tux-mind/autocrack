#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

/* great part of this function is taken from aircrack-ng suite source code.
 * derive the PMK from the passphrase and the essid
 */
unsigned char *calc_pmk( char *essid_pre, char *key )
{
	int i, j, slen;
	unsigned char buffer[65],*pmk;
	char essid[33+4];
	SHA_CTX ctx_ipad;
	SHA_CTX ctx_opad;
	SHA_CTX sha1_ctx;

	if(key == NULL || essid_pre == NULL)
	{
		report_error("called with NULL argument.",0,0,error);
		return NULL;
	}
	pmk = malloc(40*sizeof(unsigned char));
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
	return pmk;
}