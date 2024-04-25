/* Copyright (c) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 */
/*
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 */

#include <crypto_utils.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

/***************************************************************************
 * Function	:	crypto_hash_init
 * Description	:	Wrapper function for SHA256_Init
 ***************************************************************************/
void crypto_hash_init(void *ctx)
{
	SHA256_CTX *c = (SHA256_CTX *)ctx;
	SHA256_Init(c);
}

/***************************************************************************
 * Function	:	crypto_hash_update
 * Description	:	Wrapper function for SHA256_Update
 ***************************************************************************/
void crypto_hash_update(void *ctx, void *data, uint32_t len)
{
	SHA256_CTX *c = (SHA256_CTX *)ctx;
	SHA256_Update(c, data, len);
}

/***************************************************************************
 * Function	:	crypto_hash_final
 * Description	:	Wrapper function for SHA256_Final
 ***************************************************************************/
void crypto_hash_final(void *hash, void *ctx)
{
	SHA256_CTX *c = (SHA256_CTX *)ctx;
	SHA256_Final(hash, c);
}

/***************************************************************************
 * Function	:	crypto_hash_update_file
 * Arguments	:	ctx - SHA256 context
 *			fname - Image Name
 * Return	:	SUCCESS or Failure
 * Description	:	Opens the Image File and updates the context with
 *			its contents
 ***************************************************************************/
int crypto_hash_update_file(void *ctx, char *fname)
{
	FILE *fp;
	unsigned char buf[IOBLOCK];
	size_t bytes = 0;
	SHA256_CTX *c = (SHA256_CTX *)ctx;

	/* open the file */
	fp = fopen(fname, "rb");
	if (fp == NULL) {
		printf("Error in opening the file: %s\n", fname);
		return FAILURE;
	}

	/* go to the begenning */
	fseek(fp, 0L, SEEK_SET);

	while (!feof(fp)) {
		/* read some data */
		bytes = fread(buf, 1, IOBLOCK, fp);
		if (ferror(fp)) {
			fprintf(stderr, "Error in reading file\n");
			fclose(fp);
			return FAILURE;
		} else if (feof(fp) && (bytes == 0)) {
			break;
		}

		SHA256_Update(c, buf, bytes);
	}

	fclose(fp);

	return SUCCESS;
}

/***************************************************************************
 * Function	:	crypto_rsa_sign
 * Description	:	Wrapper function for RSA_sign
 ***************************************************************************/
int crypto_rsa_sign(void *img_hash, uint32_t len, void *rsa_sign,
			uint32_t *rsa_len, char *key_name)
{
	int ret;
	FILE *fpriv;
	RSA *priv_key;
	EVP_PKEY *pkey = NULL;
	ENGINE *e = NULL;

	if (!OPENSSL_init_ssl(0, NULL)) {
		printf("Could not init OpenSSL.\n");
		return FAILURE;
	}

	if (!strncmp(key_name, "pkcs11:", 7)) {
		ENGINE_load_builtin_engines();
		e = ENGINE_by_id("pkcs11");
		if (!e) {
			printf("Could not find pkcs11 engine.\n");
			goto rsa_failure;
		}
		if (!ENGINE_init(e)) {
			printf("Could not initialize pkcs11 engine.\n");
			goto rsa_failure;
		}
		if (!ENGINE_set_default_RSA(e)) {
			printf("Could not set engine as default for RSA.\n");
			goto rsa_failure;
		}
		printf("\n");
		fflush(stdout);
		fflush(stderr);
		printf("Loading private key: %s\n", key_name);
		pkey = ENGINE_load_private_key(e, key_name, NULL, NULL);
		if (!pkey) {
			printf("Could not load specified pkcs11 key.\n");
			goto rsa_failure;
		}
		priv_key = (RSA *)EVP_PKEY_get0_RSA(pkey);
		ret = RSA_sign(NID_sha256, img_hash, len,
			       rsa_sign, rsa_len,
			       priv_key);
		if (ret != 1) {
			printf("Error in Signing\n");
			goto rsa_failure;
		}

	} else {
		/* Open the private Key */
		fpriv = fopen(key_name, "r");
		if (fpriv == NULL) {
			printf("Error in file opening %s:\n", key_name);
			return FAILURE;
		}

		priv_key = PEM_read_RSAPrivateKey(fpriv, NULL, NULL, NULL);
		fclose(fpriv);
		if (priv_key == NULL) {
			printf("Error in key reading %s:\n", key_name);
			return FAILURE;
		}

		/* Sign the Image Hash with Private Key */
		ret = RSA_sign(NID_sha256, img_hash, len,
			       rsa_sign, rsa_len,
			       priv_key);
		if (ret != 1) {
			printf("Error in Signing\n");
			return FAILURE;
		}
	}

	if (pkey) EVP_PKEY_free(pkey);
	if (e) ENGINE_finish(e);
	if (e) ENGINE_free(e);

	return SUCCESS;

 rsa_failure:
	if (pkey) EVP_PKEY_free(pkey);
	if (e) ENGINE_finish(e);
	if (e) ENGINE_free(e);

	return FAILURE;
}

/***************************************************************************
 * Function	:	crypto_extract_pub_key
 * Arguments	:	fname_pub - Public Key File Name
 *			len - Pointer to Length of public Key (to be updated)
 *			key_ptr - Pointer to buffer where public key is stored
 * Return	:	Success or Failure
 * Description	:	OPen the Public Key, read it into the provided buffer
 *			and update the Key lenght.
 ***************************************************************************/
int crypto_extract_pub_key(char *fname_pub, uint32_t *len, uint8_t *key_ptr)
{
	FILE *fp;
	RSA *pub_key;
	EVP_PKEY *pkey = NULL;
	ENGINE *e = NULL;
	uint32_t key_len;
	const BIGNUM *modulus, *exponent;

	if (!OPENSSL_init_ssl(0, NULL)) {
		printf("Could not init OpenSSL.\n");
		return FAILURE;
	}

	if (!strncmp(fname_pub, "pkcs11:", 7)) {
		ENGINE_load_builtin_engines();
		e = ENGINE_by_id("pkcs11");
		if (!e) {
			printf("Could not find pkcs11 engine.\n");
			goto rsa_failure;
		}
		if (!ENGINE_init(e)) {
			printf("Could not initialize pkcs11 engine.\n");
			goto rsa_failure;
		}
		if (!ENGINE_set_default_RSA(e)) {
			printf("Could not set engine as default for RSA.\n");
			goto rsa_failure;
		}
		printf("\n");
		fflush(stdout);
		fflush(stderr);
		printf("Loading public key: %s\n", fname_pub);
		pkey = ENGINE_load_public_key(e, fname_pub, NULL, NULL);
		if (!pkey) {
			printf("Could not load specified pkcs11 key.\n");
			goto rsa_failure;
		}
		pub_key = (RSA *)EVP_PKEY_get0_RSA(pkey);
		if (!pub_key) {
			printf("Could not load pkcs11 public key.\n");
		}
	} else {
		fp = fopen(fname_pub, "r");
		if (fp == NULL) {
			fprintf(stderr, "Error in file opening %s:\n",
				fname_pub);
			return FAILURE;
		}

		pub_key = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
		fclose(fp);
		if (pub_key == NULL) {
			fprintf(stderr, "Error in key reading %s:\n",
				fname_pub);
			return FAILURE;
		}
	}

	key_len = RSA_size(pub_key);
	*len = 2 * key_len;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	/* copy N and E */
        modulus = (BIGNUM *)pub_key->n;
        exponent = (BIGNUM *)pub_key->e;
#else
	/* get N and E */
	RSA_get0_key(pub_key, &modulus, &exponent, NULL);
#endif
	/* Copy N component */
	BN_bn2bin(modulus, key_ptr);

	/*
	 * Pointer where exponent part of key has to start from.
	 */
	key_ptr = key_ptr + key_len;

	/*
	 * Copy E component. Move the pointer to the end location
	 * where exponent bytes needs to be copied.
	 */
	BN_bn2bin(exponent, key_ptr + key_len - BN_num_bytes(exponent));

	if (pkey) EVP_PKEY_free(pkey);
	if (e) ENGINE_finish(e);
	if (e) ENGINE_free(e);

	return SUCCESS;

 rsa_failure:
	if (pkey) EVP_PKEY_free(pkey);
	if (e) ENGINE_finish(e);
	if (e) ENGINE_free(e);

	return FAILURE;
}

/***************************************************************************
 * Function	:	crypto_print_attribution
 * Arguments	:	None
 * Return	:	Void
 * Description	:	Prints attribution to OpenSSL Project
 ***************************************************************************/
void crypto_print_attribution(void)
{
	printf("\n");
	printf("==========================================================\n");
	printf("This tool includes software developed by OpenSSL Project\n");
	printf("for use in the OpenSSL Toolkit (http://www.openssl.org/)\n");
	printf("This product includes cryptographic software written by\n");
	printf("Eric Young (eay@cryptsoft.com)\n");
	printf("==========================================================\n");
}

/***************************************************************************
 * Description	:	CRC32 Lookup Table
 ***************************************************************************/
static uint32_t crc32_lookup[] = {
	 0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
	 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
	 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
	 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
	 0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,
	 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
	 0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
	 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
	 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
	 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
	 0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940,
	 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
	 0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,
	 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
	 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
	 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
	 0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A,
	 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
	 0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,
	 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
	 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
	 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
	 0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,
	 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
	 0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,
	 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
	 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
	 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
	 0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086,
	 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
	 0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,
	 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
	 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
	 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
	 0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
	 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
	 0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE,
	 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
	 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
	 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
	 0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,
	 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
	 0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60,
	 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
	 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
	 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
	 0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,
	 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
	 0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
	 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
	 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
	 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
	 0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E,
	 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
	 0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,
	 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
	 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
	 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
	 0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0,
	 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
	 0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6,
	 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
	 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
	 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D };
	
/***************************************************************************
 * Function	:	crypto_calculate_crc()
 * Arguments	:	data - Pointer to Data
 *			length - size of data (in bytes)
 * Return	:	CRC32 Value
 * Description	:	Calculate CRC32 over the data
 ***************************************************************************/
uint32_t crypto_calculate_crc(void *data, uint32_t length)
{
	uint32_t crc = 0xFFFFFFFF;
	uint32_t index = 0;
	uint32_t i = 0;
	uint8_t *buf = (uint8_t *)data;

	while (i != length) {
		index = (crc ^ buf[i]) & 0xFF;
		crc = (crc >> 8) ^ crc32_lookup[index];
		i++;
	}
	return crc ^ 0xFFFFFFFF;
}

/***************************************************************************
 * Function	:	crypto_calculate_checksum()
 * Arguments	:	data - Pointer to Data
 *			num - Number of 32 bit words for checksum
 * Return	:	Checksum Value
 * Description	:	Calculate Checksum over the data
 ***************************************************************************/
uint32_t crypto_calculate_checksum(void *data, uint32_t num)
{
	uint32_t i, checksum;
	uint64_t sum = 0;
	uint32_t *word = (uint32_t *)data;

	for (i = 0; i < num; i++) {
		sum = sum + word[i];
		sum = sum & 0xFFFFFFFF;
	}
	checksum = (uint32_t)(sum & 0xFFFFFFFF);
	return checksum;
}
