/* This code generates RSA public and private keys and stores the
 * keys in file.
 */

/* Copyright (c) 2008 - 2010 Freescale Semiconductor, Inc.
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

#define OPENSSL_NO_KRB5
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>

#define RSA_MIN_LEN 1024
#define RSA_MAX_LEN 4096

#define PRI_KEY_FILE "srk.pri"
#define PUB_KEY_FILE "srk.pub"

static int generate_rsa_keys(const unsigned int n, FILE *fpri, FILE *fpub)
{
	RSA *srk;
	int ret = 0;

	srk = RSA_generate_key(n, RSA_F4, NULL, NULL);

	if (srk == NULL) {
		return -1;
	}

	ret = PEM_write_RSAPrivateKey(fpri, srk, NULL, NULL, 0, 0, NULL);

	if (!ret)
		return -1;

	ret = 0;

	ret = PEM_write_RSAPublicKey(fpub, srk);

	if (!ret)
		return -1;

#ifdef DEBUG
	printf("public modulus (n):\n");
	printf("%s\n", BN_bn2hex(srk->n));

	printf("public exponent (e):\n");
	printf("%s\n", BN_bn2hex(srk->e));

	printf("private exponent (d):\n");
	printf("%s\n", BN_bn2hex(srk->d));

	printf("secret prime factor (p):\n");
	printf("%s\n", BN_bn2hex(srk->p));
	printf("secret prime factor (q):\n");
	printf("%s\n", BN_bn2hex(srk->q));

	printf("dmp1 [ d mod (p-1) ]:\n");
	printf("%s\n", BN_bn2hex(srk->dmp1));
	printf("dmq1 [ d mod (q-1) ]:\n");
	printf("%s\n", BN_bn2hex(srk->dmq1));

	printf("iqmp [ q^-1 mod p ]:\n");
	printf("%s\n", BN_bn2hex(srk->iqmp));

	printf("RSA SIZE: %d\n", RSA_size(srk));

#endif

	RSA_free(srk);

	return 0;
}

int main(const int argc, const char **argv)
{
	int ret = 0;
	unsigned int length;
	FILE *fpri;
	FILE *fpub;

	printf("\n");
	printf("===============================================================\n");
	printf("This product includes software developed by the OpenSSL Project\n");
	printf("for use in the OpenSSL Toolkit (http://www.openssl.org/)\n");
	printf("This product includes cryptographic software written by\n");
	printf("Eric Young (eay@cryptsoft.com)\n");
	printf("===============================================================\n");
	printf("\n");
	printf("Generating SRK pair stored in ===> srk.pri and srk.pub\n");

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <Key length in bits >\n", argv[0]);
		exit(1);
	}

	length = atol(argv[1]);
	if ((length < RSA_MIN_LEN) || (length > RSA_MAX_LEN)) {
		fprintf(stderr,
			"RSA key length should be between %d and  %d both inclusive \n",
			RSA_MIN_LEN, RSA_MAX_LEN);
		return -1;
	}

	/* open the file */
	fpri = fopen(PRI_KEY_FILE, "w");
	if (fpri == NULL) {
		fprintf(stderr, "error in opening the file: %s\n",
			PRI_KEY_FILE);
		return -1;
	}

	fpub = fopen(PUB_KEY_FILE, "w");
	if (fpub == NULL) {
		fprintf(stderr, "error in opening the file: %s\n",
			PUB_KEY_FILE);
		fclose(fpri);
		return -1;
	}

	/* generate RSA keys and store in files */
	ret = generate_rsa_keys(length, fpri, fpub);
	if (ret != 0)
		fprintf(stderr, "error in generating the RSA key \n");

	fclose(fpri);
	fclose(fpub);

	return ret;
}
