/* This code generates RSA public and private keys and stores the
 * keys in file.
 */

/* Copyright (c) 2008 - 2012 Freescale Semiconductor, Inc.
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
#include <unistd.h>
#include <getopt.h>

#define RSA_LEN1	1024
#define RSA_LEN2	2048	
#define RSA_LEN3	4096

#define PRI_KEY_FILE "srk.pri"
#define PUB_KEY_FILE "srk.pub"

static int generate_rsa_keys(const unsigned int n, FILE *fpri, FILE *fpub)
{
	RSA *srk = NULL;
	BIGNUM *public_exponent = NULL;
	int ret = 0;

	/* Allocate space for RSA structure */
	srk = RSA_new();

	if (srk == NULL) {
		return -1;
	}

	public_exponent = BN_new();
	if (public_exponent == NULL || !BN_set_word(public_exponent, RSA_F4)) {
		BN_free(public_exponent);
		return -1;
	}

	ret = RSA_generate_key_ex(srk, n, public_exponent, NULL);
	if (!ret) {
		RSA_free(srk);
		BN_free(public_exponent);
		return -1;
	}

	ret = PEM_write_RSAPrivateKey(fpri, srk, NULL, NULL, 0, 0, NULL);

	if (!ret) {
		RSA_free(srk);
		BN_free(public_exponent);
		return -1;
	}

	ret = PEM_write_RSAPublicKey(fpub, srk);

	if (!ret) {
		RSA_free(srk);
		BN_free(public_exponent);
		return -1;
	}

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
	BN_free(public_exponent);

	return 0;
}

void usage(void)
{
	printf("Usage: genkeys <Key length in bits >\n");
	printf("Key length can be %d or %d or %d\n\n",
					RSA_LEN1, RSA_LEN2, RSA_LEN3);

	printf("Options\n\n");
	printf("-h,--help\t\tUsage of the command\n");
	printf("-k,--pubkey\t\tFile where Public key would be stored in PEM format"\
			"(default = srk.pub)\n"); 
	printf("-p,--privkey\t\tFile where Private key would be stored in PEM format"\
			"(default = srk.priv)\n"); 

	printf("\n");
}

int main(int argc, char **argv)
{
	int ret = 0;
	unsigned int length;
	FILE *fpri;
	FILE *fpub;
	char *pub_fname = PUB_KEY_FILE;
	char *priv_fname = PRI_KEY_FILE;
	int c;

	printf("\n\t#----------------------------------------------------#");
	printf("\n\t#-------         --------     --------        -------#");
	printf("\n\t#------- CST (Code Signing Tool) Version 2.0  -------#");
	printf("\n\t#-------         --------     --------        -------#");
	printf("\n\t#----------------------------------------------------#");
	printf("\n");

	printf("\n");
	printf("===============================================================\n");
	printf("This product includes software developed by the OpenSSL Project\n");
	printf("for use in the OpenSSL Toolkit (http://www.openssl.org/)\n");
	printf("This product includes cryptographic software written by\n");
	printf("Eric Young (eay@cryptsoft.com)\n");
	printf("===============================================================\n");
	printf("\n");

	while (1) {
		static struct option long_options[] = {
		{"help", no_argument,       0, 'h'},
		/* These options don't set a flag.
		 * We distinguish them by their indices. */
		{"pubkey",  required_argument, 0, 'k'},
		{"privkey",  required_argument, 0, 'p'},
		{0, 0, 0, 0}
		};
		int option_index = 0;

		c = getopt_long(argc, argv, "p:k:h",
				long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c) {
		case 'h':
		usage();
		exit(0);

		case 'k':
		pub_fname = optarg;
		break;
		
		case 'p':
		priv_fname = optarg;
		break;

		case '?':
		/* getopt_long already printed an error message. */
		printf("?");
		break;

		default:
		printf("default");
		exit(0);
		}
	}
	if (optind < argc) {
		if ((argc - optind) != 1) {
			printf("Only 1 argumnet is allowed with the command\n");
			usage();
			exit(1);
		}
		length = atol(argv[optind]);
		if (length != RSA_LEN1 && length != RSA_LEN2 && length != RSA_LEN3) {
			printf("Wrong key length\n\n");
			usage();
			exit(1);
		}
	} else {
		usage();
		exit(1);
	}

	/* open the file */
	fpri = fopen(priv_fname, "w");
	if (fpri == NULL) {
		fprintf(stderr, "error in opening the file: %s\n",
			priv_fname);
		return -1;
	}

	fpub = fopen(pub_fname, "w");
	if (fpub == NULL) {
		fprintf(stderr, "error in opening the file: %s\n",
			pub_fname);
		fclose(fpri);
		return -1;
	}

	/* generate RSA keys and store in files */
	ret = generate_rsa_keys(length, fpri, fpub);
	if (ret != 0)
		fprintf(stderr, "error in generating the RSA key \n");

	fclose(fpri);
	fclose(fpub);

	printf("Generated SRK pair stored in :\n\t\tPUBLIC KEY %s\n"\
				"\t\tPRIVATE KEY %s\n", pub_fname, priv_fname);

	return ret;
}
