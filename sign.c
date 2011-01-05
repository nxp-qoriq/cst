/* This code generates and puts  header, public key and signature
 * on top of the image / data to be validated.
 */

/* Copyright (c) 2010 Freescale Semiconductor, Inc.
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
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <unistd.h>
#include <getopt.h>

#define FSL_UID1 0x11111111
#define OEM_UID1 0x99999999
#define PRI_KEY_FILE "srk.pri"
#define PUB_KEY_FILE "srk.pub"
#define TBL_FILE "sg_table.out"
#define HDR_FILE "hdr.out"

#define BARKER_LEN 4		/* barker code length in  header */
#define IOBLOCK 128		/* I/O block size used for hashing operations */
#define SHA256_DIGEST_LENGTH 32
#define NUM_SG_ENTRIES	8
#define NID_sha256 672

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

struct sg_table {
	u32 len;		/* length of the segment */
	u32 pdata;		/* ptr to the data segment*/
};

struct img_hdr {
	u8 barker[BARKER_LEN];	/* barker code */
	u32 pkey;		/* public key offset */
	u32 key_len;		/* pub key length */
	u32 psign;		/* sign ptr */
	u32 sign_len;		/* length of the signature */
	union {
		u32 psgtable;	/* prt to SG table */
		u32 pimg;		/* img offset */
	};
	union {
		u32 sg_entries;		/* no of entries in SG table */
		u32 img_size;		/* img_size length */
	};
	u32 img_start;		/* start ptr */
	u32 sg_flag;		/* Scatter gather flag */
	u32 uid_flag;		/* Flag to indicate uid is present or not*/
	u32 fsl_uid;		/* Freescale unique id */
	u32 oem_uid;		/* OEM unique id */
};

struct sg_input {
	char *name;
	uint32_t addr;
};

struct global {
	/* Variables used across functions */
	FILE *fsrk_pri;
	RSA *srk;
	struct sg_table hsgtbl[NUM_SG_ENTRIES];  /* SG table */
	struct img_hdr himg;
	/* These entries are filled by parsing the arguments */
	int sg_flag;
	int entry_flag;
	int hash_flag;
	int num_entries;
	char *pub_fname;
	char *priv_fname;
	char *hdrfile;
	char *sgfile;
	uint32_t fslid;
	uint32_t oemid;
	unsigned long sg_addr;
	unsigned long img_addr;
	unsigned long entry_addr;
	int verbose_flag;
	struct sg_input entries[NUM_SG_ENTRIES];
};

struct global gd;

/* return the size of the give file */
static int get_size(const char *c)
{
	FILE *fp;
	unsigned char buf[IOBLOCK];
	size_t bytes = 0;

	fp = fopen(c, "rb");
	if (fp == NULL) {
		fprintf(stderr, "Error in opening the file: %s\n", c);
		exit(0);
	}

	while (!feof(fp)) {
		/* read some data */
		bytes += fread(buf, 1, IOBLOCK, fp);
		if (ferror(fp)) {
			fprintf(stderr, "Error in reading file\n");
			return -1;
		} else if (feof(fp) && (bytes == 0))
			break;
	}

	fclose(fp);
	return bytes;
}


int get_size_and_updatehash(const char *fname, SHA256_CTX *ctx)
{
	FILE *fp;
	unsigned char buf[IOBLOCK];
	size_t bytes = 0;
	size_t len = 0;
	int j = 0;

	/* open the file */
	fp = fopen(fname, "rb");
	if (fp == NULL) {
		fprintf(stderr, "Error in opening the file: %s\n", fname);
		exit(0);
	}

	/* go to the begenning */
	fseek(fp, 0L, SEEK_SET);

	while (!feof(fp)) {
		/* read some data */
		bytes = fread(buf, 1, IOBLOCK, fp);
		if (ferror(fp)) {
			fprintf(stderr, "Error in reading file\n");
			exit(0);
		} else if (feof(fp) && (bytes == 0))
			break;

		SHA256_Update(ctx, buf, bytes);
#ifdef DEBUG
		for (j = 0; j < bytes / 4; j++)
			printf("%x\n", htonl(*((uint32_t *)buf + j)));
#endif
		len += bytes;
	}

	fclose(fp);

	return len;
}

static void dump_img_hdr1(struct img_hdr *h)
{
	int i;
	printf("barker:0x");
	for (i = 0; i < BARKER_LEN; i++)
		printf("%02.2x", htonl(h->barker[i]));
	printf("\n");
	printf("pkey %d, key length %d\n", htonl(h->pkey), htonl(h->key_len));
	printf("psign %d, length %d\n", htonl(h->psign), htonl(h->sign_len));
	printf("sg_flag %d\n", htonl(h->sg_flag));
	if (htonl(h->sg_flag))
		printf(" psgtable  %x len %d\n",
			htonl(h->psgtable), htonl(h->sg_entries));
	else
		printf(" pimg %x len %d\n", htonl(h->pimg), htonl(h->img_size));
	printf("img start %x\n ", htonl(h->img_start));
	printf("FSL UID %x\n ", htonl(h->fsl_uid));
	printf("OEM UID %x\n ", htonl(h->oem_uid));
}

static void dump_sg_table1(struct sg_table *t, int n)
{
	int i;
	printf("no of entries  %d\n", n);
	for (i = 0; i < n; i++)
		printf(" entry %d  len %d ptr %x\n",
				i, (t+i)->len, (t+i)->pdata);
}


static void dump_gd(void)
{
	int i = 0;
	printf("sg_flag : %d\n", gd.sg_flag);
	printf("entry_flag : %d\n", gd.entry_flag);
	printf("num_entries : %d\n", gd.num_entries);
	printf("pub_fname : %s\n", gd.pub_fname);
	printf("priv_fname : %s\n", gd.priv_fname);
	printf("sg_addr : %x\n", gd.sg_addr);
	printf("entry_addr : %x\n", gd.entry_addr);
	printf("img_addr : %x\n", gd.img_addr);
	for (i = 0; i < gd.num_entries; i++) {
		printf("binary name %s .. addr %x\n",
				gd.entries[i].name, gd.entries[i].addr);
	}
}

int open_priv_file(void)
{
	/* open SRK private key file and get the key */
	gd.fsrk_pri = fopen(gd.priv_fname, "r");
	if (gd.fsrk_pri == NULL) {
		fprintf(stderr, "Error in opening the file: %s\n",
			gd.priv_fname);
		return -1;
	}

	gd.srk = PEM_read_RSAPrivateKey(gd.fsrk_pri, NULL, NULL, NULL);
	if (gd.srk == NULL) {
		fprintf(stderr, "Error in reading key from : %s\n",
			gd.priv_fname);
		fclose(gd.fsrk_pri);
		return -1;
	}

}


void fill_header(SHA256_CTX *ctx, u32 key_len, u32 sign_len)
{
	u32 size = sizeof(struct img_hdr);
	gd.himg.barker[0] = 0x68;
	gd.himg.barker[1] = 0x39;
	gd.himg.barker[2] = 0x27;
	gd.himg.barker[3] = 0x81;
	if (gd.sg_flag) {
		gd.himg.psgtable = htonl(gd.sg_addr);
		gd.himg.sg_entries = htonl(gd.num_entries);
	} else {
		gd.himg.img_size = htonl(get_size(gd.entries[0].name));
		gd.himg.pimg = htonl(gd.entries[0].addr);
	}
	gd.himg.key_len = htonl(2 * key_len);
	gd.himg.sign_len = htonl(sign_len);
	gd.himg.pkey = htonl(size);
	gd.himg.psign = htonl(size +  2 * key_len);
	gd.himg.img_start = htonl(gd.entry_addr);
	gd.himg.sg_flag = htonl(gd.sg_flag);
	gd.himg.uid_flag = htonl(1);
	gd.himg.fsl_uid = htonl(gd.fslid);
	gd.himg.oem_uid = htonl(gd.oemid);

	SHA256_Update(ctx, &gd.himg, sizeof(struct img_hdr));
}

void fill_and_update_sg_tbl(SHA256_CTX *ctx)
{
	int i = 0;
	for (i = 0; i < gd.num_entries; i++) {
		gd.hsgtbl[i].len = htonl(get_size(gd.entries[i].name)) ;
		gd.hsgtbl[i].pdata = htonl(gd.entries[i].addr);
	}
	SHA256_Update(ctx, &gd.hsgtbl,
			sizeof(struct sg_table) * gd.num_entries);
}

void printkeyhash(u8 *addr, uint32_t len)
{
	SHA256_CTX key_ctx;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	int i;

	SHA256_Init(&key_ctx);
	SHA256_Update(&key_ctx, addr, len);
	SHA256_Final(hash, &key_ctx);
	printf("\n");
	printf("Key Hash :\n");
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%02x", hash[i]);
	printf("\n\n");
}

void printonlyhash(void)
{
	int i, j;
	SHA256_CTX key_ctx;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	FILE *fsrk_pub;
	RSA *srk_pub;
	unsigned char *tmp;
	unsigned char *exponent;
	unsigned char *key;
	uint32_t key_len;

	/* open SRK public key file and get the key */
	fsrk_pub = fopen(gd.pub_fname, "r");
	if (fsrk_pub == NULL) {
		fprintf(stderr, "Error in opening the file: %s\n",
			gd.pub_fname);
		return;
	}

	srk_pub = PEM_read_RSAPublicKey(fsrk_pub, NULL, NULL, NULL);
	if (srk_pub == NULL) {
		fprintf(stderr, "Error in reading key from : %s\n",
			gd.pub_fname);
		fclose(fsrk_pub);
		return;
	}

	key_len = RSA_size(srk_pub);
	key = malloc(key_len * 2);
	memset(key, 0, 2 * key_len);
	tmp = (unsigned char *)(((BIGNUM *) srk_pub->n)->d);
	for (j = key_len - 1, i = 0;
			i < ((BIGNUM *) srk_pub->n)->top * 8; i++, j--)
		key[j] = tmp[i];

	exponent =  key + key_len;
	tmp = (unsigned char *)(((BIGNUM *) srk_pub->e)->d);
	for (j = key_len - 1, i = 0;
			i < ((BIGNUM *) srk_pub->e)->top * 8; i++, j--)
		exponent[j] = tmp[i];

	SHA256_Init(&key_ctx);
	SHA256_Update(&key_ctx, (u8 *)key, 2 * key_len);
	SHA256_Final(hash, &key_ctx);
	printf("\n");
	printf("Key Hash :\n");
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%02x", hash[i]);
	printf("\n\n");

	fclose(fsrk_pub);
	free(key);
	RSA_free(srk_pub);
}

void usage(void)
{
	printf("Usage :");
	printf("./sign [OPTION] FILE ADDRESS [FILE ADDRESS...-s|"\
							"--sgaddr=ADDR]\n");
	printf("\nFILE\t\t\tFile to be signed\n");
	printf("ADDRESS\t\t\tAddress where this binary would be loaded by "\
								"user\n\n");
	printf("This script signs the files and generates the header"\
							 "as understood by ");
	printf("ISBC/ESBC with signature embedded in it.\n");
	printf("For format of header generated refer to the User Document.\n");

	printf("For more than 1 FILE ADDRESS pair, -s option is mandatory.\n");

	printf("\nOptions:\n");

	printf("-s,--sgaddr ADDR\t");
	printf("The address of scatter gather table as added in the header.\n");
	printf("\t\t\t(default sg_flag = 0)\n");

	printf("-e,--entraddr ADDR\t");
	printf("Entry Point/Image start address field in the header.\n");
	printf("\t\t\t(default=ADDRESS of first file specified in command)\n");

	printf("-p,--privkey FILE\t");
	printf("Private key filename to be used for signing the image.\n");
	printf("\t\t\t(File has to be in PEM format)"\
			"(default = srk.pri generated by genkeys command)\n");

	printf("-k,--pubkey FILE\t");
	printf("Public key filename in PEM format.\n");
	printf("\t\t\t(default=srk.pub generated by genkeys).\n");
	printf("\t\t\tRequired for --hash option in case private key "\
							"is not available.\n");

	printf("--oemuid OEMUID\t\t");
	printf("OEM UID to be populated in the header (default=0x99999999).\n");

	printf("--fsluid FSLUID\t\t");
	printf("FSL UID to be populated in header. (default=0x11111111)\n");

	printf("--sgfile FILE\t\t");
	printf("Binary file which would be generated for scatter gather table."\
						 "(default=sg_tbl.out)\n");

	printf("--hdrfile FILE\t\t");
	printf("Binary file that would be generated for header." \
							"(default=hdr.out)\n");

	printf("--hash\t\t\t");
	printf("Print the hash of the public key.\n");
	printf("\t\t\tThis hash value can be used with validate command / "\
						"to populate the SFP.\n");

	printf("-h,--help\t\t");
	printf("Show this help message and exit\n");
}

int main(int argc, char **argv)
{
	int c;
	int i, ret, j = 0;
	u32 key_len, sign_len, hdrlen;
	u8 *header;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned char *tmp;
	unsigned char *sign;
	unsigned char *key;
	SHA256_CTX ctx;
	FILE *ftbl;
	FILE *fhdr;

	printf("\n");
	printf("===========================================================\n");
	printf("This product includes software developed by the OpenSSL \
								Project\n");
	printf("for use in the OpenSSL Toolkit (http://www.openssl.org/)\n");
	printf("This product includes cryptographic software written by\n");
	printf("Eric Young (eay@cryptsoft.com)\n");
	printf("===========================================================\n");
	printf("\n");

	memset(&gd, 0, sizeof(struct global));
	gd.pub_fname = "srk.pub";
	gd.priv_fname = PRI_KEY_FILE;
	gd.hdrfile = HDR_FILE;
	gd.sgfile = TBL_FILE;
	gd.oemid = OEM_UID1;
	gd.fslid = FSL_UID1;

	while (1) {
		static struct option long_options[] = {
		{"verbose", no_argument,       &gd.verbose_flag, 1},
		{"hash", no_argument,       &gd.hash_flag, 1},
		{"help", no_argument,       0, 'h'},
		/* These options don't set a flag.
		 * We distinguish them by their indices. */
		{"sgaddr",  required_argument, 0, 's'},
		{"pubkey",  required_argument, 0, 'k'},
		{"privkey",  required_argument, 0, 'p'},
		{"entryaddr",  required_argument, 0, 'e'},
		{"hdrfile",  required_argument, 0, 0},
		{"sgfile",  required_argument, 0, 0},
		{"oemuid",  required_argument, 0, 0},
		{"fsluid",  required_argument, 0, 0},
		{0, 0, 0, 0}
		};
		int option_index = 0;

		c = getopt_long(argc, argv, "p:a:s:k:e:h",
				long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c) {
		case 0:
		/* If this option set a flag, do nothing else now. */
		if (long_options[option_index].flag != 0)
			break;
		if (strcmp(long_options[option_index].name, "hdrfile") == 0)
			gd.hdrfile = optarg;
		else if (strcmp(long_options[option_index].name, "sgfile") == 0)
			gd.sgfile = optarg;
		else if (strcmp(long_options[option_index].name, "oemuid") == 0)
			gd.oemid = strtoul(optarg, 0, 16);
		else if (strcmp(long_options[option_index].name, "fsluid") == 0)
			gd.fslid = strtoul(optarg, 0, 16);
		break;

		case 's':
		gd.sg_addr = strtoul(optarg, 0, 16);
		gd.sg_flag = 1;
		break;

		case 'a':
		gd.img_addr = strtoul(optarg, 0 , 16);
		break;

		case 'k':
		gd.pub_fname = optarg;
		break;

		case 'p':
		gd.priv_fname = optarg;
		break;

		case 'e':
		gd.entry_addr = strtoul(optarg, 0, 16);
		gd.entry_flag = 1;
		break;

		case 'h':
		usage();
		exit(0);

		case '?':
		/* getopt_long already printed an error message. */
		break;

		default:
		abort();
		}
	}

	if (optind < argc) {
		if ((argc - optind) % 2 != 0) {
			printf("Error. File address parameter not in pair.\
							 Refer usage\n");
			usage();
			exit(1);
		}
		if ((argc - optind) / 2 > 1 && gd.sg_flag == 0) {
			printf("SG table address missing\n");
			usage();
			exit(1);
		}

		i = 0;
		while (optind < argc) {
			gd.entries[i].name = argv[optind++];
			gd.entries[i].addr = strtoul(argv[optind++], 0, 16);
#ifdef DEBUG
			printf("%s ", gd.entries[i].name);
			printf("%x ", gd.entries[i].addr);
#endif
			i++;
		}
		gd.num_entries = i;
	}

	if (gd.num_entries == 0) {
		if (gd.hash_flag) {
			printonlyhash();
			exit(0);
		} else {
			printf("Error in usage\n");
			usage();
			exit(1);
		}
	}

	if (gd.entry_flag == 0)
		gd.entry_addr = gd.entries[0].addr;

	if (open_priv_file() < 0)
		exit(1);

	/* hdrlen size of the  sign, SRK and header */
	key_len = sign_len = RSA_size(gd.srk);
	hdrlen = 2 * key_len + sign_len + sizeof(struct img_hdr);

	header = malloc(hdrlen);
	if (header == NULL) {
		fprintf(stderr, "Error in allocating memory of %d bytes\n"
								, hdrlen);
		goto exit1;
	}

	SHA256_Init(&ctx);
	/* Update the headers contents in SHA */
	/* Also update `the image contents in SHA if sg = 0 */
	fill_header(&ctx, key_len, sign_len);
#ifdef DEBUG
	dump_gd();
#endif
	memcpy(header, &gd.himg, sizeof(struct img_hdr));

	/* copy N and E */
	key = header + sizeof(struct img_hdr);
	memset(key, 0, 2 * key_len);

	/* Copy N component */
	tmp = (unsigned char *)(((BIGNUM *) gd.srk->n)->d);
	for (j = key_len - 1, i = 0;
			i < ((BIGNUM *) gd.srk->n)->top * 8; i++, j--)
		key[j] = tmp[i];

	/* Copy E component */
	key = header + sizeof(struct img_hdr) + key_len;
	tmp = (unsigned char *)(((BIGNUM *) gd.srk->e)->d);
	for (j = key_len - 1, i = 0;
			i < ((BIGNUM *) gd.srk->e)->top * 8; i++, j--)
		key[j] = tmp[i];

	SHA256_Update(&ctx, header + sizeof(struct img_hdr),  2 * key_len);

	if (gd.hash_flag == 1)
		printkeyhash(header + sizeof(struct img_hdr),  2 * key_len);

	if (gd.sg_flag == 1)
		fill_and_update_sg_tbl(&ctx);

	for (i = 0 ; i < gd.num_entries; i++)
		get_size_and_updatehash(gd.entries[i].name, &ctx) ;

	SHA256_Final(hash, &ctx);

	if (gd.verbose_flag) {
		printf("\n");
		printf("Image Hash :");
		for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
			printf("%02x", hash[i]);
		printf("\n");
	}
	/* copy Sign */
	sign = header + sizeof(struct img_hdr) + 2 * key_len;
	if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sign,
							&sign_len, gd.srk)
		!= 1) {
		printf("Error in generating signature\n");
		goto exit2;
	}

	if (gd.verbose_flag) {
		dump_img_hdr1(&gd.himg);
		printf("SG table\n");
		dump_sg_table1((struct sg_table *) gd.hsgtbl, gd.num_entries);
	}

	/* Create the header file */
	fhdr = fopen(gd.hdrfile, "wb");
	if (fhdr == NULL) {
		fprintf(stderr, "Error in opening the file: %s\n", gd.hdrfile);
		goto exit2;
	}
	ret = fwrite((unsigned char *)header, 1, hdrlen, fhdr);
	printf("HEADER file %s created\n", gd.hdrfile);

	/* Create the SG Table file */
	if (gd.sg_flag == 1) {
		ftbl = fopen(gd.sgfile, "wb");
		if (ftbl == NULL) {
			fprintf(stderr, "Error in opening the file: %s\n",
								gd.sgfile);
			goto exit3;
		}
		ret = fwrite((unsigned char *)gd.hsgtbl, 1,
				sizeof(struct sg_table) * gd.num_entries, ftbl);
		fclose(ftbl);
		printf("SG Table file %s created\n", gd.sgfile);
	}

	printf("\n");
exit3:
	fclose(fhdr);
exit2:
	free(header);
exit1:
	fclose(gd.fsrk_pri);
	RSA_free(gd.srk);
	exit(0);
}
