# @file
# Makefile containing rules for generating keys and signing images.
#
# Set PATH_OPENSSL_DIR to OPENSSL dir on your machine.
#

CC=gcc
LD=gcc
RM=rm -f
CCFLAGS= -g -DSIMICS
LDFLAGS=

sign_OBJS = sign.o
genkeys_OBJS = gen_keys.o
sfp_snvs_OBJS = sfp_snvs.o

# targets that are not files
.PHONY: all clean

# make targets
all: sign gen_keys sfp_snvs

gen_keys: ${genkeys_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ -lssl -ldl -lcrypto -L$(PATH_OPENSSL_DIR)

sign: ${sign_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ -lssl -ldl -lcrypto -L$(PATH_OPENSSL_DIR)

sfp_snvs: ${sfp_snvs_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ -lssl -ldl -lcrypto -L$(PATH_OPENSSL_DIR)

%.o: %.c
	${CC} -c ${CCFLAGS} $<

clean:
	${RM} ${sign_OBJS}  *.o gen_keys sg_sign *.out sfp_snvs

distclean:	clean
	rm -rf srk.pub srk.pri
