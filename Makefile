# @file
# Makefile containing rules for generating keys and signing images.
#
# Set PATH_OPENSSL_DIR to OPENSSL dir on your machine.
#

CC=gcc
LD=gcc
RM=rm -f
CCFLAGS= -g -Wall
#-DBLOCK_ADDRESS_FORMAT

OPENSSL_LIB_PATH := $(PATH_OPENSSL_DIR)/lib
OPENSSL_INC_PATH := $(PATH_OPENSSL_DIR)/include
CCFLAGS += -I$(OPENSSL_INC_PATH)
LDFLAGS= -L$(OPENSSL_LIB_PATH)

#LDFLAGS += -lssl -lcrypto -ldl
LIBS += -lssl -lcrypto -ldl

genkeys_OBJS = gen_keys.o
uni_cfsign_OBJS = uni_cfsign.o
uni_sign_OBJS = uni_sign.o
genotpmk_OBJS = gen_otpmk.o

# targets that are not files
.PHONY: all clean

# make targets
all: uni_sign uni_cfsign gen_otpmk gen_keys
#all: gen_keys

gen_keys: ${genkeys_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

gen_otpmk: ${genotpmk_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

uni_cfsign: ${uni_cfsign_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

uni_sign: ${uni_sign_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

%.o: %.c
	${CC} -c ${CCFLAGS} $< 

clean:
	${RM} *.o gen_keys *.out uni_sign uni_cfsign gen_otpmk

distclean:	clean
	rm -rf srk.pub srk.pri
