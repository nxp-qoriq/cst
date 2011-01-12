# @file
# Makefile containing rules for generating keys and signing images.
#
# Set PATH_OPENSSL_DIR to OPENSSL dir on your machine.
#

CC=gcc
LD=gcc
RM=rm -f
CCFLAGS= -g -DSIMICS 

ifdef USE_LTIB
   OPENSSL_LIB_PATH := $(LTIB_LIB_PATH)
   OPENSSL_INC_PATH := $(LTIB_INC_PATH)
   CCFLAGS += -I$(OPENSSL_INC_PATH)
   LDFLAGS= -L$(OPENSSL_LIB_PATH)
else ifdef PATH_OPENSSL_DIR
   OPENSSL_LIB_PATH := $(PATH_OPENSSL_DIR)
   OPENSSL_INC_PATH := $(PATH_OPENSSL_DIR)/include
   CCFLAGS += -I$(OPENSSL_INC_PATH)
   LDFLAGS= -L$(OPENSSL_LIB_PATH)
endif

LDFLAGS += -lssl -lcrypto -ldl

sign_OBJS = sign.o
genkeys_OBJS = gen_keys.o
sfp_snvs_OBJS = sfp_snvs.o

# targets that are not files
.PHONY: all clean

# make targets
all: sign gen_keys sfp_snvs

gen_keys: ${genkeys_OBJS}
	${LD} ${LDFLAGS} -o $@ $^

sign: ${sign_OBJS}
	${LD} ${LDFLAGS} -o $@ $^

sfp_snvs: ${sfp_snvs_OBJS}
	${LD} ${LDFLAGS} -o $@ $^

%.o: %.c
	${CC} -c ${CCFLAGS} $<

clean:
	${RM} *.o gen_keys *.out sfp_snvs sign

distclean:	clean
	rm -rf srk.pub srk.pri
