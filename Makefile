# @file
# Makefile containing rules for generating keys and signing images.
#
# Set PATH_OPENSSL_DIR to OPENSSL dir on your machine.
#
ARCH ?= powerpc

INSTALL ?= install
BIN_DEST_DIR ?= /usr/bin

LIB_HASH_DRBG_NAME = hash_drbg
LIB_HASH_DRBG_PATH = lib_$(LIB_HASH_DRBG_NAME)
LIB_HASH_DRBG = $(LIB_HASH_DRBG_PATH)/lib$(LIB_HASH_DRBG_NAME).a
LIB_HASH_DRBG_INCLUDE_PATH = $(LIB_HASH_DRBG_PATH)/include

#
# Should debug output be generated from LIB?
#
# VERBOSITY=0: Print no debug output
# VERBOSITY=1: Print error messages, when the Hash_DRBG fails to operation correctly
# VERBOSITY=2: Print some informational messages during normal operation
#
LIB_VERBOSITY ?= 0


CC=gcc
LD=gcc
RM=rm -f
CCFLAGS= -g -Wall -Iinclude -I$(LIB_HASH_DRBG_INCLUDE_PATH)

ifneq ($(OPENSSL_LIB_PATH),)
LDFLAGS += -L$(OPENSSL_LIB_PATH)
endif

ifneq ($(OPENSSL_INC_PATH),)
CCFLAGS += -I$(OPENSSL_INC_PATH)
endif

ifeq ($(ARCH),arm)
CCFLAGS += -DARM
endif

LIBS += -lssl -lcrypto -ldl

genkeys_OBJS = gen_keys.o
uni_cfsign_OBJS = uni_cfsign.o
uni_sign_OBJS = uni_sign.o
genotpmk_OBJS = gen_otpmk_high_entropy.o
gendrv_OBJS = gen_drv_high_entropy.o
gensign_OBJS = gen_sign.o
sign_embed_OBJS = sign_embed.o
uni_pbi_OBJS = uni_pbi.o

vpath %.c src/

# targets that are not files
.PHONY: all clean

# make targets
INSTALL_BINARIES ?= gen_otpmk_high_entropy gen_drv_high_entropy uni_sign uni_cfsign uni_pbi gen_keys gen_sign sign_embed

all: $(LIB_HASH_DRBG) $(INSTALL_BINARIES)

gen_keys: ${genkeys_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

gen_otpmk_high_entropy: ${genotpmk_OBJS} $(LIB_HASH_DRBG)
	${LD} ${LDFLAGS} -o $@ $^

gen_drv_high_entropy: ${gendrv_OBJS} $(LIB_HASH_DRBG)
	${LD} ${LDFLAGS} -o $@ $^

gen_sign: ${gensign_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

sign_embed: ${sign_embed_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

uni_cfsign: ${uni_cfsign_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

uni_sign: ${uni_sign_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

uni_pbi: ${uni_pbi_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

$(LIB_HASH_DRBG):
	@echo "#########################################"
	@echo "### Building Shared Library hash_drbg ###"
	@echo "#########################################"
	make LIB_HASH_DRBG_PATH=$(LIB_HASH_DRBG_PATH) 	\
		VERBOSITY=-DVERBOSITY=$(LIB_VERBOSITY)	\
		-f $(LIB_HASH_DRBG_PATH)/src/Makefile
	@echo "#########################################"
	@echo "###    Build Complete for hash_drbg   ###"
	@echo "#########################################"

%.o: %.c
	${CC} -c ${CCFLAGS} ${CFLAGS} $<

install: $(foreach binary,$(INSTALL_BINARIES),install-$(binary))
	cp -rf input_files $(DESTDIR)$(BIN_DEST_DIR)/cst/

install-%: %
	$(INSTALL) -d $(DESTDIR)$(BIN_DEST_DIR)/cst
	$(INSTALL) -m 755 $< $(DESTDIR)$(BIN_DEST_DIR)/cst/

clean:
	${RM} *.o gen_keys *.out uni_sign uni_cfsign uni_pbi gen_otpmk_high_entropy gen_drv_high_entropy gen_sign sign_embed

distclean:	clean
	rm -f *.pub *.pri $(LIB_HASH_DRBG)
