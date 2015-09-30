# @file
# Makefile containing rules for generating keys and signing images.
#
# Set PATH_OPENSSL_DIR to OPENSSL dir on your machine.
#
ARCH ?= powerpc

INSTALL ?= install
BIN_DEST_DIR ?= /usr/bin

SO_LIB_NAME = hash_drbg
SO_LIB      = $(SO_LIB_DIR)/lib$(SO_LIB_NAME).so
SO_LIB_PATH = $(shell pwd)/lib/$(SO_LIB_NAME)
SO_LIB_DIR = $(SO_LIB_PATH)/shared_lib
SO_LIB_INCLUDE_PATH = $(SO_LIB_PATH)/include
SO_LIB_SOURCE_PATH = $(SO_LIB_PATH)/source

CC=gcc
LD=gcc
RM=rm -f
CCFLAGS= -g -Wall -Iinclude -I$(SO_LIB_INCLUDE_PATH)

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
INSTALL_BINARIES ?= uni_sign uni_cfsign uni_pbi gen_otpmk_high_entropy gen_keys gen_drv_high_entropy gen_sign sign_embed

all: $(SO_LIB_NAME) $(INSTALL_BINARIES)

gen_keys: ${genkeys_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

gen_otpmk_high_entropy: ${genotpmk_OBJS} $(SO_LIB)
	${LD} ${LDFLAGS} -L$(SO_LIB_DIR) -Wl,-rpath $(SO_LIB_DIR) -l$(SO_LIB_NAME) -o $@ $^ ${LIBS}

gen_drv_high_entropy: ${gendrv_OBJS} $(SO_LIB)
	${LD} ${LDFLAGS} -L$(SO_LIB_DIR) -Wl,-rpath $(SO_LIB_DIR) -l$(SO_LIB_NAME) -o $@ $^ ${LIBS}

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

$(SO_LIB_NAME):
	@echo "#########################################"
	@echo "### Building Shared Library hash_drbg ###"
	@echo "#########################################"
	mkdir -p $(SO_LIB_DIR)
	make SO_LIB_SOURCE_PATH=$(SO_LIB_PATH)/source -f $(SO_LIB_SOURCE_PATH)/Makefile
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
	make SO_LIB_SOURCE_PATH=$(SO_LIB_PATH)/source -f $(SO_LIB_SOURCE_PATH)/Makefile clean 

distclean:	clean
	rm -rf srk.pub srk.pri
