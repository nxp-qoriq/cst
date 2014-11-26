# @file
# Makefile containing rules for generating keys and signing images.
#
# Set PATH_OPENSSL_DIR to OPENSSL dir on your machine.
#
ARCH ?= powerpc

INSTALL ?= install
BIN_DEST_DIR ?= /usr/bin

CC=gcc
LD=gcc
RM=rm -f
CCFLAGS= -g -Wall
#-DBLOCK_ADDRESS_FORMAT

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
genotpmk_OBJS = gen_otpmk.o
gendrv_OBJS = gen_drv.o
gensign_OBJS = gen_sign.o
sign_embed_OBJS = sign_embed.o

# targets that are not files
.PHONY: all clean

# make targets
INSTALL_BINARIES ?= uni_sign uni_cfsign gen_otpmk gen_keys gen_drv gen_sign sign_embed

all: $(INSTALL_BINARIES)

gen_keys: ${genkeys_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

gen_otpmk: ${genotpmk_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

gen_drv: ${gendrv_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

gen_sign: ${gensign_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

sign_embed: ${sign_embed_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

uni_cfsign: ${uni_cfsign_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

uni_sign: ${uni_sign_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

%.o: %.c
	${CC} -c ${CCFLAGS} ${CFLAGS} $<

install: $(foreach binary,$(INSTALL_BINARIES),install-$(binary))
	cp -rf input_files $(DESTDIR)$(BIN_DEST_DIR)/cst/

install-%: %
	$(INSTALL) -d $(DESTDIR)$(BIN_DEST_DIR)/cst
	$(INSTALL) -m 755 $< $(DESTDIR)$(BIN_DEST_DIR)/cst/

clean:
	${RM} *.o gen_keys *.out uni_sign uni_cfsign gen_otpmk gen_drv gen_sign sign_embed

distclean:	clean
	rm -rf srk.pub srk.pri
