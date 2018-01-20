# @file
# Makefile containing rules for generating keys and signing images.
#
# Set PATH_OPENSSL_DIR to OPENSSL dir on your machine.
#
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

ifneq ($(OPENSSL_LIB_PATH),)
LDFLAGS += -L$(OPENSSL_LIB_PATH)
endif

ifneq ($(OPENSSL_INC_PATH),)
CCFLAGS += -I$(OPENSSL_INC_PATH)
endif

LIBS += -lssl -lcrypto -ldl

genkeys_OBJS = gen_keys.o
genotpmk_OBJS = gen_otpmk_drbg.o
gendrv_OBJS = gen_drv_drbg.o
gen_sign_OBJS = gen_sign.o crypto_utils.o
sign_embed_OBJS = sign_embed.o

create_hdr_isbc_SRCS = $(wildcard common/*.c) \
		$(wildcard taal/*.c) \
		$(wildcard tools/header_generation/*.c) \
		$(wildcard tools/header_generation/create_hdr_isbc/*.c) \
		$(wildcard tools/header_generation/create_hdr_isbc/taal_api/*.c)

create_hdr_isbc_OBJS = $(basename $(create_hdr_isbc_SRCS))
create_hdr_isbc_OBJS := $(notdir $(create_hdr_isbc_OBJS))
create_hdr_isbc_OBJS := $(create_hdr_isbc_OBJS:%=%.o)

create_hdr_esbc_SRCS = $(wildcard common/*.c) \
		$(wildcard taal/*.c) \
		$(wildcard tools/header_generation/*.c) \
		$(wildcard tools/header_generation/create_hdr_esbc/*.c) \
		$(wildcard tools/header_generation/create_hdr_esbc/taal_api/*.c)

create_hdr_esbc_OBJS = $(basename $(create_hdr_esbc_SRCS))
create_hdr_esbc_OBJS := $(notdir $(create_hdr_esbc_OBJS))
create_hdr_esbc_OBJS := $(create_hdr_esbc_OBJS:%=%.o)

create_hdr_pbi_SRCS = $(wildcard common/*.c) \
		$(wildcard taal/*.c) \
		$(wildcard tools/header_generation/*.c) \
		$(wildcard tools/header_generation/create_hdr_pbi/*.c) \
		$(wildcard tools/pbi_creation/*.c) \
		$(wildcard tools/header_generation/create_hdr_pbi/taal_api/*.c)

create_hdr_pbi_OBJS = $(basename $(create_hdr_pbi_SRCS))
create_hdr_pbi_OBJS := $(notdir $(create_hdr_pbi_OBJS))
create_hdr_pbi_OBJS := $(create_hdr_pbi_OBJS:%=%.o)

create_hdr_cf_SRCS = $(wildcard common/*.c) \
		$(wildcard taal/*.c) \
		$(wildcard tools/header_generation/*.c) \
		$(wildcard tools/header_generation/create_hdr_cf/*.c) \
		$(wildcard tools/header_generation/create_hdr_cf/taal_api/*.c)

create_hdr_cf_OBJS = $(basename $(create_hdr_cf_SRCS))
create_hdr_cf_OBJS := $(notdir $(create_hdr_cf_OBJS))
create_hdr_cf_OBJS := $(create_hdr_cf_OBJS:%=%.o)

gen_fusescr_SRCS = $(wildcard common/*.c) \
		$(wildcard taal/*.c) \
		$(wildcard tools/fuse_provisioning/*.c)

gen_fusescr_OBJS = $(basename $(gen_fusescr_SRCS))
gen_fusescr_OBJS := $(notdir $(gen_fusescr_OBJS))
gen_fusescr_OBJS := $(gen_fusescr_OBJS:%=%.o)

vpath %.c 	common/ taal/ tools/header_generation/ \
		tools/header_generation/create_hdr_isbc/ tools/header_generation/create_hdr_isbc/taal_api/ \
		tools/header_generation/create_hdr_esbc/ tools/header_generation/create_hdr_esbc/taal_api/ \
		tools/header_generation/create_hdr_pbi/ tools/header_generation/create_hdr_pbi/taal_api/ \
		tools/header_generation/create_hdr_cf/ tools/header_generation/create_hdr_cf/taal_api/ \
		tools/key_generation/ \
		tools/pbi_creation/ \
		tools/signature_generation/ \
		tools/fuse_provisioning \

INCLUDES = 	-Itools/header_generation/create_hdr_isbc/include/ \
		-Itools/header_generation/create_hdr_esbc/include/ \
		-Itools/header_generation/create_hdr_pbi/include/ \
		-Itools/header_generation/create_hdr_cf/include/ \
		-Itools/fuse_provisioning/include/ \
		-Itaal/include -Icommon/include \
		-I$(LIB_HASH_DRBG_INCLUDE_PATH)

CCFLAGS= -g -Wall -Wno-strict-aliasing -Werror $(INCLUDES)

INSTALL_BINARIES = 	create_hdr_isbc create_hdr_esbc \
			create_hdr_pbi create_hdr_cf \
			gen_keys gen_otpmk_drbg gen_drv_drbg \
			gen_sign sign_embed gen_fusescr \

# targets that are not files
.PHONY: all clean

# make targets
all: $(LIB_HASH_DRBG) ${INSTALL_BINARIES}
	cp -rf scripts/* ./
	@echo
	@echo "#########################################"
	@echo "# Tools Compiled:"
	@echo "# ${INSTALL_BINARIES}"
	@echo "#########################################"
	@echo

create_hdr_isbc: ${create_hdr_isbc_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

create_hdr_esbc: ${create_hdr_esbc_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

create_hdr_pbi: ${create_hdr_pbi_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

create_hdr_cf: ${create_hdr_cf_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

gen_sign: ${gen_sign_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

sign_embed: ${sign_embed_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

gen_keys: ${genkeys_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

gen_otpmk_drbg: ${genotpmk_OBJS} $(LIB_HASH_DRBG)
	${LD} ${LDFLAGS} -o $@ $^

gen_drv_drbg: ${gendrv_OBJS} $(LIB_HASH_DRBG)
	${LD} ${LDFLAGS} -o $@ $^

gen_fusescr: ${gen_fusescr_OBJS}
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
	cp -rf scripts/* $(DESTDIR)$(BIN_DEST_DIR)/cst/

install-%: %
	$(INSTALL) -d $(DESTDIR)$(BIN_DEST_DIR)/cst
	$(INSTALL) -m 755 $< $(DESTDIR)$(BIN_DEST_DIR)/cst/

clean:
	${RM} *.o ${INSTALL_BINARIES}

distclean:	clean
	${RM} *.pub *.pri $(LIB_HASH_DRBG)
