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

create_hdr_isbc_SRCS = $(wildcard common/*.c) \
		$(wildcard taal/*.c) \
		$(wildcard tools/*.c) \
		$(wildcard tools/create_hdr_isbc/*.c) \
		$(wildcard tools/create_hdr_isbc/taal_api/*.c)

create_hdr_isbc_OBJS = $(basename $(create_hdr_isbc_SRCS))
create_hdr_isbc_OBJS := $(notdir $(create_hdr_isbc_OBJS))
create_hdr_isbc_OBJS := $(create_hdr_isbc_OBJS:%=%.o)

create_hdr_esbc_SRCS = $(wildcard common/*.c) \
		$(wildcard taal/*.c) \
		$(wildcard tools/*.c) \
		$(wildcard tools/create_hdr_esbc/*.c) \
		$(wildcard tools/create_hdr_esbc/taal_api/*.c)

create_hdr_esbc_OBJS = $(basename $(create_hdr_esbc_SRCS))
create_hdr_esbc_OBJS := $(notdir $(create_hdr_esbc_OBJS))
create_hdr_esbc_OBJS := $(create_hdr_esbc_OBJS:%=%.o)

create_hdr_pbi_SRCS = $(wildcard common/*.c) \
		$(wildcard taal/*.c) \
		$(wildcard tools/*.c) \
		$(wildcard tools/create_hdr_pbi/*.c) \
		$(wildcard tools/create_hdr_pbi/taal_api/*.c)

create_hdr_pbi_OBJS = $(basename $(create_hdr_pbi_SRCS))
create_hdr_pbi_OBJS := $(notdir $(create_hdr_pbi_OBJS))
create_hdr_pbi_OBJS := $(create_hdr_pbi_OBJS:%=%.o)

create_hdr_cf_SRCS = $(wildcard common/*.c) \
		$(wildcard taal/*.c) \
		$(wildcard tools/*.c) \
		$(wildcard tools/create_hdr_cf/*.c) \
		$(wildcard tools/create_hdr_cf/taal_api/*.c)

create_hdr_cf_OBJS = $(basename $(create_hdr_cf_SRCS))
create_hdr_cf_OBJS := $(notdir $(create_hdr_cf_OBJS))
create_hdr_cf_OBJS := $(create_hdr_cf_OBJS:%=%.o)

sign_img_hash_SRCS = $(wildcard common/*.c) \
		$(wildcard tools/sign_img_hash/*.c) \

sign_img_hash_OBJS = $(basename $(sign_img_hash_SRCS))
sign_img_hash_OBJS := $(notdir $(sign_img_hash_OBJS))
sign_img_hash_OBJS := $(sign_img_hash_OBJS:%=%.o)

append_sign_hdr_SRCS = $(wildcard common/*.c) \
		$(wildcard tools/append_sign_hdr/*.c) \

append_sign_hdr_OBJS = $(basename $(append_sign_hdr_SRCS))
append_sign_hdr_OBJS := $(notdir $(append_sign_hdr_OBJS))
append_sign_hdr_OBJS := $(append_sign_hdr_OBJS:%=%.o)

vpath %.c 	common/ taal/ tools/ \
		tools/create_hdr_isbc/ tools/create_hdr_isbc/taal_api/ \
		tools/create_hdr_esbc/ tools/create_hdr_esbc/taal_api/ \
		tools/create_hdr_pbi/ tools/create_hdr_pbi/taal_api/ \
		tools/create_hdr_cf/ tools/create_hdr_cf/taal_api/ \
		tools/key_generation/ \
		tools/sign_img_hash \
		tools/append_sign_hdr

INCLUDES = 	-Itools/create_hdr_isbc/include/ \
		-Itools/create_hdr_esbc/include/ \
		-Itools/create_hdr_pbi/include/ \
		-Itools/create_hdr_cf/include/ \
		-Itaal/include -Icommon/include \
		-I$(LIB_HASH_DRBG_INCLUDE_PATH)

CCFLAGS= -g -Wall -Werror $(INCLUDES)

INSTALL_BINARIES = 	create_hdr_isbc create_hdr_esbc create_hdr_pbi \
			create_hdr_cf \
			sign_img_hash append_sign_hdr \
			gen_keys gen_otpmk_drbg gen_drv_drbg

# targets that are not files
.PHONY: all clean

# make targets
all: $(LIB_HASH_DRBG) ${INSTALL_BINARIES}
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

sign_img_hash: ${sign_img_hash_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

append_sign_hdr: ${append_sign_hdr_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

gen_keys: ${genkeys_OBJS}
	${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

gen_otpmk_drbg: ${genotpmk_OBJS} $(LIB_HASH_DRBG)
	${LD} ${LDFLAGS} -o $@ $^

gen_drv_drbg: ${gendrv_OBJS} $(LIB_HASH_DRBG)
	${LD} ${LDFLAGS} -o $@ $^

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
