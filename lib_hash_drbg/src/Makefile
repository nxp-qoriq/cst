#
# Makefile for hash_drbg library Creation
#
LIB_HASH_DRBG_PATH ?= ..
LIB_HASH_DRBG_SOURCE_PATH = $(LIB_HASH_DRBG_PATH)/src
LIB_HASH_DRBG_INCLUDE_PATH = $(LIB_HASH_DRBG_PATH)/include

CC = gcc
CFLAGS = -g -Wall -Wno-overlength-strings -I$(LIB_HASH_DRBG_INCLUDE_PATH)

#CC = g++
#CFLAGS = -m32 -fpic -O2 -Wall -pedantic -I../include

#
# If a TPM is required, but not available, never generate and random data.
#  This should be set for production use.
# TPM_REQUIRED=1: a TPM must be used to feed the entropy pool
# TPM_REQUIRED=0: a TPM will be used if available, but not required
#
TPM_REQUIRED ?= -DTPM_REQUIRED=0

#
# How many OTPMK values should be generated per seed when a TPM is not present?
#
RESEED_MAX_LONG ?= -DRESEED_MAX_LONG=10000

#
# How many OTPMK values should be generated per seed when a TPM is present?
RESEED_MAX_SHORT ?= -DRESEED_MAX_SHORT=1000
#
# What else should happen if there is no TPM and it is required, CAVP test failure,
#  or error during entropy generation?
# SEVERITY=1:  Print an explaination, and exit.
# SEVERITY=0:  Return an error code, but allow program to continue.
#
SEVERITY ?= -DSEVERITY=1

#
# Should debug output be generated?
#
# VERBOSITY=0: Print no debug output
# VERBOSITY=1: Print error messages, when the Hash_DRBG fails to operation correctly
# VERBOSITY=2: Print some informational messages during normal operation
#
VERBOSITY ?= -DVERBOSITY=0

#
# Should entropy be generated for every OTPMK?
#
# PRED_RES=0: Do not reseed before every OTPMK generation (it's not really needed,
#              but will always occur if a TPM is detected)
# PRED_RES_1: Force a reseed before every OTPMK generation, even if a TPM is not detected
#              Setting this can make OTPMK generation very slow when there is no TPM
#
PRED_RES ?= -DPRED_RES=0

DEFINES = $(TPM_REQUIRED) $(USE_URANDOM) $(SEVERITY) $(VERBOSITY) $(PRED_RES) $(RESEED_MAX_LONG) $(RESEED_MAX_SHORT)

LIB_HASH_DRBG_NAME = hash_drbg
LIB_HASH_DRBG      = $(LIB_HASH_DRBG_PATH)/lib$(LIB_HASH_DRBG_NAME).a

LIB_SRC = \
      entropy.c \
      hash_drbg.c \
      hash_drbg_selftest.c \
      hash_drbg_cavp_data.c \
      get_rand.c \
      otpmk.c \
      drvr.c \
      sha256.c \
      sha256_cavp_selftest.c \
      sha256LongMsg_data.c \
      sha256ShortMsg_data.c \
      sha256Monte_data.c

LIB_OBJ = \
      entropy.o \
      hash_drbg.o \
      hash_drbg_selftest.o \
      hash_drbg_cavp_data.o \
      get_rand.o \
      otpmk.o \
      drvr.o \
      sha256.o \
      sha256_cavp_selftest.o \
      sha256LongMsg_data.o \
      sha256ShortMsg_data.o \
      sha256Monte_data.o

PROG_SRC = main.c

PROG_OBJ = main.o

vpath %.c $(LIB_HASH_DRBG_SOURCE_PATH)

all: $(LIB_HASH_DRBG)

$(LIB_HASH_DRBG): $(LIB_OBJ)
	ar rc $@ $(LIB_OBJ)

otpmk: $(LIB_HASH_DRBG) $(PROG_OBJ)
	$(CC) $(CFLAGS) $(PROG_OBJ) -O2 -L$(LIB_HASH_DRBG_PATH) -l$(LIB_HASH_DRBG_NAME) -o $@

.c.o:
	$(CC) $(CFLAGS) $(DEFINES) -c $< -o $@

clean:
	rm -f $(LIB_OBJ) $(PROG_OBJ) otpmk $(LIB_HASH_DRBG)
