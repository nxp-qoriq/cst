#!/bin/bash

#-----------------------------------------------------------------------------
#
# File: sign_pbi.sh
#
# Description:
#	This script takes input file as argument and is used to sign the
#	PBI commands in the specified RCW file for the Platform specified.
#	For doing this the required CST Tools are invoked with the
#	input file as argument
#
#		Copyright (c) 2015 Freescale Semiconductor, Inc.
#		Freescale Proprietary.
#
#-----------------------------------------------------------------------------

if [ $# -ne 1 ]
then
	echo "Incorrect Usage. Correct Usage is:"
	echo "	$0 <input_file>"
	exit 1
fi

echo "Invoking the CST Tools for Signing"
./create_hdr_pbi $1
./sign_img_hash $1
./append_sign_hdr $1
