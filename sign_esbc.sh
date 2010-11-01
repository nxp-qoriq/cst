#!/bin/bash
# generate Signed ESBC image

# Copyright (c) 2008 - 2010 Freescale Semiconductor, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in the
#      documentation and/or other materials provided with the distribution.
#    * Neither the name of Freescale Semiconductor nor the
#      names of its contributors may be used to endorse or promote products
#      derived from this software without specific prior written permission.
#
#
# THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

usage ()
{
	usage1
	usage2
}
usage1 ()
{
	echo Usage: $0 ' gen <RSA key Size (1024 or 2048 or 4096)>'
}
usage2 ()
{
	echo Usage: $0 ' sign <no of SG entries> <Entry1, Entry2...Entry8> <header address> <table address> <entry1 address,entry2 address...>'
}

simics_dir="../simics_scripts/"
bootfile="boot.simics"

if [ $# -lt 2 ] ;then
	usage
	exit 1
fi



if [ "$1" == gen ] ;then
	if [ -f "./gen_keys" ] ;then
		if [ $2 -lt 1024 ] ;then
			echo Key size is lessthen 1024.
			usage1
			exit 1
		elif [ $2 -gt 4096 ] ;then
			echo Key size is greaterthen 4096.
			usage1
			exit 1
		else
			./gen_keys $2
			echo
			exit 1
		fi
	else
		echo "File ./gen_keys does not exists. do a Make"
	fi
	exit 1
elif [ "$1" == sign ] ;then
	if [ -f "./sg_sign" ] ;then
		if [ $2 -lt 1 ] ;then
			echo "number of entries should be >= 1"
			usage2
			exit 1
		elif [ $2 -gt 8 ] ;then
			echo "number of entries should be <= 8"
			usage2
			exit 1
		else
			./sfp_snvs 0x11111111 0x99999999 0x00000004
			echo "# Script to run P4080 Secure boot on simulator" >$bootfile
			echo >>$bootfile
			echo "\$cpu_cores = 1" >>$bootfile
			echo >>$bootfile
			echo "\$guest_image[0] = sfp.out" >>$bootfile
			echo "\$guest_addr[0] = 0xffff0000" >>$bootfile
			echo >>$bootfile
			echo "\$guest_image[1] = snvs.out" >>$bootfile
			echo "\$guest_addr[1] = 0xffff1000" >>$bootfile
			echo >>$bootfile
			declare -a ARRAY
			numentries=$2
			numargs=$#
			for (( i = 0; i < numargs; i++ )) # loop
			do
				ARRAY[$i]=$1
				shift

			done

			echo "\$guest_image[2]  = esbc_hdr.out"  >>$bootfile
			echo "\$guest_addr[2]   = " ${ARRAY[$numentries+2]} >>$bootfile
			echo >>$bootfile
			echo "\$guest_image[3]  = sg_table.out" >>$bootfile
			echo "\$guest_addr[3]   = " ${ARRAY[$numentries+3]} >>$bootfile
			echo >>$bootfile

			esbc_loc=${ARRAY[$numentries+2]}

			for (( i = 4; i < numentries+4; i++ )) # loop
			do

				echo "\$guest_image[$i]  = "  ${ARRAY[$i-2]}>>$bootfile
				echo "\$guest_addr[$i]   = "  ${ARRAY[$numentries+i]}>>$bootfile
				echo >>$bootfile
				cp   ${ARRAY[$i-2]} $simics_dir
			done
			echo "run-command-file \"bootsim.include\"">>$bootfile
			echo >>$bootfile
			echo "#ESBC location set by the PBL">>$bootfile
			echo "set 0xfe0e0200 $esbc_loc" >>$bootfile
			echo >>$bootfile

			./sg_sign    ${ARRAY[1]} ${ARRAY[2]}  ${ARRAY[3]}   ${ARRAY[4]}  ${ARRAY[5]}  ${ARRAY[6]} ${ARRAY[7]} ${ARRAY[8]} ${ARRAY[9]}  ${ARRAY[10]} ${ARRAY[11]} ${ARRAY[12]} ${ARRAY[13]} ${ARRAY[14]} ${ARRAY[15]} ${ARRAY[16]} ${ARRAY[17]} ${ARRAY[18]} ${ARRAY[19]}
			cp sfp.out snvs.out boot.simics  esbc_hdr.out sg_table.out $simics_dir
			echo "The SIMICS script file is $simics_dir$bootfile"
			echo
			exit
		fi
	else
		echo "File ./sg_sign does not exists. do a Make"
	fi
	exit 1
else
	usage
	exit 1
fi
