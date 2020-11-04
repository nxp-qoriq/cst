#!/bin/bash

#-----------------------------------------------------------------------------
#
# File: ls104x_1012_qspi.sh
#
# Copyright 2017-2018, 2020 NXP
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of Freescale Semiconductor nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
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
#-----------------------------------------------------------------------------

# Sign bootscript image
./uni_sign input_files/uni_sign/ls104x_1012/input_bootscript_secure

# Generating SRK hash
./uni_sign --hash input_files/uni_sign/ls104x_1012/input_bootscript_secure > srk_hash.txt

# Sign bootscript for decapsulation
if [ -f bootscript_dec ]; then
    ./uni_sign input_files/uni_sign/ls104x_1012/input_bootscript_secure_dec
fi
if [ -f bootscript_enforce ]; then
    ./uni_sign input_files/uni_sign/ls104x_1012/input_bootscript_secure_enforce
    ./uni_sign input_files/uni_sign/ls104x_1012/input_initramfs_secure
fi

if [ -f "$pfe_fw" ]; then
    ./uni_sign input_files/uni_sign/ls104x_1012/input_pfe_secure
fi

# Sign kernel image
./uni_sign input_files/uni_sign/ls104x_1012/input_kernel_secure

# Sign uImage.bin
./uni_sign input_files/uni_sign/ls104x_1012/input_uimage_secure

# Sign uImage.dtb
./uni_sign input_files/uni_sign/ls104x_1012/input_dtb_secure

# Concatenate secure boot headers
if [ -f secboot_hdrs_qspiboot.bin ]; then
    rm secboot_hdrs_qspiboot.bin
fi
touch secboot_hdrs_qspiboot.bin
dd if=hdr_kernel.out of=secboot_hdrs_qspiboot.bin bs=1K seek=0
if [ -f "$pfe_fw" ]; then
dd if=hdr_pfe.out of=secboot_hdrs_qspiboot.bin bs=1K seek=256
fi
