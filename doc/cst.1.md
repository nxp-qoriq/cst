% CST(1) Code Signing Tool 2.0 | NXP Layerscape LX2160 and QorIQ Secure Boot
% Vincent Jardin
% September 2026

<!-- Copyright 2026 Free Mobile, Vincent Jardin -->
<!-- Convert with: pandoc -s -t man doc/cst.1.md -o cst.1 -->

# NAME

cst - NXP Code Signing Tool for QorIQ and Layerscape secure boot:
**gen_keys**, **gen_otpmk_drbg**, **gen_drv_drbg**, **uni_sign**,
**uni_pbi**, **uni_cfsign**, **create_hdr_isbc**, **create_hdr_esbc**,
**create_hdr_pbi**, **create_hdr_cf**, **gen_sign**, **sign_embed**,
**gen_fusescr**

# SYNOPSIS

**gen_keys** [**-k** *pub.pem*] [**-p** *priv.pem*] *bits*

**gen_otpmk_drbg** **-b** *1*|*2* [**--s** *hex256*] [**--u**]

**gen_drv_drbg** *A1*|*A2*|*B* [*hex64*]

**uni_sign** [*options*] *input_file*

**uni_pbi** [*options*] *input_file*

**uni_cfsign** [*options*] *input_file*

**create_hdr_isbc** | **create_hdr_esbc** | **create_hdr_cf** [**--verbose**]
[**--hash**] [**--img_hash**] [**--out** *file*] [**--in** *file*]
[**--app** *file* **--app_off** *hexoffset*] *input_file*

**create_hdr_pbi** [**--verbose**] [**--hash**] [**--img_hash**]
[**--out** *file*] [**--in** *rcw*] [**--sben**] *input_file*

**gen_sign** [**--sign_file** *sign.out*] *hash_file* *priv_key*

**sign_embed** *hdr_file* *sign_file*

**gen_fusescr** [**--verbose**] *input_file*

# DESCRIPTION

The Code Signing Tool (CST) prepares the keys, headers and signatures that
the BootROM and the boot loader of NXP QorIQ (PowerPC) and Layerscape
(ARM) SoCs verify when secure boot is enabled. The SoC contains a Security
Fuse Processor (SFP) holding a hash of the Super Root Keys (SRKH) and a One
Time Programmable Master Key (OTPMK). The Internal Secure Boot Code (ISBC)
in the BootROM uses the SRKH to check the first image. That image contains
the External Secure Boot Code (ESBC) which checks the next images with the
same mechanism, forming a chain of trust up to the kernel.

Every verified image is preceded by a Command Sequence File (CSF) header
produced by this CST tool. The header holds the SRK table (the RSA public
keys), a scatter-gather (SG) table describing the images and their load
addresses, optional unique identifiers and flags, and an RSA signature. The
signature is computed with PKCS#1 v1.5 with the SHA-256 digest of the header,
the SRK table, the SG table and the images themselves. The boot code hashes
the SRK table, compares it with the SRKH fuses, then verifies the signature
with the selected key.

CST is a set of small command line programs sharing one input file format.
The platform named in the input file selects the trust architecture (TA)
and therefore the header layout:

| Trust architecture | PLATFORM values accepted | Boot flow |
|--------------------|--------------------------|-----------|
| TA 1.x, PBL        | P4080, P3041, P2041, P5040, P5020 (or 4080, 3041, ...) | PBL, e500mc |
| TA 1.x, non-PBL    | P1010, 1010, BSC9132, 9132, 9131 | IBR, CF header |
| TA 2.0, PBL        | T4240, T2080, T1040, T1023, B4860 (or 4240, ...) | PBL, e6500/e5500 |
| TA 2.0, non-PBL    | C290                     | IBR, CF header |
| TA 2.1, Armv7      | LS1020, LS1              | PBL |
| TA 2.1, Armv8      | LS1043, LS1046, LS1012   | PBL |
| TA 3.0             | LS2080, LS2085           | Service Processor |
| TA 3.1             | LS2088, LS1088           | Service Processor |
| TA 3.2             | LX2160, LS1028           | Service Processor |

This page uses the LX2160A (trust architecture 3.2, chassis 3.2) as its
reference platform. Its Service Processor BootROM validates the RCW and PBI
commands, then the BL2 stage of TF-A copied by PBI block copy commands into
OCRAM, using the SRKH fused in a little-endian Security Fuse Processor
(SFP version 3.4). BL2 then validates BL31, the optional BL32 (OP-TEE) and
BL33 (U-Boot) carried in the FIP, and U-Boot in turn validates the MC
firmware, DPC, DPL, boot script, kernel and device tree. Everything from the
RCW to the kernel carries a CSF header produced by this tool, either
directly or through the TF-A and flexbuild builds that call it. The same
tools and fields apply to LS1028 (TA 3.2), LS1088 and LS2088 (TA 3.1), and
in a reduced form to the PBL based LS1043, LS1046 and LS1012 and to the
older QorIQ devices.

The **uni_sign**, **uni_pbi** and **uni_cfsign** scripts are thin wrappers
that check the input file exists and call the corresponding **create_hdr_**
program found next to the script, so they work both from the source tree and
once installed in */usr/bin*.

# TOOLS

## gen_keys

    gen_keys [-k|--pubkey pub.pem] [-p|--privkey priv.pem] bits

Generates an RSA key pair with public exponent 65537. *bits* is 1024, 2048
or 4096. The keys are written in PEM as PKCS#1 *RSA PRIVATE KEY* and
*RSA PUBLIC KEY* files, by default **srk.pri** and **srk.pub** in the
current directory. The public key is later embedded in the SRK table and
its hash goes to the SRKH fuses. The private key must be protected. Keys
generated elsewhere can be used as long as they are RSA keys in PEM.

## gen_otpmk_drbg

    gen_otpmk_drbg -b bit_order [--s hex256] [--u]

Produces a 256 bit OTPMK value with the SFP Hamming check bits inserted.
Without **--s** a random value is generated with the NIST SP 800-90A
Hash_DRBG shipped in *lib_hash_drbg*, seeded from */dev/random* (or
*/dev/urandom* with **--u**). With **--s** the 64 hex digit string is taken
as the key and only the check bits are computed.

**-b** *1*
:   Bit ordering for TA 1.x SFP: BSC913x, P1010, P2, P3, P4, P5, C29x.
    OTPMKR0 receives bits 31:0.

**-b** *2*
:   Bit ordering for TA 2.x and 3.x SFP: T1, T2, T4, B4 and all
    Layerscape, LX2160 included. OTPMKR0 receives bits 255:224.

The output is the full 256 bit value followed by a table of the eight
OTPMKR register values to program in the SFP mirror registers, in the order
the SFP expects for the chosen scheme. Only the long spellings **--s** and
**--u** (or **--string** and **--urand**) are parsed. The short **-s** is
silently ignored and **-u** is rejected.

## gen_drv_drbg

    gen_drv_drbg A1|A2|B [hex64]

Produces a 64 bit Debug Response Value (DRV) with Hamming check bits, used
by the secure debug challenge/response feature. The first argument selects
the Hamming algorithm of the SoC family:
  **A1** for T10xx, T20xx, T4xxx, P4080 rev1 and B4xxx,
  **A2** for Layerscape, LX2160 included,
  **B** for P10xx, P20xx, P30xx, P4080 rev2/rev3, P50xx, BSC913x and C29x.
Without a 16 hex digit string a random value is drawn from the Hash_DRBG.
The two DRV register values are printed.

## uni_sign, create_hdr_isbc, create_hdr_esbc

    uni_sign [options] input_file

Creates the CSF header, SRK table, SG table and signature for one or more
images. **uni_sign** runs **create_hdr_esbc** when the input file contains a
line reading exactly `ESBC=1`, and **create_hdr_isbc** otherwise. The ISBC
form is used for the image verified by the BootROM (U-Boot, SPL, or on
TA 3.x the BL2 of TF-A). The ESBC form is used for every later image in the
chain (kernel, device tree, boot script, initramfs, TF-A BL31/BL33, MC firmware,
DPC, DPL, PFE firmware and so on). See ATF for some other formats.

On LX2160 the TF-A build calls **create_hdr_isbc** itself for BL2 and
**create_hdr_esbc** for each FIP component, with the input files in
*drivers/nxp/auth/csf_hdr_parser/* of the TF-A tree (*input_bl2_ch3_2*,
*input_pbi_ch3_2* and *input_blx_ch3*), while flexbuild runs the script
*platforms/lx2160_xspi.sh* or *lx2160_sd.sh* of this package for the
images U-Boot validates. The samples in *input_files/uni_sign/lx2160/*
are what those scripts use.

**--verbose**
:   Dump the generated header fields, the image hash and the SRK hash.

**--hash**
:   Only compute and print the SRK table hash, as a 64 hex digit value and
    as the eight *SFP SRKHR0..7* register values. No header is produced.

**--img_hash**
:   Produce the header without signature, padded up to the signature
    offset, and store the SHA-256 image hash in the file named by
    IMAGE_HASH_FILENAME (default **hash.out**). No private key is needed.
    See *SIGNING WITH AN EXTERNAL SIGNER* below.

**--out** *file*
:   Header file name, overriding OUTPUT_HDR_FILENAME.

**--in** *file*
:   Image file, overriding the file name given in IMAGE_1.

**--app** *file* **--app_off** *hexoffset*
:   Append *file* to the header file at *hexoffset* bytes from its start,
    padding the gap with 0xff. Both options are required together.

Outputs: the header file (default **hdr.out**), for TA 1.x PBL platforms
with ESBC=0 also the SG table file (OUTPUT_SG_BIN, default
**sg_table.out**), and **ie_table.out** when IE keys are used. The SRK hash
and its SFP register values are always printed at the end.

## uni_pbi, create_hdr_pbi

    uni_pbi [options] input_file

Handles the Reset Configuration Word (RCW) and its Pre-Boot Initialization
(PBI) commands. The behaviour depends on the trust architecture:

For *TA 2.x* (LS1020, LS1043, LS1046, LS1012 and PBL PowerPC): the RCW file is
copied to OUTPUT_RCW_PBI_FILENAME (default **rcw_pbi_sec.bin**) with the
SB_EN and BOOT_HO bits set as requested, a PBI write of BOOT1_PTR (the
address of the ISBC CSF header) to the boot pointer register, optional ACS
write commands from COPY_CMD that load SPL and its header into OCRAM from
SD or NAND, and optional images appended at fixed offsets from
APPEND_IMAGES. Nothing is signed by this tool: the RCW is verified by the
ISBC through the header pointed to by BOOT1_PTR. The **--verbose**,
**--hash** and **--img_hash** options do not apply here.

For *TA 3.x* (LS1088, LS2088, LS2085, LX2160, LS1028): the RCW and PBI commands
are themselves signed. The tool inserts a *load security header* command
followed by the CSF header and SRK table, a command loading BOOT1_PTR into
the Boot1 CSF pointer, optional SCRATCHRW13/14 writes of IE_TABLE_ADDR,
optional block copy commands from COPY_CMD, then the original PBI commands,
updates the PBI length and SB_EN bit in the RCW, recomputes the RCW
checksum and the PBI CRC, and appends the RSA signature. The result goes to
OUTPUT_HDR_FILENAME (default **hdr.out**, samples use **rcw_sec.bin**). The
input RCW must already end with a *stop* or *CRC and stop* command.

The BOOT1_PTR command is only inserted when the field is set. TF-A's
*create_pbl* has already added the block copy commands for BL2 and its
header and the pointer to the header in OCRAM (0x1800a000 on LX2160), so
the *input_pbi_ch3_2* file it feeds to **create_hdr_pbi** carries neither
BOOT1_PTR nor COPY_CMD. The sample *input_files/uni_pbi/lx2160/* file with
BOOT1_PTR=206c0000 belongs to the older flow where U-Boot executed in place
from FlexSPI NOR mapped at 0x20000000 and its header sat at flash offset
0x6c0000.

**--sben**
:   Set the SB_EN bit in the RCW, as an alternative to the SB_EN field.

**--in** *rcw*
:   RCW file, overriding RCW_PBI_FILENAME.

## uni_cfsign, create_hdr_cf

    uni_cfsign [options] input_file

Creates the Configuration (CF) header used by the non-PBL devices P1010,
BSC9131, BSC9132 and C290, whose Internal BootROM (IBR) reads a signed
list of address/data configuration words before locating the ESBC header.
The CF_WORD pairs, the target memory type (IMAGE_TARGET) and the location
of the ISBC CSF header (ESBC_HDRADDR) are written into a CF header that is
hashed and signed like a CSF header. The output file is OUTPUT_HDR_FILENAME
(default **hdr.out**). The same **--verbose**, **--hash**, **--img_hash**
and **--out** options as **uni_sign** apply.

## gen_sign

    gen_sign [--sign_file sign.out] hash_file priv_key

Signs the 32 byte SHA-256 digest in *hash_file*, as produced by
**--img_hash**, with the RSA private key in *priv_key*, using PKCS#1 v1.5
with a SHA-256 DigestInfo (the same output as OpenSSL's *RSA_sign*). The
signature length equals the key length: 128, 256 or 512 bytes. The result
is written to **sign.out** unless **--sign_file** is given.

## sign_embed

    sign_embed hdr_file sign_file

Appends *sign_file* to the end of *hdr_file*. A header produced with
**--img_hash** is padded to its signature offset, so appending places the
signature exactly where the header says it is.

## gen_fusescr

    gen_fusescr [--verbose] input_file

Generates **fuse_scr.bin** (or OUTPUT_FUSE_FILENAME), a fuse provisioning
script consumed by the fuse provisioning firmware of TF-A (*fuse_fip.bin*,
LX2160 and the other chassis 3 SoCs) or PPA (LS1012, LS1043, LS1046). The
tool accepts PLATFORM=LX2160. The sample input file to start from is the
*ls2088_1088* one, which has the same fields. The script tells the firmware
which fuses to program: OTPMK (minimal, random or user supplied), SRKH, OEM
UIDs, debug challenge and response values, the debug level, and the system
configuration bits WP, ITS, NSEC, ZD, key revocation K0..K6 and field
return FR0/FR1. The firmware reports its result in DCFG scratch register 4,
at 0x01e0020c on LX2160 (*md 1e0020c 1* in U-Boot: zero means success, the
error codes are listed in the LSDK and TF-A documentation).

## byte_swap.tcl

    tclsh byte_swap.tcl input output n

Helper script, not installed as a command. Pads *input* with zero bytes to
a multiple of *n* and reverses the byte order inside each *n* byte group.
It was added for platforms whose flash controller presents images with a
swapped byte order.

# INPUT FILE FORMAT

All header tools read a plain text file with one field per line:

    # comment
    FIELD=value
    FIELD=value1,value2
    FIELD={value1,value2,value3}

Lines starting with **#** are ignored, as is a leading C style comment
block. White space and the characters `{ } [ ] ( )` are stripped, then the
value is split on `,`, `;` and `=`.

Field names are matched as substrings of the line, so keep exactly one
field per line and do not rename fields.

Numbers are hexadecimal without a *0x* prefix (a prefix is tolerated).

Each tool reads only the fields it knows for the selected trust
architecture. Other fields are silently ignored. In particular the legacy
names HASH_FILENAME, INPUT_SIGN_FILENAME, SIGN_SIZE and RSA_SIGN_FILENAME
found in old sample files have no effect: the hash file name is
IMAGE_HASH_FILENAME.

## Fields common to the header tools

PLATFORM
:   SoC name, see the table in DESCRIPTION. Mandatory.

ESBC
:   Only read by the **uni_sign** wrapper, which looks for the exact line
    `ESBC=1`. Set it for every image after the one checked by the boot ROM.

PUB_KEY
:   Comma separated list of public key files forming the SRK table: one key
    on TA 1.x, up to 4 on TA 2.x and up to 8 on TA 3.x. Default *srk.pub*.

PRI_KEY
:   Private key used to sign. One file (TA 3.x) or a list matching PUB_KEY
    (TA 2.x, where KEY_SELECT picks the pair). Default *srk.pri*. Not
    needed with **--img_hash**.

KEY_SELECT
:   1 based index of the SRK table entry the boot ROM must use. Default 1.
    Keys can later be revoked through the SFP key revocation fuses.

FSL_UID_0, FSL_UID_1, OEM_UID_0 .. OEM_UID_4
:   32 bit identifiers copied into the header: when present the matching
    UID flag is set and the BootROM compares them with the SFP fuses.
    TA 1.x and 2.x have FSL_UID_0/1 and OEM_UID_0/1, TA 3.x has five OEM
    UIDs.

OUTPUT_HDR_FILENAME
:   Header (or signed RCW) output file. Default *hdr.out*.

IMAGE_HASH_FILENAME
:   Hash file written by **--img_hash**. Default *hash.out*.

VERBOSE
:   1 has the same effect as **--verbose**.

APPEND_IMAGES
:   `{file,hexoffset}`, may be repeated up to 10 times. After the header
    is written, each file is appended at the given offset from the start of
    the output file, with 0xff padding in between. Works with every header
    tool and is the mechanism used to build single flash images.

## Image fields (uni_sign)

ENTRY_POINT
:   Entry point placed in the header, 64 bit on TA 3.x. Defaults to the
    address of IMAGE_1.

IMAGE_1 .. IMAGE_8
:   `{file,src_addr,dst_addr}`. Each becomes one SG table entry with the
    file size. *src_addr* is where the image sits when verified (64 bit on
    TA 3.x): on LX2160 BL2 at 0x1800d000 in OCRAM, MC, DPC and DPL either
    in place in FlexSPI NOR (0x20a00000, 0x20e00000, 0x20d00000) or loaded
    to DDR for SD boot (0x80a00000, 0x80e00000, 0x80d00000), the boot
    script at 0x80000000, the kernel at 0x81000000 or 0xa0000000 as an ITB,
    the device tree at 0x90000000 and an initramfs at 0xb0000000.
    *dst_addr* is only used by non-PBL devices, which copy the image there,
    and is *ffffffff* otherwise. Empty entries `{,,}` are skipped.

IMAGE_TARGET
:   Non-PBL devices only. Memory the image is read from: NOR_8B, NOR_16B,
    NAND_8B_512, NAND_8B_2K, NAND_8B_4K, NAND_16B_512, NAND_16B_2K,
    NAND_16B_4K, SD, SDHC, MMC or SPI. Default NOR_16B.

SG_TABLE_ADDR, OUTPUT_SG_BIN
:   TA 1.x PBL devices with ESBC=0: address where the separate SG table
    file will be placed, and its file name (default *sg_table.out*).

HK_AREA_POINTER, HK_AREA_SIZE
:   TA 2.0 (T-series, B4, C290) with ESBC=0: house keeping area the SEC
    engine needs, 4 KiB aligned and below 3.5 GiB.

SEC_IMAGE
:   TA 2.0: mark the header as the secondary (backup) image.

WP_FLAG
:   TA 2.x: set the SFP write protect flag in the header.

MP_FLAG
:   Execute the Manufacturing Protection routine. ISBC phase only: needed on
    LS1 and TA 3.x.

ISS_FLAG
:   TA 3.x, ISBC phase: Increment Security State. When set the ISBC moves
    the SNVS security state machine from *check* to *trusted* after a
    successful verification. Usually 1.

LW_FLAG
:   TA 3.x, ISBC phase: Leave Writeable. When set the ISBC does not set the
    SFP write disable, so fuses stay programmable (development only).

ESBC_HDRADDR
:   Address where this header will be placed. Needed to compute the IE
    table address on TA 2.1 and 3.x, and mandatory for CF headers, where it
    tells the IBR where the ISBC CSF header is.

IE_KEY, IE_REVOC, IE_KEY_SEL
:   ISBC Key Extension: IE_KEY lists up to 32 extra public key files that
    the ISBC header carries in an IE table (written to *ie_table.out* and
    signed with the SRK). Later ESBC headers select one of them with
    IE_KEY_SEL instead of carrying an SRK table, so the boot loader can
    verify images with keys that are not in the SRKH. IE_REVOC lists the
    1 based indexes of IE keys to mark revoked.

## RCW fields (uni_pbi)

RCW_PBI_FILENAME
:   Input RCW (plus PBI) binary. Mandatory.

BOOT1_PTR
:   Address of the ISBC CSF header of the first image. Mandatory.

OUTPUT_RCW_PBI_FILENAME
:   TA 2.x output file, default *rcw_pbi_sec.bin*.

SB_EN, BOOT_HO
:   TA 2.x: set the Secure Boot Enable bit, and the Boot Hold-Off bit that
    keeps the core in reset so the SRKH can be fused from a debugger. On
    TA 3.x the tool always sets SB_EN.

BOOT_SRC
:   TA 2.x: *SD_BOOT* when booting from SD. APPEND_IMAGES offsets are then
    counted from the start of the SD card, and the tool subtracts the 0x1000
    bytes (block 8) at which the RCW itself is stored.

COPY_CMD
:   `{src_offset,dst_addr,file}`, up to 10 entries.
    TA 2.x: the contents of *file* are embedded in the PBI as Alternate
    Configuration Space (ACS) write commands targeting *dst_addr* in OCRAM,
    so that SPL and its header are loaded by the PBL itself from a non-XIP
    medium such as SD or NAND. *src_offset* is not used and is conventionally
    *ffffffff*.
    TA 3.x: block copy commands.

IE_TABLE_ADDR
:   TA 3.x: 64 bit address of the IE table, written to SCRATCHRW13/14 by a
    PBI command so U-Boot can find it.

MP_FLAG, ISS_FLAG, LW_FLAG
:   TA 3.x flags of the PBI header, as for **uni_sign**.

## CF header fields (uni_cfsign)

CF_WORD
:   `(address,data)`, up to 1024 pairs written by the IBR before it looks
    for the ESBC header. Typically the local bus and DDR setup needed to
    read the boot loader.

IMAGE_TARGET, ESBC_HDRADDR
:   As above, both mandatory.

ESBC_HDRADDR_SEC_IMAGE
:   C290 and T1040 family: header address of the secondary image.

## Fuse script fields (gen_fusescr)

OTPMK_FLAGS
:   Four binary digits: *0000* program the default minimal OTPMK, *0001*
    a random value, *0010* the OTPMK_0..7 values, *0101* and *0110* the
    same on top of a pre-programmed minimal value, *1xxx* leave the OTPMK
    alone.

OTPMK_0 .. OTPMK_7, SRKH_0 .. SRKH_7
:   Register values as printed by **gen_otpmk_drbg** and **uni_sign
    --hash**.

OEM_UID_0 .. OEM_UID_4, DCV_0, DCV_1, DRV_0, DRV_1
:   OEM identifiers, debug challenge and debug response values (from
    **gen_drv_drbg**).

DBG_LVL
:   Three binary digits: *000* debug open, *001* challenge/response without
    notification, *01x* with notification, *1xx* debug closed.

WP, ITS, NSEC, ZD, K0 .. K6, FR0, FR1
:   System configuration bits: OEM write protect, Intent To Secure,
    non-secure, ZUC disable, key revocation and field return.

POVDD_GPIO
:   GPIO the firmware raises to supply POVDD during programming, when the
    board does not use a jumper.

OUTPUT_FUSE_FILENAME
:   Default *fuse_scr.bin*.

# WORKFLOWS

All examples target the LX2160ARDB booting from FlexSPI NOR (*xspi*) with
the LSDK layout, where the RCW with BL2 sits at flash offset 0, the FIP at
0x100000, the CST header bundle at 0x600000, the DDR PHY FIP at 0x800000,
the fuse provisioning FIP at 0x880000, MC at 0xa00000, DPL at 0xd00000 and
DPC at 0xe00000. For SD or eMMC the same offsets apply in 512 byte blocks
starting at block 8.

## Generate the keys

    gen_keys 2048          # srk.pri and srk.pub
    gen_otpmk_drbg -b 2    # OTPMKR0..7, keep for fuse provisioning

Copy *srk.pri* and *srk.pub* into the TF-A tree (its default input files
name them there) and into the CST directory. Up to eight public keys can be
listed in PUB_KEY: KEY_SELECT picks the one used, and the SRKH covers the
whole table, so decide the key set before fusing.

## Build the signed RCW, BL2 and FIP with TF-A

    make PLAT=lx2160ardb TRUSTED_BOARD_BOOT=1 CST_DIR=/usr/bin \
         BOOT_MODE=flexspi_nor RCW=rcw_2200_750_3200_19_5_2.bin \
         BL32=tee.bin SPD=opteed BL33=u-boot.bin pbl fip
    make PLAT=lx2160ardb TRUSTED_BOARD_BOOT=1 CST_DIR=/usr/bin fip_ddr

TF-A runs the CST tools for you. For *pbl* it creates the BL2 header with
`create_hdr_isbc --in bl2.bin --out hdr_bl2 input_bl2_ch3_2` (ENTRY_POINT
and IMAGE_1 at 0x1800d000, ISS_FLAG=1), lets *create_pbl* add the block
copy commands that place the header at 0x1800a000 and BL2 at 0x1800d000
from flash offsets 0x5000 and 0x9000, then signs the whole RCW and PBI with
`create_hdr_pbi --out bl2_flexspi_nor_sec.pbl --in rcw_sec.pbl
input_pbi_ch3_2`. For *fip* every component gets an ESBC header prepended
with `create_hdr_esbc --in bl31.bin --out bl31.bin.cst --app bl31.bin
--app_off 0x3000 input_blx_ch3`, that is a 12 KiB header followed by the
image, which BL2 validates before use. The outputs are
*bl2_flexspi_nor_sec.pbl*, *fip.bin* and *ddr_fip_sec.bin*. Use
BL31_INPUT_FILE, BL32_INPUT_FILE and BL33_INPUT_FILE to point at your own
input files, for instance to set OEM UIDs.

## Sign the images U-Boot validates

    cd /var/tmp/sign && cp /usr/share/cst/platforms/lx2160_xspi.sh .
    cp -r /usr/share/cst/input_files . && cp ~/srk.pri ~/srk.pub .
    cp .../lx2160ardb_boot.scr bootscript
    cp .../Image uImage.bin ; cp .../fsl-lx2160a-rdb.dtb uImage.dtb
    cp .../kernel.itb . ; cp .../mc.itb .; cp .../dpl.dtb .; cp .../dpc.dtb .
    ./lx2160_xspi.sh

This is what flexbuild does in *tools/secure_sign_image*. The script runs
**uni_sign** on each input file of *input_files/uni_sign/lx2160/* (the
*nor/* subdirectory for MC, DPC and DPL, *sd/* for SD boot), writes
*srk_hash.txt*, and builds *secboot_hdrs_xspiboot.bin* with the kernel ITB
header at 0, the MC header at 256 KiB, the DPC header at 512 KiB and the
DPL header at 768 KiB. Flash that bundle at 0x600000, and put *hdr_bs.out*,
*hdr_linux.out* and *hdr_dtb.out* where the boot script expects them: the
LSDK distro boot script loads */secboot_hdrs/lx2160ardb/hdr_linux.out* and
*hdr_dtb.out* from the boot partition and runs `esbc_validate` on each
before `booti`. Any change to an image, an address or the key set means
running the script again.

## Signing with an external signer

The private key never has to be provided to CST. Run the header tool with
**--img_hash** and the public key only, sign the 32 byte digest elsewhere,
then embed the result. For the kernel of the LX2160 flow:

    uni_sign --img_hash input_files/uni_sign/lx2160/input_kernel_secure
    gen_sign hash.out srk.pri            # or an HSM producing PKCS#1 v1.5
    sign_embed hdr_kernel.out sign.out

Any signer works provided it produces a PKCS#1 v1.5 signature of the SHA-256
digest with a SHA-256 DigestInfo, for instance
`openssl pkeyutl -sign -inkey srk.pri -pkeyopt digest:sha256 -in hash.out`.
The three step result is byte for byte identical to the single step one.
The headers TF-A creates can be handled the same way by adding
**--img_hash** to the **create_hdr_isbc**, **create_hdr_pbi** and
**create_hdr_esbc** invocations in *tools/nxp/create_pbl/pbl_ch3.mk* and
*drivers/nxp/auth/csf_hdr_parser/csf_hdr.mk*, then signing and embedding
each hash before the images are assembled.

## Provision the fuses on the LX2160ARDB

    uni_sign --hash input_files/uni_sign/lx2160/input_kernel_secure
    cp /usr/share/cst/input_files/gen_fusescr/ls2088_1088/input_fuse_file .
    # set PLATFORM=LX2160, OTPMK_FLAGS, OTPMK_0..7 from gen_otpmk_drbg,
    # SRKH_0..7 from the SRKHR values just printed, optionally OEM UIDs,
    # DCV/DRV from gen_drv_drbg A2, DBG_LVL, and ITS once validated
    gen_fusescr input_fuse_file          # fuse_scr.bin

TF-A packs the script into a fuse provisioning FIP: put jumper J9 on the
board to supply POVDD and set POVDD_ENABLE to yes in
*plat/nxp/soc-lx2160a/lx2160ardb/platform.mk*:

    make PLAT=lx2160ardb FUSE_PROG=1 BOOT_MODE=flexspi_nor RCW=... \
         BL32=tee.bin SPD=opteed BL33=u-boot.bin \
         FUSE_PROV_FILE=/path/to/input_fuse_file pbl fip fip_fuse

Flash *fuse_fip.bin* at 0x880000, boot once, and check that DCFG scratch
register 4 reads zero (`md 1e0020c 1`). The values of the SFP mirror
registers can also be written from U-Boot with `mw.l` and committed with
the SFP INGR register: on LX2160 the SFP is little-endian, so the SRKHR
words are written exactly as printed, unlike big-endian SFP devices such
as LS1046 where they must be byte swapped. Fusing is irreversible.

## Check the secure state

    => md 1e90014 1
    01e90014: 8000af00

Bits 11:8 of SNVS_HPSR at 0x01e90014 give the security state machine: 0xf
is secure boot, 0xb a non-secure boot. The bit 15 set means the BootROM booted
and bits 14:12 equal to 010 mean Intent To Secure. A BL2 or FIP validation
failure shows up as an ISBC or ESBC error code in DCFG scratch register 3
(`md 1e00208 1`) and, once the ITS fuse is blown, stops the boot.

# FILES

*srk.pri*, *srk.pub*
:   Default key pair.

*hdr.out*, *hash.out*, *sign.out*, *sg_table.out*, *ie_table.out*,
*rcw_pbi_sec.bin*, *fuse_scr.bin*
:   Default output names.

*/usr/share/cst/input_files/*
:   Sample input files per tool and platform, including *input_unisign_format*
    and *input_cfsign_format* which describe every field.

*/usr/share/cst/platforms/*
:   Board scripts chaining the tools for each boot medium, *lx2160_xspi.sh*
    and *lx2160_sd.sh* for the LX2160ARDB.

*secboot_hdrs_xspiboot.bin*, *secboot_hdrs_sdboot.bin*
:   Header bundle those scripts produce, flashed at 0x600000.

*drivers/nxp/auth/csf_hdr_parser/input_bl2_ch3_2*, *input_pbi_ch3_2*, *input_blx_ch3*
:   Input files TF-A feeds to CST for the LX2160 RCW, BL2 and FIP.

# EXIT STATUS

0 on success. Errors return -1.

# NOTES

The SRKH and OTPMK fuses cannot be changed. Fuse the eight SRKHR values
exactly as printed, each as a 32 bit big endian word in the register given,
and generate a distinct OTPMK per device. Setting the ITS fuse commits the
device to secure boot permanently.

The **uni_sign** wrapper selects the ESBC tool with a literal match on
`ESBC=1`. `ESBC = 1` or a trailing space silently falls back to the ISBC
header, which the boot loader will reject.

The signature covers the image contents, so the header must be regenerated
whenever an image or a load address changes.

On LX2160 the BL2 header must fit in the 12 KiB (CSF_HDR_SZ 0x3000) that
TF-A reserves between 0x1800a000 and 0x1800d000 in OCRAM. Eight 4096 bit
keys in the SRK table still fit. The same 0x3000 is the **--app_off** used
for the FIP components, so the header size of every TF-A image is bounded
by that value.

**gen_otpmk_drbg** and **gen_drv_drbg** block until */dev/random* has
entropy on old kernels. Use **--u** during development only. The DRBG
library runs its NIST CAVP self tests on every start.

Builds against OpenSSL 3 keep producing PKCS#1 key files so keys remain
interchangeable with older CST releases.

# HISTORY

The code base was started at Freescale in November 2010 for the P-series
(TA 1.x) devices and later maintained by NXP. The milestones:
 - the Trust Architecture Abstraction Layer (*taal*) and
   the *--hash* and *--img_hash* options in November 2015
 - followed by the current tool layout with *gen_sign* and *sign_embed*
   in December 2015
 - LS2085 and the ISBC Key Extension in early 2016
 - PBI creation with ACS write commands for LS1021A SD boot in early 2017
 - unified input files per SoC family and the per-board platform scripts
   in 2017
 - weak default implementations in *taal* and the fuse provisioning tool
   in January 2018
 - OpenSSL 1.1 support, command line options for the header tools and LX2160
   in mid 2018
 - TF-A based boot flows in August 2018
 - LS1028 in January 2019
 - IMA-EVM boot scripts in 2019
 - the port to the OpenSSL 3 EVP interface in 2026

# SEE ALSO

*openssl-genrsa*(1), *openssl-pkeyutl*(1)

Layerscape Software Development Kit User Guide, chapter *Secure boot*
(*Code Signing Tool*, *CSF Header Data Structure*, *ISBC/ESBC Validation
Error Codes*, *Fuse Provisioning User Guide*),
<https://www.nxp.com/design/software/embedded-software/linux-software-and-development-tools/layerscape-software-development-kit:LAYERSCAPE-SDK>

Upstream sources: <https://github.com/nxp-qoriq/cst>

Trusted Firmware-A, NXP Layerscape platform documentation: *nxp-layerscape*,
*nxp-ls-tbbr* (trusted board boot with CSF headers) and *nxp-ls-fuse-prov*
(fuse provisioning, LX2160ARDB jumper J9),
<https://trustedfirmware-a.readthedocs.io/en/latest/plat/nxp/>, with the
CST input files in *drivers/nxp/auth/csf_hdr_parser/* and the PBL
assembly in *tools/nxp/create_pbl/pbl_ch3.mk* of the TF-A sources.

NXP flexbuild, *docs/memory_layout.txt* (flash offsets), *tools/secure_sign_image*
and *configs/board/lx2160ardb.conf*, <https://github.com/NXP/flexbuild>

NXP community, Layerscape knowledge base: *Setting up Secure Boot on
LS1028ARDB Platform*, *Secure boot, Fuse Provisioning, Secure debug*, and
the threads *How to sign binaries with CST and using a HSM instead of
srk.pri/pub local files* and *CSF Header: RSA Signature*,
<https://community.nxp.com/t5/Layerscape/bd-p/layerscape>

Grapeboard (LS1012A) secure boot procedure with CST,
<https://github.com/ms-iot/lsdk/blob/master/docs/grapeboard_secureboot.md>

# COPYRIGHT

Copyright 2008-2016 Freescale Semiconductor, Inc. Copyright 2016-2025 NXP.
This manual page Copyright 2026 Free Mobile, Vincent Jardin. CST and this
page are distributed under the BSD-3-Clause license.
