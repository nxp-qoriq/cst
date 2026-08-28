# cst-ng — Code Signing Tool for NXP QorIQ and Layerscape

`cst-ng` builds the key material, boot headers and signed PBI/RCW images required by
the Trust Architecture secure boot flow on NXP QorIQ and Layerscape SoCs.

On these parts the on-chip Internal Secure Boot Code (ISBC) validates the first
image it loads against a signed header, and the External Secure Boot Code (ESBC)
running from that image validates everything loaded afterwards. This tool produces
those headers, the RSA key pairs behind them, the SRK hash that is fused into the
device, and the OTPMK/debug-response values used to provision it.

This is a fork of NXP's [`cst`](https://github.com/nxp-qoriq/cst), updated to build
and run cleanly on current toolchains. Generated headers, signatures and SRK hashes
are byte-identical to upstream for every configuration shipped in `input_files/`, and
existing `srk.pub`/`srk.pri` key files remain valid — see
[Differences from upstream](#differences-from-upstream).

## Supported platforms

The platform named in the input file selects the trust-architecture revision, which
in turn selects the header layout. No command-line switch is involved.

| Trust architecture | Platforms |
| --- | --- |
| TA 1.x (PBL) | P2041, P3041, P4080, P5020, P5040 |
| TA 1.x (non-PBL) | P1010, BSC9131, BSC9132 |
| TA 2.0 (PBL) | T1023, T1040, T2080, T4240, B4860 |
| TA 2.0 (non-PBL) | C290 |
| TA 2.1 (ARMv7) | LS1020 |
| TA 2.1 (ARMv8) | LS1012, LS1043, LS1046 |
| TA 3.0 | LS2080, LS2085 |
| TA 3.1 | LS1088, LS2088 |
| TA 3.2 | LS1028, LX2160 |

## Prerequisites

* GCC and GNU make
* OpenSSL development headers and libraries, 1.1.1 or later (3.x is supported)

On Debian or Ubuntu:

```sh
sudo apt install build-essential libssl-dev
```

## Building

```sh
make
```

The executables and the wrapper scripts from `scripts/` are placed in the top level
of the working tree, which is where the tools expect to find each other.

To build against an OpenSSL installed outside the default search paths, point the
build at it rather than overriding `CFLAGS`:

```sh
make OPENSSL_INC_PATH=/opt/openssl/include OPENSSL_LIB_PATH=/opt/openssl/lib
```

Other targets:

| Target | Effect |
| --- | --- |
| `make install` | Installs the binaries, `scripts/` and `input_files/` under `$(DESTDIR)$(BIN_DEST_DIR)/cst` (`BIN_DEST_DIR` defaults to `/usr/bin`) |
| `make clean` | Removes the objects, binaries and copied scripts |
| `make distclean` | Also removes generated keys, headers and images, returning the tree to its checked-out state |

## Quick start

Sign a U-Boot image for an LS2088 board:

```sh
make

# Generate a 2048-bit super root key pair (srk.pub / srk.pri).
./gen_keys 2048

# The image named by the input file must be present in the working directory.
cp /path/to/u-boot-dtb.bin .

# Produce the signed header (hdr_uboot.out).
./uni_sign --verbose input_files/uni_sign/ls2088_1088/qspi_ls2088/input_uboot_secure
```

Print the SRK hash to be fused into the device's SFP:

```sh
./uni_sign --hash input_files/uni_sign/ls2088_1088/qspi_ls2088/input_uboot_secure
```

```
SRK (Public Key) Hash:
e52870da638b75944a20de7a86b80d758b2e52cc7468d067550e5e0172cfb54b
	 SFP SRKHR0 = e52870da
	 ...
```

The hash covers the public key exactly as it is embedded in the header, so it changes
whenever the key or the key table does.

## Input files

The header-creation tools are driven by a configuration file rather than by command
line arguments. `input_files/` holds a ready-made file for each supported board and
boot source; copy the closest match and edit it. `input_files/uni_sign/input_unisign_format`
documents every field.

A minimal example:

```
PLATFORM=LS2088
ENTRY_POINT=20100000
PUB_KEY=srk.pub
PRI_KEY=srk.pri
KEY_SELECT=1
IMAGE_1={u-boot-dtb.bin,20100000,ffffffff}
OUTPUT_HDR_FILENAME=hdr_uboot.out
```

Notes:

* `PLATFORM` is mandatory and chooses the header format.
* Up to eight images may be listed. `DST_ADDR` is only meaningful on non-PBL parts.
* TA 2.0 parts support a table of up to four keys selected by `KEY_SELECT`; other
  parts take a single key and no `KEY_SELECT`.
* `ESBC=1` signs an image validated by the ESBC chain; the default, `ESBC=0`, signs
  the image validated by the on-chip ISBC.
* Paths in the input file are resolved relative to the current directory, so run the
  tools from the directory holding the images.

## Tools

### Wrapper scripts

These are the normal entry points. Each inspects the input file and dispatches to the
right header-creation binary.

| Script | Purpose |
| --- | --- |
| `uni_sign` | Signs boot and ESBC images (`create_hdr_isbc`, `create_hdr_esbc`) |
| `uni_pbi` | Signs the PBI/RCW image (`create_hdr_pbi`) |
| `uni_cfsign` | Signs images in the CF header format (`create_hdr_cf`) |

Common options: `--verbose` dumps the generated header fields, `--hash` prints the SRK
hash, `--img_hash` writes the image hash to a separate file and emits an unsigned
header, and `--out`/`--in` override the file names from the input file.

The `--img_hash` flow exists for setups where the private key is held offline: the
tool emits the hash to be signed, `gen_sign` (or an external HSM) produces the
signature, and `sign_embed` inserts it into the header.

### Key generation

| Tool | Purpose |
| --- | --- |
| `gen_keys <bits>` | Generates an RSA key pair, 1024, 2048 or 4096 bits. Defaults to `srk.pub` and `srk.pri`; override with `-k` and `-p`. |
| `gen_otpmk_drbg` | Generates a One Time Programmable Master Key with correct parity. `--b 1` for BSC913x/P1010/P3/P4/P5/C29x, `--b 2` for T-series, B-series and Layerscape. |
| `gen_drv_drbg` | Generates a debug response value with Hamming code. `A1` for T10xx/T20xx/T4xxx/P4080rev1/B4xxx, `A2` for Layerscape, `B` for P10xx/P20xx/P30xx/P4080rev2/rev3/P50xx/BSC913x/C29x. |

Both DRBG tools read entropy from `/dev/random` by default; `gen_otpmk_drbg --u`
selects `/dev/urandom`.

### Header creation

Called by the wrapper scripts, and usable directly:
`create_hdr_isbc`, `create_hdr_esbc`, `create_hdr_pbi`, `create_hdr_cf`.

`create_hdr_pbi` additionally takes `--sben` to set `SB_EN` in the RCW, which arms
secure boot on the target.

### Signature generation

| Tool | Purpose |
| --- | --- |
| `gen_sign [--sign_file <out>] <hash_file> <priv_key>` | Signs a hash produced by `--img_hash`. Writes `sign.out` by default. |
| `sign_embed <hdr_file> <sign_file>` | Embeds a detached signature into an already generated header. |

### Fuse provisioning

`gen_fusescr <input_file>` builds the fuse script (`fuse_scr.bin`) that programs the
SRK hash, OTPMK, debug response and related fuses. Templates are in
`input_files/gen_fusescr/`.

## Repository layout

| Path | Contents |
| --- | --- |
| `common/` | Crypto helpers, input-file parser and shared definitions |
| `taal/` | Trust Architecture Abstraction Layer: maps a platform to its header format |
| `tools/` | The tools themselves, one directory per category |
| `lib_hash_drbg/` | Hash DRBG used by the OTPMK and debug-response generators |
| `scripts/` | Wrapper scripts copied to the top level by `make` |
| `input_files/` | Ready-made input files for each supported board |

Header layouts are implemented per trust-architecture revision under
`tools/header_generation/*/taal_api/`. Adding a platform that reuses an existing
layout is a matter of extending the table in `taal/taal.c`.

## Differences from upstream

* Builds warning-free against OpenSSL 3.x. The RSA and hashing code uses the EVP API
  instead of the low-level `RSA_*` functions removed from the modern interface. Key
  files keep their existing PKCS#1 encoding, so keys generated by either version are
  interchangeable.
* Buffer bounds are enforced where a key file or an RCW read from disk previously
  controlled the size of a write into a fixed-size buffer. Oversized keys and
  malformed RCWs are now rejected with a diagnostic instead of corrupting memory.
* A misaligned load when printing the SRK hash was replaced with a defined access.
* `make clean` now undoes `make`, and generated files are excluded from version
  control.

One deliberate output change: the PBI block-copy command previously derived its
length with a padding expression that did not round up, so an image whose size was
not a multiple of four produced a length matching neither the file nor its aligned
size. It now rounds up correctly. Every configuration in `input_files/` uses
4-byte-aligned images and is unaffected.

## License

BSD 3-Clause. See [LICENSE](LICENSE).

Copyright (c) 2008-2016 Freescale Semiconductor, Inc.
Copyright 2017 NXP.
