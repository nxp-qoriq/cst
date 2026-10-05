#!/bin/bash
#
# Copyright 2026 Free Mobile, Vincent Jardin
#
# Smoke tests
#
set -eu

TOP=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

cd "$WORK"
cp -r "$TOP/input_files" .
for t in create_hdr_isbc create_hdr_esbc create_hdr_pbi create_hdr_cf \
	 gen_keys gen_sign sign_embed gen_fusescr gen_otpmk_drbg gen_drv_drbg; do
	[ -x "$TOP/$t" ] || fail "$t not built"
	ln -s "$TOP/$t" "$t"
done
cp "$TOP"/scripts/uni_sign "$TOP"/scripts/uni_pbi "$TOP"/scripts/uni_cfsign .

head -c 4096   /dev/urandom > bootscript
head -c 100000 /dev/urandom > kernel.itb
head -c 65536  /dev/urandom > u-boot.bin

# Tiny RCW: 35 words, PBI length 2, ending with the STOP command
{
	printf '\x55\xaa\x55\xaa\x00\x00\x10\x80'
	for i in $(seq 3 10); do printf '\x00\x00\x00\x00'; done
	printf '\x00\x00\x20\x00'                    # word 10: pbi_len = 2
	for i in $(seq 12 35); do printf '\x00\x00\x00\x00'; done
	printf '\x00\x00\xff\x80\x00\x00\x00\x00'    # STOP_CMD + crc word
} > rcw.bin

# Key generation
for bits in 1024 2048 4096; do
	./gen_keys -k pub$bits.pem -p pri$bits.pem $bits > /dev/null
	head -1 pri$bits.pem | grep -q 'BEGIN RSA PRIVATE KEY' || fail "pri$bits: wrong PEM label"
	head -1 pub$bits.pem | grep -q 'BEGIN RSA PUBLIC KEY'  || fail "pub$bits: wrong PEM label"
	openssl rsa -in pri$bits.pem -check -noout > /dev/null 2>&1 || fail "pri$bits: openssl rejects key"
done
cp pri2048.pem srk.pri
cp pub2048.pem srk.pub
pass "gen_keys 1024/2048/4096, PKCS#1 PEM, keys valid"

# Header generation on every trust architecture
run_hdr() {
	local name=$1 out=$2 wrapper=$3 input=$4
	rm -f "$out"
	./$wrapper "$input" > "$name.log" 2>&1 || { cat "$name.log"; fail "$name"; }
	[ -s "$out" ] || fail "$name: $out not created"
	pass "$name -> $out ($(stat -c%s "$out") bytes)"
}
run_hdr esbc_ta2  hdr_bs.out     uni_sign   input_files/uni_sign/ls104x_1012/input_bootscript_secure
run_hdr esbc_ta3  hdr_kernel.out uni_sign   input_files/uni_sign/lx2160/input_kernel_secure
run_hdr isbc_ta1  esbc_hdr.out   uni_sign   input_files/uni_sign/p1010/input_uboot_nor_secure
run_hdr isbc_ta2  hdr_uboot.out  uni_sign   input_files/uni_sign/t1_t2_t4/input_uboot_nor_secure
run_hdr cf_ta1    cf_hdr.out     uni_cfsign input_files/uni_cfsign/p1010/input_nor_secure
run_hdr pbi_ta3   rcw_sec.bin    uni_pbi    input_files/uni_pbi/lx2160/input_pbi_flexspi_nor_secure
# Add here your needed targets

# SRK hash option
./uni_sign --hash input_files/uni_sign/ls104x_1012/input_bootscript_secure > srk_hash.log 2>&1
grep -qE '^[0-9a-f]{64}$' srk_hash.log || fail "--hash did not print a 64 hex digit SRK hash"
pass "--hash prints SRK hash"

# Two step flow: --img_hash, gen_sign, sign_embed
cp hdr_bs.out hdr_bs.ref
./uni_sign --img_hash input_files/uni_sign/ls104x_1012/input_bootscript_secure > two_step.log 2>&1
[ "$(stat -c%s hash.out)" = 32 ] || fail "hash.out is not a 32 byte SHA256"
./gen_sign hash.out srk.pri > /dev/null
./sign_embed hdr_bs.out sign.out > /dev/null
cmp hdr_bs.ref hdr_bs.out || fail "two step header differs from single step header"
pass "img_hash + gen_sign + sign_embed reproduces the single step header"

# OpenSSL 1.1 and 3 common checks
# OpenSSL 1.1 only loads SubjectPublicKeyInfo public keys, so derive one.
openssl rsa -in srk.pri -pubout -out srk_spki.pub 2> /dev/null
openssl pkeyutl -verify -pubin -inkey srk_spki.pub -sigfile sign.out -in hash.out \
	-pkeyopt digest:sha256 > verify.log 2>&1 || { cat verify.log; fail "openssl cannot verify sign.out"; }
pass "openssl verifies the RSA signature"

# The public key in SubjectPublicKeyInfo form is accepted since OpenSSL 3
if openssl version | grep -qE '^OpenSSL ([3-9]|[1-9][0-9])\.'; then
	sed 's/^PUB_KEY=.*/PUB_KEY=srk_spki.pub/' \
		input_files/uni_sign/ls104x_1012/input_bootscript_secure > input_spki
	./uni_sign input_spki > spki.log 2>&1 || { cat spki.log; fail "SPKI public key"; }
	cmp hdr_bs.ref hdr_bs.out || fail "SPKI public key gives a different header"
	pass "SubjectPublicKeyInfo public key accepted"
fi

# Other tools
./gen_fusescr input_files/gen_fusescr/ls104x_1012/input_fuse_file > fuse.log 2>&1 || { cat fuse.log; fail "gen_fusescr"; }
[ -s fuse_scr.bin ] || fail "fuse_scr.bin not created"
pass "gen_fusescr -> fuse_scr.bin"

./gen_otpmk_drbg > otpmk.log 2>&1 || { cat otpmk.log; fail "gen_otpmk_drbg"; }
grep -qiE '[0-9a-f]{8}' otpmk.log || fail "gen_otpmk_drbg printed no OTPMK"
pass "gen_otpmk_drbg"

./gen_drv_drbg A1 > drv.log 2>&1 || { cat drv.log; fail "gen_drv_drbg"; }
pass "gen_drv_drbg"

echo "All smoke tests passed"
