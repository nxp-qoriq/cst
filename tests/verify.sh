#!/bin/bash
#
# Copyright 2026 Free Mobile, Vincent Jardin
#
# cst_verify test suite:
#    positive cases built with the CST tools
#    negative cases by mutating them
#
set -euo pipefail

TOP=$(cd "$(dirname "$0")/.." && pwd)
readonly TOP
readonly SAMPLES=${TOP}/input_files/uni_sign
SCRATCH=
STATUS=0
OUTPUT=
SRK_HASH=
OTHER_SRK_HASH=

readonly CSF_HDR_SZ=0x3000
readonly UNALIGNED_BL2_SIZE=50001

readonly HDR_BARKER=0x00
readonly HDR_SRK_TABLE_OFFSET=0x04
readonly HDR_NUM_SRK=0x08
readonly HDR_SRK_SELECT=0x09
readonly HDR_MISC_FLAGS=0x0b
readonly HDR_SIGNATURE_OFFSET=0x10
readonly HDR_SIGNATURE_LENGTH=0x14
readonly HDR_IMAGE_ADDRESS=0x18
readonly HDR_SG_TABLE_OFFSET=0x18
readonly HDR_SG_ENTRIES=0x1c
readonly HDR_IMAGE_LENGTH=0x20
readonly HDR_ENTRY_POINT=0x20
readonly HDR_FSL_UID=0x28
readonly SRK_MODULUS=4
readonly SG_TARGET=4
readonly MISC_IE=0x01
readonly MISC_ISS=0x20

readonly THREE_PUBLIC_KEYS=rsa1024.pub,srk.pub,rsa4096.pub
readonly THREE_PRIVATE_KEYS=rsa1024.pri,srk.pri,rsa4096.pri

readonly -a INPUT_KERNEL_SECURE=(
	PLATFORM=LX2160
	PUB_KEY=srk.pub
	PRI_KEY=srk.pri
	KEY_SELECT=1
	'IMAGE_1={kernel.itb,a0000000,ffffffff}'
)
readonly -a INPUT_BL2_CH3_2=(
	PLATFORM=LX2160
	PUB_KEY=srk.pub
	PRI_KEY=srk.pri
	KEY_SELECT=1
	ENTRY_POINT=1800D000
	'IMAGE_1={bl2.bin,1800D000,ffffffff}'
	MP_FLAG=0
	ISS_FLAG=1
	LW_FLAG=0
)
pass() {
	echo "PASS: $*"
}

fail() {
	echo "FAIL: $1" >&2
	shift
	if (( $# > 0 )); then
		printf '%s\n' "$@" >&2
	fi
	exit 1
}

quietly() {
	local output
	output=$("$@" 2>&1) || fail "$*" "${output}"
}

file_size() {
	stat -c%s "$1"
}

random_file() {
	head -c "$2" /dev/urandom > "$1"
}

byte() {
	local escape
	printf -v escape '\\x%02x' "$1"
	printf '%b' "${escape}"
}

le32() {
	local value=$1
	byte $(( value & 0xff ))
	byte $(( (value >> 8) & 0xff ))
	byte $(( (value >> 16) & 0xff ))
	byte $(( (value >> 24) & 0xff ))
}

write_at() {
	dd of="$1" bs=1 seek=$(( $2 )) conv=notrunc status=none
}

write_u8() {
	byte "$3" | write_at "$1" "$2"
}

write_le32() {
	le32 "$3" | write_at "$1" "$2"
}

read_u8() {
	od -An -tu1 -j $(( $2 )) -N1 "$1" | tr -d ' '
}

read_le32() {
	local b0 b1 b2 b3
	read -r b0 b1 b2 b3 < <(od -An -tu1 -j $(( $2 )) -N4 "$1")
	echo $(( b0 | (b1 << 8) | (b2 << 16) | (b3 << 24) ))
}

flip_byte() {
	write_u8 "$1" "$2" $(( $(read_u8 "$1" "$2") ^ 0x5a ))
}

make_even() {
	write_u8 "$1" "$2" $(( $(read_u8 "$1" "$2") & 0xfe ))
}

copy_bytes() {
	local file=$1 from=$2 to=$3 count=$4
	dd if="${file}" bs=1 skip=$(( from )) count=$(( count )) status=none > copied.bin
	write_at "${file}" "${to}" < copied.bin
}

signature_end() {
	local file=$1 header=${2:-0} offset length
	offset=$(read_le32 "${file}" $(( header + HDR_SIGNATURE_OFFSET )))
	length=$(read_le32 "${file}" $(( header + HDR_SIGNATURE_LENGTH )))
	echo $(( header + offset + length ))
}

modulus_last_byte() {
	local file=$1 srk_table=$2 key_length
	key_length=$(read_le32 "${file}" "${srk_table}")
	echo $(( srk_table + SRK_MODULUS + key_length / 2 - 1 ))
}

modulus_as_signature() {
	local file=$1 modulus signature length
	modulus=$(( $(read_le32 "${file}" "${HDR_SRK_TABLE_OFFSET}") + SRK_MODULUS ))
	signature=$(read_le32 "${file}" "${HDR_SIGNATURE_OFFSET}")
	length=$(read_le32 "${file}" "${HDR_SIGNATURE_LENGTH}")
	copy_bytes "${file}" "${modulus}" "${signature}" "${length}"
}

revocation_mask() {
	local key mask=0
	for key in "$@"; do
		mask=$(( mask | 1 << (7 - key) ))
	done
	printf '0x%x' "${mask}"
}

write_input() {
	local file=$1 assignment field
	local -A value=()
	local -a fields=()
	shift
	for assignment in "$@"; do
		field=${assignment%%=*}
		if [[ -z ${value[${field}]+set} ]]; then
			fields+=("${field}")
		fi
		value[${field}]=${assignment#*=}
	done
	for field in "${fields[@]}"; do
		echo "${field}=${value[${field}]}"
	done > "${file}"
}

sign_esbc() {
	local output=$1 image_offset=$2
	shift 2
	write_input esbc_input.txt "${INPUT_KERNEL_SECURE[@]}" "$@"
	quietly create_hdr_esbc --in kernel.itb --out "${output}" \
		--app_off "${image_offset}" --app kernel.itb esbc_input.txt
}

sign_bl2() {
	local output=$1
	shift
	write_input bl2_input.txt "${INPUT_BL2_CH3_2[@]}" "$@"
	quietly create_hdr_isbc --in bl2.bin --out "${output}" bl2_input.txt
}

srk_hash_of_input() {
	create_hdr_esbc --hash "$1" | grep -E '^[0-9a-f]{64}$'
}

run_cst_verify() {
	STATUS=0
	OUTPUT=$(cst_verify "$@" 2>&1) || STATUS=$?
	if [[ ${OUTPUT} == *"runtime error"* || ${OUTPUT} == *Sanitizer* ]]; then
		fail "cst_verify $*: sanitizer report" "${OUTPUT}"
	fi
	if (( STATUS > 2 )); then
		fail "cst_verify $*: crashed with exit status ${STATUS}" "${OUTPUT}"
	fi
}

failed_checks() {
	sed -n 's/^\([A-Z][0-9]*\) FAIL:.*/\1/p' <<< "${OUTPUT}" | sort -u | paste -sd ' '
}

sorted_words() {
	tr ' ' '\n' <<< "$1" | sort -u | paste -sd ' '
}

expect_pass() {
	local description=$1
	shift
	run_cst_verify "$@"
	if (( STATUS != 0 )); then
		fail "$1: ${description}: exit status ${STATUS}, expected 0" "${OUTPUT}"
	fi
	pass "$1: ${description}"
}

expect_fail() {
	local description=$1 expected actual
	expected=$(sorted_words "$2")
	shift 2
	run_cst_verify "$@"
	actual=$(failed_checks)
	if (( STATUS != 1 )) || [[ ${actual} != "${expected}" ]]; then
		fail "$1: ${description}: exit status ${STATUS} with failed checks '${actual}'," \
		     "expected exit status 1 with failed checks '${expected}'" "${OUTPUT}"
	fi
	pass "$1: ${description}"
}

expect_usage_error() {
	local description=$1
	shift
	run_cst_verify "$@"
	if (( STATUS != 2 )); then
		fail "$1: ${description}: exit status ${STATUS}, expected 2" "${OUTPUT}"
	fi
	pass "$1: ${description}"
}

truncation_lengths() {
	local size=$1 length
	for (( length = 0; length < size; length += length < 0x1000 ? 7 : 509 )); do
		echo "${length}"
	done
	for (( length = size > 16 ? size - 16 : 0; length < size; length++ )); do
		echo "${length}"
	done
}

expect_truncated_copies_fail() {
	local file=$1 length
	shift
	while read -r length; do
		head -c "${length}" "${file}" > truncated.bin
		run_cst_verify "$@" truncated.bin
		if (( STATUS == 0 )); then
			fail "$1: ${file} cut to ${length} bytes is accepted" "${OUTPUT}"
		fi
	done < <(truncation_lengths "$(file_size "${file}")")
	pass "$1: every truncated copy of ${file} fails"
}

esbc_mutant() {
	local description=$1 failing=$2 edit=$3
	shift 3
	cp kernel.cst mutant.cst
	"${edit}" mutant.cst "$@"
	expect_fail "${description}" "${failing}" esbc --in mutant.cst
}

isbc_mutant() {
	local description=$1 failing=$2 edit=$3
	shift 3
	cp hdr_bl2 mutant.hdr
	"${edit}" mutant.hdr "$@"
	expect_fail "${description}" "${failing}" isbc --hdr mutant.hdr --img bl2.bin
}

use_built_tools() {
	local tool
	for tool in cst_verify create_hdr_esbc create_hdr_isbc create_hdr_pbi gen_keys; do
		[[ -x ${TOP}/${tool} ]] || fail "${TOP}/${tool} is not built"
	done
	PATH=${TOP}:${PATH}
}

enter_scratch_directory() {
	SCRATCH=$(mktemp -d)
	trap 'rm -rf "${SCRATCH}"' EXIT
	cd "${SCRATCH}" || fail "cannot enter ${SCRATCH}"
}

generate_keys() {
	local bits
	for bits in 1024 2048 4096; do
		quietly gen_keys -k "rsa${bits}.pub" -p "rsa${bits}.pri" "${bits}"
	done
	cp rsa2048.pub srk.pub
	cp rsa2048.pri srk.pri
	quietly gen_keys -k other.pub -p other.pri 2048
}

generate_images() {
	random_file kernel.itb 40000
	random_file u-boot.bin 70000
	random_file bl2.bin "${UNALIGNED_BL2_SIZE}"
}

compute_srk_hashes() {
	write_input srk_input.txt "${INPUT_KERNEL_SECURE[@]}"
	write_input other_input.txt "${INPUT_KERNEL_SECURE[@]}" PUB_KEY=other.pub
	SRK_HASH=$(srk_hash_of_input srk_input.txt) || fail "no SRK hash for srk.pub"
	OTHER_SRK_HASH=$(srk_hash_of_input other_input.txt) || fail "no SRK hash for other.pub"
	[[ ${SRK_HASH} != "${OTHER_SRK_HASH}" ]] || fail "two keys give the same SRK hash"
}

sign_reference_images() {
	sign_esbc kernel.cst "${CSF_HDR_SZ}"
	sign_bl2 hdr_bl2
}

# ESBC headers as TF-A packs them in the FIP: header followed by the image,
# or apart. Checks the expected key, the SRK hash and key revocation the way
# BL2 reads them, so a FIP image BL2 would reject fails here, not on a board.
test_esbc() {
	head -c "$(signature_end kernel.cst)" kernel.cst > kernel.hdr
	head -c $(( $(file_size kernel.itb) - 1 )) kernel.itb > short.itb

	expect_pass "header followed by the image" esbc --in kernel.cst --pub srk.pub --srk-hash "${SRK_HASH}"
	expect_pass "header and image in two files" esbc --hdr kernel.hdr --img kernel.itb
	expect_pass "--platform LX2160" esbc --in kernel.cst --platform LX2160
	expect_pass "--ta 3.2" esbc --in kernel.cst --ta 3.2
	expect_fail "another --pub" E12 esbc --in kernel.cst --pub other.pub
	expect_fail "another --srk-hash" E8 esbc --in kernel.cst --srk-hash "${OTHER_SRK_HASH}"
	expect_fail "selected key revoked" E4 esbc --in kernel.cst --revoke-mask "$(revocation_mask 1)"
	expect_pass "every other key revoked" esbc --in kernel.cst --revoke-mask "$(revocation_mask 2 3 4 5 6 7)"
	expect_fail "image one byte short" E10 esbc --hdr kernel.hdr --img short.itb
}

# BL2 hashes the image from CSF_HDR_SZ whatever the header says. An image
# appended at another --app_off is self-consistent yet fails at boot: only
# an explicit offset check catches that mismatch with TF-A.
test_esbc_image_offset() {
	sign_esbc kernel_at_0xc00.cst 0xc00
	expect_fail "image at 0xc00, BL2 hashes from CSF_HDR_SZ" E13 esbc --in kernel_at_0xc00.cst
	expect_pass "image at 0xc00 with --hdr-size 0xc00" esbc --in kernel_at_0xc00.cst --hdr-size 0xc00
	expect_pass "image at 0xc00 with --hdr-size 0" esbc --in kernel_at_0xc00.cst --hdr-size 0
}

# One field corrupted at a time, as a broken build or a tampered file would.
# Each must fail on the BL2 check covering it and on no other, so a check that
# stops working is detected and named. Truncated files must never crash.
test_esbc_mutations() {
	local srk_table signature
	srk_table=$(read_le32 kernel.cst "${HDR_SRK_TABLE_OFFSET}")
	signature=$(read_le32 kernel.cst "${HDR_SIGNATURE_OFFSET}")

	esbc_mutant "image byte"              E9  flip_byte  $(( CSF_HDR_SZ + 1234 ))
	esbc_mutant "image address"           E9  flip_byte  "${HDR_IMAGE_ADDRESS}"
	esbc_mutant "signature byte"          E9  flip_byte  $(( signature + 100 ))
	esbc_mutant "modulus byte"            E9  flip_byte  $(( srk_table + SRK_MODULUS + 50 ))
	esbc_mutant "signature = modulus"     E7  modulus_as_signature
	esbc_mutant "no SRK"                  E2  write_u8   "${HDR_NUM_SRK}" 0
	esbc_mutant "9 SRKs"                  E2  write_u8   "${HDR_NUM_SRK}" 9
	esbc_mutant "SRK 0 selected"          E3  write_u8   "${HDR_SRK_SELECT}" 0
	esbc_mutant "SRK 2 of 1 selected"     E3  write_u8   "${HDR_SRK_SELECT}" 2
	esbc_mutant "300 byte key"            E5  write_le32 "${srk_table}" 300
	esbc_mutant "signature length 0x80"   E6  write_le32 "${HDR_SIGNATURE_LENGTH}" 0x80
	esbc_mutant "signature past the end"  E10 write_le32 "${HDR_SIGNATURE_OFFSET}" 0x100000
	esbc_mutant "SRK table past the end"  E10 write_le32 "${HDR_SRK_TABLE_OFFSET}" 0x100000
	esbc_mutant "image past the end"      E10 write_le32 "${HDR_IMAGE_LENGTH}" 0xffffff
	esbc_mutant "barker"                  E1  write_u8   "${HDR_BARKER}" 0x13
	esbc_mutant "IE key extension flag"   E14 write_u8   "${HDR_MISC_FLAGS}" "${MISC_IE}"
	esbc_mutant "modulus top bit clear"   E11 write_u8   $(( srk_table + SRK_MODULUS )) 0x7f
	esbc_mutant "modulus even"            E11 make_even  "$(modulus_last_byte kernel.cst "${srk_table}")"
	expect_truncated_copies_fail kernel.cst esbc --in
}

# RSA-1024 and RSA-4096 change the SRK entry and the signature length: the
# checks must hold for every key size the BootROM accepts, not only 2048.
test_esbc_key_sizes() {
	local bits
	for bits in 1024 4096; do
		sign_esbc "rsa${bits}.cst" "${CSF_HDR_SZ}" PUB_KEY="rsa${bits}.pub" PRI_KEY="rsa${bits}.pri"
		expect_pass "RSA-${bits}" esbc --in "rsa${bits}.cst" --pub "rsa${bits}.pub"
		flip_byte "rsa${bits}.cst" $(( CSF_HDR_SZ + 7 ))
		expect_fail "RSA-${bits}, image byte" E9 esbc --in "rsa${bits}.cst"
	done
}

# Every TA 3.x platform name, including LS2085 with the TA 3.0 layout, must
# select a header layout the verifier parses correctly.
test_esbc_platforms() {
	local platform
	for platform in LS1028 LS1088 LS2085 LS2088; do
		sign_esbc "${platform}.cst" "${CSF_HDR_SZ}" PLATFORM="${platform}"
		expect_pass "--platform ${platform}" esbc --in "${platform}.cst" --platform "${platform}"
	done
}

# With several SRKs the selected key is not the first: the verifier must use
# the selected key, compare the whole table in order with --pub, and apply a
# revocation to the selected key only.
test_esbc_three_srks() {
	sign_esbc three_srks.cst "${CSF_HDR_SZ}" \
		PUB_KEY="${THREE_PUBLIC_KEYS}" PRI_KEY="${THREE_PRIVATE_KEYS}" KEY_SELECT=2
	expect_pass "3 SRKs, key 2" esbc --in three_srks.cst --pub "${THREE_PUBLIC_KEYS}"
	expect_fail "3 SRKs, --pub in another order" E12 esbc --in three_srks.cst --pub srk.pub,rsa1024.pub,rsa4096.pub
	expect_fail "3 SRKs, key 2 revoked" E4 esbc --in three_srks.cst --revoke-mask "$(revocation_mask 2)"
	expect_pass "3 SRKs, keys 1 and 3 revoked" esbc --in three_srks.cst --revoke-mask "$(revocation_mask 1 3)"
}

# The BL2 (Boot1) header the BootROM checks before releasing the cores:
# expected key and SRK hash, revocation, and exactly one image per SG entry.
test_isbc() {
	cp bl2.bin bl2_mutant.bin
	flip_byte bl2_mutant.bin 2000

	expect_pass "BL2 header" isbc --hdr hdr_bl2 --img bl2.bin --pub srk.pub --srk-hash "${SRK_HASH}"
	expect_fail "another --pub" I12 isbc --hdr hdr_bl2 --img bl2.bin --pub other.pub
	expect_fail "another --srk-hash" I5 isbc --hdr hdr_bl2 --img bl2.bin --srk-hash "${OTHER_SRK_HASH}"
	expect_fail "selected key revoked" I11 isbc --hdr hdr_bl2 --img bl2.bin --revoke-mask "$(revocation_mask 1)"
	expect_fail "two images for one SG entry" I10 isbc --hdr hdr_bl2 --img bl2.bin --img bl2.bin
	expect_fail "another image" I10 isbc --hdr hdr_bl2 --img kernel.itb
	expect_fail "image byte" I7 isbc --hdr hdr_bl2 --img bl2_mutant.bin
	expect_usage_error "no --img" isbc --hdr hdr_bl2
}

# One corruption at a time in the fields the BootROM reads in a Boot1
# header, SG table, entry point and B01 flag included. Each must fail on its
# own check only. Truncated headers must never crash.
test_isbc_mutations() {
	local srk_table signature sg_table
	srk_table=$(read_le32 hdr_bl2 "${HDR_SRK_TABLE_OFFSET}")
	signature=$(read_le32 hdr_bl2 "${HDR_SIGNATURE_OFFSET}")
	sg_table=$(read_le32 hdr_bl2 "${HDR_SG_TABLE_OFFSET}")

	isbc_mutant "FSL UID"                 I7    flip_byte  "${HDR_FSL_UID}"
	isbc_mutant "signature byte"          I7    flip_byte  $(( signature + 100 ))
	isbc_mutant "SG entry target"         I7    flip_byte  $(( sg_table + SG_TARGET ))
	isbc_mutant "signature = modulus"     I4    modulus_as_signature
	isbc_mutant "no SRK"                  I2    write_u8   "${HDR_NUM_SRK}" 0
	isbc_mutant "9 SRKs"                  I2    write_u8   "${HDR_NUM_SRK}" 9
	isbc_mutant "SRK 0 selected"          I3    write_u8   "${HDR_SRK_SELECT}" 0
	isbc_mutant "SRK 2 of 1 selected"     I3    write_u8   "${HDR_SRK_SELECT}" 2
	isbc_mutant "300 byte key"            I4    write_le32 "${srk_table}" 300
	isbc_mutant "signature length 0x80"   I4    write_le32 "${HDR_SIGNATURE_LENGTH}" 0x80
	isbc_mutant "signature past the end"  I10   write_le32 "${HDR_SIGNATURE_OFFSET}" 0x100000
	isbc_mutant "SG table past the end"   I6    write_le32 "${HDR_SG_TABLE_OFFSET}" 0x100000
	isbc_mutant "no SG entry"             I6    write_le32 "${HDR_SG_ENTRIES}" 0
	isbc_mutant "9 SG entries"            I6    write_le32 "${HDR_SG_ENTRIES}" 9
	isbc_mutant "B01 flag clear"          I9    write_u8   "${HDR_MISC_FLAGS}" "${MISC_ISS}"
	isbc_mutant "entry point outside BL2" "I7 I8" write_le32 "${HDR_ENTRY_POINT}" 0x19000000
	isbc_mutant "barker"                  I1    write_u8   "${HDR_BARKER}" 0x13
	isbc_mutant "modulus top bit clear"   I13   write_u8   $(( srk_table + SRK_MODULUS )) 0x7f
	isbc_mutant "modulus even"            I13   make_even  "$(modulus_last_byte hdr_bl2 "${srk_table}")"
	expect_truncated_copies_fail hdr_bl2 isbc --img bl2.bin --hdr
}

# A Boot1 header signed with the third SRK of a table: key selection and
# revocation must follow the header, not the table order.
test_isbc_three_srks() {
	sign_bl2 hdr_bl2_three_srks PUB_KEY="${THREE_PUBLIC_KEYS}" PRI_KEY="${THREE_PRIVATE_KEYS}" KEY_SELECT=3
	expect_pass "3 SRKs, key 3" isbc --hdr hdr_bl2_three_srks --img bl2.bin --pub "${THREE_PUBLIC_KEYS}"
	expect_fail "3 SRKs, key 3 revoked" I11 isbc --hdr hdr_bl2_three_srks --img bl2.bin --revoke-mask "$(revocation_mask 3)"
}

# TA 3.0 (LS2085) has a 32 bit entry point and another SG entry layout: a
# parser that assumes TA 3.1 misreads it.
test_isbc_ta_3_0() {
	sign_bl2 hdr_bl2_ls2085 PLATFORM=LS2085
	expect_pass "LS2085 (TA 3.0)" isbc --hdr hdr_bl2_ls2085 --img bl2.bin --ta 3.0
}

# The input files shipped with CST must keep producing headers that verify,
# so a regression in the samples or in the header tools shows up here.
test_cst_sample_inputs() {
	local sample
	for sample in lx2160 ls1028 ls2088_1088; do
		quietly create_hdr_esbc --in kernel.itb --out "${sample}.cst" \
			--app_off "${CSF_HDR_SZ}" --app kernel.itb "${SAMPLES}/${sample}/input_kernel_secure"
		expect_pass "kernel signed with the CST ${sample} sample input" esbc --in "${sample}.cst" --pub srk.pub
	done
	quietly create_hdr_isbc --in u-boot.bin --out uboot.hdr "${SAMPLES}/lx2160/nor/input_uboot_secure"
	expect_pass "U-Boot signed with the CST lx2160 sample input" isbc --hdr uboot.hdr --img u-boot.bin
}

main() {
	use_built_tools
	enter_scratch_directory
	generate_keys
	generate_images
	compute_srk_hashes
	sign_reference_images

	test_esbc
	test_esbc_image_offset
	test_esbc_mutations
	test_esbc_key_sizes
	test_esbc_platforms
	test_esbc_three_srks

	test_isbc
	test_isbc_mutations
	test_isbc_three_srks
	test_isbc_ta_3_0

	test_cst_sample_inputs

	echo "All verification tests passed"
}

main "$@"
