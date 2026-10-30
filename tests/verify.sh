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
readonly FLASH_BASE=0x20000000
readonly BL2_HDR_SRC_OFFSET=0x5000
readonly BL2_SRC_OFFSET=0x9000
readonly BL2_HDR_LOC=0x1800a000
readonly BL2_BASE=0x1800d000
readonly UNALIGNED_BL2_SIZE=50001

readonly CSF_HEADER_SIZE=0x50
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
readonly MISC_B01=0x40

readonly RCW_WORDS=35
readonly RCW_PREAMBLE=0xaa55aa55
readonly RCW_LOAD_WITH_CHECKSUM=0x80100000
readonly RCW_PBI_LENGTH=$((10 * 4))
readonly RCW_PBI_LENGTH_SHIFT=20
readonly RCW_SB_EN=0x400
readonly PBI_START=$((RCW_WORDS * 4))
readonly PBI_HEADER=$((PBI_START + 4))
readonly PBI_COMMANDS=$((PBI_HEADER + CSF_HEADER_SIZE))
readonly PBI_WRITE_SCRATCHRW1=0x31e00200
readonly PBI_BLOCK_COPY_FLEXSPI_NOR=0x8000000f
readonly PBI_LOAD_CSF_POINTER=0x80220000
readonly PBI_STOP=0x80ff0000
readonly PBI_CRC_STOP=0x808f0000
readonly PBI_BLOCK_COPY_MEMORY=0x80000000
readonly PBI_ALTCFG_WRITE_8_BYTES=0x90000000
readonly PBI_UNDEFINED_COMMAND=0x80300000
readonly PBI_WRITE_1_BYTE_DUART=0x121c0500
readonly PBI_WRITE_2_BYTES=0x21e00200
readonly PBI_POLL_SHORT=0x80800000
readonly PBI_POLL_LONG=0x80810000
readonly PBI_WAIT_100=0x80820064
readonly PBI_LOAD_AC_WINDOW_7=0x80120007
readonly PBI_CCSR_COPY_4_BYTES=0x80020003
readonly PBI_CCSR_REPLACE_4_BYTES=0x8042000b
readonly PBI_LOAD_CONDITION=0x80140000
readonly PBI_JUMP=0x80840000
readonly PBI_JUMP_CONDITIONAL=0x80850000
readonly PBI_JUMP_SIZE=8
readonly PBI_JUMP_CONDITIONAL_SIZE=12
readonly PBI_BLOCK_COPY_SIZE=16

readonly SERDES1_PCC8=0x01ea10a0
readonly SERDES1_PCCC=0x01ea10b0
readonly DCFG_SCRATCHRW1=0x01e00200
readonly DCFG_SCRATCHRW5=0x01e00210
readonly DCFG_SCRATCHRW6=0x01e00214
readonly -a A050426_COPIES=(
	--memory-copy "${SERDES1_PCC8}" "${DCFG_SCRATCHRW5}" 4
	--memory-copy "${SERDES1_PCCC}" "${DCFG_SCRATCHRW6}" 0xc
)

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
readonly -a INPUT_PBI_CH3_2=(
	PLATFORM=LX2160
	PUB_KEY=srk.pub
	PRI_KEY=srk.pri
	KEY_SELECT=1
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

words() {
	local word
	for word in "$@"; do
		le32 "${word}"
	done
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

early_stop_without_terminator() {
	local file=$1 stop=$2
	write_le32 "${file}" $(( stop - 16 )) "${PBI_STOP}"
	write_le32 "${file}" "${stop}" "${PBI_WRITE_SCRATCHRW1}"
}

modulus_as_signature() {
	local file=$1 modulus signature length
	modulus=$(( $(read_le32 "${file}" "${HDR_SRK_TABLE_OFFSET}") + SRK_MODULUS ))
	signature=$(read_le32 "${file}" "${HDR_SIGNATURE_OFFSET}")
	length=$(read_le32 "${file}" "${HDR_SIGNATURE_LENGTH}")
	copy_bytes "${file}" "${modulus}" "${signature}" "${length}"
}

pbi_end() {
	local pbi_length
	pbi_length=$(( $(read_le32 "$1" "${RCW_PBI_LENGTH}") >> RCW_PBI_LENGTH_SHIFT ))
	echo $(( (RCW_WORDS + pbi_length) * 4 ))
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

block_copy() {
	local file=$1 pbl_offset=$2 destination=$3 size
	size=$(file_size "${file}")
	words "${PBI_BLOCK_COPY_FLEXSPI_NOR}" $(( FLASH_BASE + pbl_offset )) \
		"${destination}" $(( size + size % 4 ))
}

pbi_commands() {
	local copy_bl2=$1 jump_bl2=$2 csf_pointer=$3 bl2_header=$4 stop=$5
	shift 5
	words "${PBI_WRITE_SCRATCHRW1}" 0x12345678
	if [[ ${jump_bl2} == yes ]]; then
		words "${PBI_JUMP}" $(( PBI_JUMP_SIZE + PBI_BLOCK_COPY_SIZE ))
	fi
	if [[ ${copy_bl2} == yes ]]; then
		block_copy bl2.bin "${BL2_SRC_OFFSET}" "${BL2_BASE}"
	fi
	words "${PBI_LOAD_CSF_POINTER}" "${csf_pointer}"
	block_copy "${bl2_header}" "${BL2_HDR_SRC_OFFSET}" "${BL2_HDR_LOC}"
	words "$@"
	words "${stop}" 0
}

rcw_with_pbi() {
	local pbi=$1 sb_en=$2 pbi_words index checksum=0
	local -a rcw=()
	pbi_words=$(( $(file_size "${pbi}") / 4 ))
	for (( index = 0; index < RCW_WORDS; index++ )); do
		rcw[index]=0
	done
	rcw[0]=${RCW_PREAMBLE}
	rcw[1]=${RCW_LOAD_WITH_CHECKSUM}
	rcw[RCW_PBI_LENGTH/4]=$(( (pbi_words << RCW_PBI_LENGTH_SHIFT) | (sb_en ? RCW_SB_EN : 0) ))
	for (( index = 0; index < RCW_WORDS - 1; index++ )); do
		checksum=$(( (checksum + rcw[index]) & 0xffffffff ))
	done
	rcw[RCW_WORDS-1]=${checksum}
	words "${rcw[@]}"
	cat "${pbi}"
}

make_pbl() {
	local output=$1 platform=LX2160 bl2_header=hdr_bl2 csf_pointer=${BL2_HDR_LOC}
	local stop=${PBI_STOP} sb_en=1 copy_bl2=yes jump_bl2=no signed=yes bl2_offset=${BL2_SRC_OFFSET}
	local -a extra_words=() more=()
	shift
	while (( $# > 0 )); do
		case $1 in
		--platform) platform=$2; shift ;;
		--bl2-header) bl2_header=$2; shift ;;
		--csf-pointer) csf_pointer=$2; shift ;;
		--place-bl2-at) bl2_offset=$2; shift ;;
		--memory-copy) extra_words+=("${PBI_BLOCK_COPY_MEMORY}" "$2" "$3" "$4"); shift 3 ;;
		--pbi-words) read -ra more <<< "$2"; extra_words+=("${more[@]}"); shift ;;
		--crc) stop=${PBI_CRC_STOP} ;;
		--no-sb-en) sb_en=0 ;;
		--xip) copy_bl2=no ;;
		--jump-over-bl2) jump_bl2=yes ;;
		--unsigned) signed=no ;;
		*) fail "make_pbl: unknown option $1" ;;
		esac
		shift
	done

	pbi_commands "${copy_bl2}" "${jump_bl2}" "${csf_pointer}" "${bl2_header}" "${stop}" \
		"${extra_words[@]}" > pbi.bin
	rcw_with_pbi pbi.bin "${sb_en}" > rcw.bin
	if [[ ${signed} == yes ]]; then
		write_input pbi_input.txt "${INPUT_PBI_CH3_2[@]}" PLATFORM="${platform}"
		quietly create_hdr_pbi --in rcw.bin --out "${output}" pbi_input.txt
	else
		cp rcw.bin "${output}"
	fi
	write_at "${output}" "${BL2_HDR_SRC_OFFSET}" < "${bl2_header}"
	write_at "${output}" "${bl2_offset}" < bl2.bin
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

expect_pbl_pass() {
	local description=$1 pbl=$2
	shift 2
	expect_pass "${description}" pbl --pbl "${pbl}" --flash-base "${FLASH_BASE}" "$@"
}

expect_pbl_fail() {
	local description=$1 failing=$2 pbl=$3
	shift 3
	expect_fail "${description}" "${failing}" pbl --pbl "${pbl}" --flash-base "${FLASH_BASE}" "$@"
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

pbi_mutant() {
	local description=$1 failing=$2 edit=$3
	shift 3
	cp reference.pbl mutant.pbl
	"${edit}" mutant.pbl "$@"
	expect_fail "${description}" "${failing}" pbi --pbl mutant.pbl
}

crc_pbi_mutant() {
	local description=$1 failing=$2 edit=$3
	shift 3
	cp crc.pbl mutant.pbl
	"${edit}" mutant.pbl "$@"
	expect_fail "${description}" "${failing}" pbi --pbl mutant.pbl
}

use_built_tools() {
	local tool
	if [[ ! -x ${TOP}/cst_verify ]]; then
		echo "SKIP: ${TOP}/cst_verify is not built, libqoriq-rcw was not found at build time"
		exit 0
	fi
	for tool in create_hdr_esbc create_hdr_isbc create_hdr_pbi gen_keys; do
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
	make_pbl reference.pbl
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

# A PBL laid out like the TF-A pbl target for LX2160A FlexSPI NOR: the
# signed PBI, its block copies, and the BL2 header and image they place in
# OCRAM must agree. Wrong expected keys and a wrong flash base must fail.
test_pbl() {
	expect_pbl_pass "TF-A FlexSPI NOR layout" reference.pbl --pub srk.pub --srk-hash "${SRK_HASH}"
	expect_pbl_pass "without the boot device window" reference.pbl --xip-window 0:0
	expect_pbl_fail "another --pub" "I12 P8" reference.pbl --pub other.pub
	expect_pbl_fail "another --srk-hash" "I5 P7" reference.pbl --srk-hash "${OTHER_SRK_HASH}"
	expect_fail "wrong flash base" X2 pbl --pbl reference.pbl --flash-base 0x30000000
	expect_usage_error "no --flash-base" pbl --pbl reference.pbl
	expect_pass "TF-A FlexSPI NOR layout" pbi --pbl reference.pbl --pub srk.pub --srk-hash "${SRK_HASH}"
}

# Defects that leave every signature valid but keep BL2 from running: no BL2
# block copy (a TF-A BL2_IN_XIP_MEM build), a CSF pointer to unwritten
# memory, a misplaced bl2.bin, an entry point outside BL2, and two headers
# with different SRK tables. Without a board, only this detects them.
test_pbl_defects() {
	make_pbl xip.pbl --xip
	expect_pbl_fail "no BL2 block copy (BL2_IN_XIP_MEM)" "X5 X6" xip.pbl

	make_pbl unwritten_header.pbl --csf-pointer 0x1800c000
	expect_pbl_fail "CSF header pointer to unwritten memory" X3 unwritten_header.pbl

	make_pbl shifted_bl2.pbl --place-bl2-at $(( BL2_SRC_OFFSET + 1 ))
	expect_pbl_fail "bl2.bin one byte after its copy source" "I7 X4" shifted_bl2.pbl

	sign_bl2 hdr_bl2_entry_outside ENTRY_POINT=19000000
	make_pbl entry_outside.pbl --bl2-header hdr_bl2_entry_outside
	expect_pbl_fail "entry point outside BL2" "I8 X4 X6" entry_outside.pbl

	sign_bl2 hdr_bl2_three_srks PUB_KEY="${THREE_PUBLIC_KEYS}" PRI_KEY="${THREE_PRIVATE_KEYS}" KEY_SELECT=3
	make_pbl different_srk_tables.pbl --bl2-header hdr_bl2_three_srks
	expect_pbl_fail "PBI and Boot1 headers with different SRK tables" X7 different_srk_tables.pbl
}

# Valid variants must not be rejected: SB_EN clear, when secure boot comes
# from the ITS fuse, and the LS1028 and LS2088 platform names.
test_pbl_variants() {
	local platform
	make_pbl no_sb_en.pbl --no-sb-en
	expect_pbl_pass "SB_EN clear, reported only" no_sb_en.pbl
	for platform in LS1028 LS2088; do
		make_pbl "${platform}.pbl" --platform "${platform}"
		expect_pbl_pass "${platform} PBI header" "${platform}.pbl"
	done
}

# Block copies of source type 0 read memory, not the boot device: the
# A-050426 workaround in NXP's LX2160A RCWs copies SerDes registers to DCFG
# scratch registers. They must not hide the PBL checks, and a region they
# overwrite cannot be trusted.
test_pbl_memory_copies() {
	make_pbl a050426.pbl "${A050426_COPIES[@]}"
	expect_pbl_pass "A-050426 copies from SerDes registers" a050426.pbl

	make_pbl xip_a050426.pbl --xip "${A050426_COPIES[@]}"
	expect_pbl_fail "no BL2 block copy, with the A-050426 copies" "X5 X6" xip_a050426.pbl

	make_pbl header_overwritten.pbl --memory-copy "${SERDES1_PCC8}" "${BL2_HDR_LOC}" 4
	expect_pbl_fail "memory copy over the Boot1 header" X3 header_overwritten.pbl
}

# Commands the Service Processor accepts and NXP's tools seldom emit: poll,
# wait, an AltConfig write, a CCSR copy, a read-modify-write and a condition
# load. None writes OCRAM, so the PBL still passes. A 2-byte CCSR write is
# reserved by the RM and must be rejected, as the BootROM does.
test_pbl_pbi_commands() {
	make_pbl commands.pbl \
		--pbi-words "${PBI_POLL_SHORT} ${DCFG_SCRATCHRW1} 0xffffffff 0x12345678" \
		--pbi-words "${PBI_POLL_LONG} ${DCFG_SCRATCHRW1} 0xffffffff 0x12345678" \
		--pbi-words "${PBI_WAIT_100}" \
		--pbi-words "${PBI_LOAD_AC_WINDOW_7} ${PBI_ALTCFG_WRITE_8_BYTES} 0x11111111 0x22222222" \
		--pbi-words "${PBI_CCSR_COPY_4_BYTES} ${BL2_BASE} ${DCFG_SCRATCHRW5} 1" \
		--pbi-words "${PBI_CCSR_REPLACE_4_BYTES} ${DCFG_SCRATCHRW5} 0xff 0x12" \
		--pbi-words "${PBI_LOAD_CONDITION} ${DCFG_SCRATCHRW1} 0xff" \
		--pbi-words "${PBI_WRITE_1_BYTE_DUART} 0x49"
	expect_pbl_pass "poll, wait, AltConfig write, CCSR copy, read-modify-write, load condition" commands.pbl

	make_pbl two_byte_write.pbl --pbi-words "${PBI_WRITE_2_BYTES} 0x1"
	expect_fail "2-byte CCSR write, reserved byte count" P6 pbi --pbl two_byte_write.pbl
}

# A jump changes what the Service Processor executes, so the walk follows
# it: one over the BL2 block copy leaves BL2 unwritten. A jump landing on a
# word that is not a command, one below the RM minimum, and a conditional
# jump before any load condition fail as the BootROM fails them; a
# conditional jump after one leaves the path to the hardware and must fail
# the memory model rather than be guessed.
test_pbl_jumps() {
	make_pbl jump.pbl --pbi-words "${PBI_JUMP} $(( PBI_JUMP_SIZE + 8 )) ${PBI_WRITE_SCRATCHRW1} 0xdeadbeef"
	expect_pbl_pass "jump over a CCSR write" jump.pbl

	make_pbl jump_over_bl2.pbl --jump-over-bl2
	expect_pbl_fail "jump over the BL2 block copy" "X5 X6" jump_over_bl2.pbl

	make_pbl jump_inside.pbl --pbi-words "${PBI_JUMP} $(( PBI_JUMP_SIZE + 4 )) ${PBI_WRITE_SCRATCHRW1} 0xdeadbeef"
	expect_pbl_fail "jump inside a command" "P6 X1" jump_inside.pbl

	make_pbl jump_short.pbl --pbi-words "${PBI_JUMP} ${PBI_JUMP_SIZE} ${PBI_WRITE_SCRATCHRW1} 0xdeadbeef"
	expect_pbl_fail "jump of 8 bytes, below the RM minimum" "P6 X1" jump_short.pbl

	make_pbl jumpc_no_loadc.pbl --pbi-words "${PBI_JUMP_CONDITIONAL} $(( PBI_JUMP_CONDITIONAL_SIZE + 8 )) 0x1 ${PBI_WRITE_SCRATCHRW1} 0xdeadbeef"
	expect_pbl_fail "conditional jump before any load condition" "P6 X1" jumpc_no_loadc.pbl

	make_pbl jumpif.pbl --pbi-words "${PBI_LOAD_CONDITION} ${DCFG_SCRATCHRW1} 0xff" \
		--pbi-words "${PBI_JUMP_CONDITIONAL} $(( PBI_JUMP_CONDITIONAL_SIZE + 8 )) 0x1 ${PBI_WRITE_SCRATCHRW1} 0xdeadbeef"
	expect_pbl_fail "conditional jump, not simulated" X2 jumpif.pbl
}

# RM 8.2.6: a stop may end execution before the PBI length, leaving room for
# commands added during development; the BootROM requires a stop at the PBI
# length and never reads what lies between. The verifier must accept it, with
# the signature over the whole PBI, and must not decode the buffer.
test_pbl_development_buffer() {
	make_pbl buffer.pbl --pbi-words "${PBI_STOP} 0 0xdeadbeef 0xdeadbeef ${PBI_WRITE_SCRATCHRW1} 0x1"
	expect_pbl_pass "early stop, development buffer with words that are not commands" buffer.pbl
}

# One corruption at a time in the RCW, the PBI commands and the PBI security
# header. Each must fail on the one check that covers it, so a check that
# stops working is detected and named.
test_pbi_mutations() {
	local srk_table signature stop
	srk_table=$(( PBI_HEADER + $(read_le32 reference.pbl $(( PBI_HEADER + HDR_SRK_TABLE_OFFSET ))) ))
	signature=$(( PBI_HEADER + $(read_le32 reference.pbl $(( PBI_HEADER + HDR_SIGNATURE_OFFSET ))) ))
	stop=$(( $(pbi_end reference.pbl) - 8 ))

	pbi_mutant "PBI command argument"            P3  flip_byte  $(( PBI_COMMANDS + 4 ))
	pbi_mutant "signature byte"                  P3  flip_byte  $(( signature + 100 ))
	pbi_mutant "modulus byte"                    P3  flip_byte  $(( srk_table + SRK_MODULUS + 50 ))
	pbi_mutant "RCW word with a stale checksum"  P1  flip_byte  "${RCW_PBI_LENGTH}"
	pbi_mutant "preamble"                        P1  write_le32 0 0x55aa55ab
	pbi_mutant "PBI length past the end"         P1  write_le32 "${RCW_PBI_LENGTH}" $(( (0x800 << RCW_PBI_LENGTH_SHIFT) | RCW_SB_EN ))
	pbi_mutant "unknown command"                 P6  write_le32 "${stop}" "${PBI_UNDEFINED_COMMAND}"
	pbi_mutant "command past the PBI length"     P6  write_le32 "${stop}" "${PBI_ALTCFG_WRITE_8_BYTES}"
	pbi_mutant "no stop at the PBI length"           P5  write_le32 "${stop}" "${PBI_WRITE_SCRATCHRW1}"
	pbi_mutant "early stop, no stop at the PBI length" P5 early_stop_without_terminator "${stop}"
	pbi_mutant "early stop, the rest not executed"   P3  write_le32 $(( stop - 16 )) "${PBI_STOP}"
	pbi_mutant "B01 flag set"                    P2  write_u8   $(( PBI_HEADER + HDR_MISC_FLAGS )) $(( MISC_ISS | MISC_B01 ))
	pbi_mutant "no SRK"                          P2  write_u8   $(( PBI_HEADER + HDR_NUM_SRK )) 0
	pbi_mutant "300 byte key"                    P9  write_le32 "${srk_table}" 300
	pbi_mutant "modulus top bit clear"           P9  write_u8   $(( srk_table + SRK_MODULUS )) 0x7f
	pbi_mutant "modulus even"                    P9  make_even  "$(modulus_last_byte reference.pbl "${srk_table}")"
	pbi_mutant "signature length 0x80"           P9  write_le32 $(( PBI_HEADER + HDR_SIGNATURE_LENGTH )) 0x80
	pbi_mutant "signature past the end"          P11 write_le32 $(( PBI_HEADER + HDR_SIGNATURE_OFFSET )) 0x100000
	pbi_mutant "SRK table among the PBI words"   P11 write_le32 $(( PBI_HEADER + HDR_SRK_TABLE_OFFSET )) 0x40
}

# With the CRC and stop command, a changed PBI word breaks the CRC as well
# as the signature: it must be reported as a CRC failure, as must a wrong CRC.
test_pbi_crc() {
	make_pbl crc.pbl --crc
	expect_pbl_pass "CRC and stop command" crc.pbl
	crc_pbi_mutant "PBI command argument, CRC present" P4 flip_byte $(( PBI_COMMANDS + 4 ))
	crc_pbi_mutant "CRC word"                          P4 flip_byte $(( $(pbi_end crc.pbl) - 4 ))
}

# A PBL that never went through create_hdr_pbi, a packaging mistake, must
# be rejected rather than silently skipped.
test_unsigned_pbl() {
	make_pbl unsigned.pbl --unsigned
	expect_fail "no load security header" P2 pbi --pbl unsigned.pbl
	expect_pbl_fail "no load security header" "P2 X1" unsigned.pbl
}

# A partial flash write or download truncates the PBL: every truncated copy
# must fail, without crashing the verifier.
test_truncated_pbl() {
	expect_truncated_copies_fail reference.pbl pbl --flash-base "${FLASH_BASE}" --pbl
}

# The PBI check must accept a file ending right after the PBI signature and
# reject anything shorter, which bounds what the pbi mode reads.
test_pbi_needs_only_the_signed_pbi() {
	head -c "$(signature_end reference.pbl "${PBI_HEADER}")" reference.pbl > signed_pbi.pbl
	expect_pass "PBL cut after the PBI signature" pbi --pbl signed_pbi.pbl
	expect_truncated_copies_fail signed_pbi.pbl pbi --pbl
}

# dump decodes without a verdict; its memory map must show the Boot1 CSF
# header pointer, the first thing to look at when a PBL does not boot.
test_dump() {
	run_cst_verify dump pbl --pbl reference.pbl --flash-base "${FLASH_BASE}"
	if (( STATUS != 0 )) || [[ ${OUTPUT} != *"Boot1 CSF header pointer ${BL2_HDR_LOC}"* ]]; then
		fail "dump pbl: exit status ${STATUS}, expected 0 and the Boot1 CSF header pointer" "${OUTPUT}"
	fi
	pass "dump pbl: memory map with the Boot1 CSF header pointer"
}

# CI jobs parse the --json report: it must be identical across runs for the
# same input and carry the verdict.
test_json_report() {
	local first_report
	run_cst_verify pbl --pbl reference.pbl --flash-base "${FLASH_BASE}" --json
	first_report=${OUTPUT}
	run_cst_verify pbl --pbl reference.pbl --flash-base "${FLASH_BASE}" --json
	if [[ ${OUTPUT} != "${first_report}" ]]; then
		fail "pbl --json: the report differs between two runs" "${first_report}" "${OUTPUT}"
	fi
	if (( STATUS != 0 )) || [[ ${OUTPUT} != *'"verdict": "PASS"'* ]]; then
		fail "pbl --json: exit status ${STATUS}, expected 0 and a PASS verdict" "${OUTPUT}"
	fi
	pass "pbl --json: deterministic report with a PASS verdict"
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

	test_pbl
	test_pbl_defects
	test_pbl_variants
	test_pbl_memory_copies
	test_pbl_pbi_commands
	test_pbl_jumps
	test_pbl_development_buffer
	test_pbi_mutations
	test_pbi_crc
	test_unsigned_pbl
	test_truncated_pbl
	test_pbi_needs_only_the_signed_pbi
	test_dump
	test_json_report

	echo "All verification tests passed"
}

main "$@"
