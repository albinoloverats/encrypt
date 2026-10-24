#!/bin/sh
set -eu

tmp=$(mktemp -d "${TMPDIR:-/tmp}/encrypt-cli-test.XXXXXX")
input=$tmp/input
encrypted=$tmp/encrypted
decrypted=$tmp/decrypted
stdout=$tmp/stdout
stderr=$tmp/stderr
trap 'rm -f "$input" "$encrypted" "$decrypted" "$stdout" "$stderr"; rmdir "$tmp"' EXIT HUP INT TERM

dd if=/dev/zero of="$input" bs=4096 count=8 2>/dev/null
./encrypt -c AES -s SHA256 -m CBC -a HMAC_SHA256 -i 10 -p test-password "$input" "$encrypted"

size=$(wc -c < "$encrypted")
truncate -s "$((size - 16))" "$encrypted"

if ./decrypt -p test-password "$encrypted" "$decrypted" >"$stdout" 2>"$stderr"; then
	echo "decryption unexpectedly accepted a damaged compressed stream" >&2
	exit 1
fi

grep -Eq 'Failed: (LZMA decompression error|Read/Write error)!' "$stderr"
