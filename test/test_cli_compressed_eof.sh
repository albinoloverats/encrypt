#!/bin/sh
set -eu

tmp=$(mktemp -d "${TMPDIR:-/tmp}/encrypt-cli-test.XXXXXX")
HOME=$tmp
export HOME
input=$tmp/input
encrypted=$tmp/encrypted
decrypted=$tmp/decrypted
stdout=$tmp/stdout
stderr=$tmp/stderr
trap 'rm -f "$input" "$encrypted" "$decrypted" "$stdout" "$stderr"; rmdir "$tmp"' EXIT HUP INT TERM

dd if=/dev/urandom of="$input" bs=4096 count=8 2>/dev/null
./encrypt -c AES -s SHA256 -m CBC -a HMAC_SHA256 -i 10 -p test-password "$input" "$encrypted"

size=$(wc -c < "$encrypted")
test "$size" -gt 4096

if ./decrypt -p test-password "$encrypted" "$decrypted" -r >"$stdout" 2>"$stderr"; then
	echo "raw decryption unexpectedly accepted missing algorithms" >&2
	exit 1
fi

grep -q 'Raw decryption requires cipher, hash, mode, and MAC options' "$stderr"

truncate -s "$((size / 2))" "$encrypted"

if ./decrypt -p test-password "$encrypted" "$decrypted" >"$stdout" 2>"$stderr"; then
	echo "decryption unexpectedly accepted a damaged compressed stream" >&2
	exit 1
fi

grep -Eq 'Failed: (LZMA decompression error|Read/Write error)!' "$stderr"
