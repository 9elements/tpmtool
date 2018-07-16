#!/bin/bash
UPX=$(which upx)

set -e

for file in dist/*/tpmtool
do
	$UPX --best --ultra-brute "$file"
done
