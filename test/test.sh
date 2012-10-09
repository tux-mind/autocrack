#!/bin/sh

if test "x$(pwd)" != "xtest" ;then cd test; fi
../autocrack -i hash.md5.in -w uword
for f in *.dump; do CAPS="$CAPS -c $f"; done
../autocrack -w uword $CAPS
