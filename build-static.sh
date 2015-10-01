#!/bin/sh

gcc -static -o evmctl.static -include config.h src/evmctl.c src/libimaevm.c -lcrypto -lkeyutils -ldl

