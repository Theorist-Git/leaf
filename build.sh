#!/usr/bin/sh

set -xe

nasm -f elf64 leaf.asm -o leaf.o
ld  leaf.o -o leaf
rm leaf.o
./leaf