#!/bin/bash

BUILD_TARGET="Debug"
ELFPACK="./bin/${BUILD_TARGET}/elfpack"
ELFLDR="./bin/${BUILD_TARGET}/elfldr"

HOST_ELF_FILE=${ELFLDR}
DST_ELF_FILE="/tmp/lspay"
PAYLOAD_FILE="/tmp/shell.elf"

DST_ELF_SECTION=".note.gnu.buf[...]"
DST_ELF_META_SECTION=".note.gnu.buf"
DST_ELF_META_ALGO="X"
DST_DESC_NAME=".rodata"
XOR_KEY=""


if [[ $# -eq 0 ]]
then
  echo "Need key"
  exit 1
fi

XOR_KEY=$1
PAY_OPTS=("$@")
PAY_OPTS=("${PAY_OPTS[@]:1}") # removes the first element


if [[ -f  $DST_ELF_FILE ]]
then
  /bin/rm $DST_ELF_FILE
fi

#cmake --build /home/dev/Code/elfpack/cmake-build-debug --target clean
#cmake --build /home/dev/Code/elfpack/cmake-build-debug --target all

echo Packing with $ELFPACK : host file ${HOST_ELF_FILE} with ${PAYLOAD_FILE} into ${DST_ELF_FILE} within section "${DST_ELF_SECTION}" as record  ${DST_DESC_NAME}, algo ${DST_ELF_META_ALGO} with key: "${XOR_KEY}"

$ELFPACK ${HOST_ELF_FILE} ${PAYLOAD_FILE} ${DST_ELF_FILE} "${DST_ELF_SECTION}" ${DST_DESC_NAME} ${DST_ELF_META_ALGO} "${XOR_KEY}"

chmod +rx $DST_ELF_FILE && $DST_ELF_FILE  "${PAY_OPTS[@]}"



