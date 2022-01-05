#!/bin/bash

BUILD_TARGET="Debug"
ELFPACK="./bin/${BUILD_TARGET}/elfpack"
ELFLDR="./bin/${BUILD_TARGET}/elfldr"
#HOST_ELF_FILE="/usr/bin/ls"
HOST_ELF_FILE=${ELFLDR}
DST_ELF_FILE="/tmp/lspay"
PAYLOAD_FILE="/usr/bin/ls"
DST_ELF_SECTION=".note.gnu.buf[...]"
DST_DESC_NAME=".rodata"
XOR_KEY=""


if [[ $# -eq 1 ]]
then
  echo "XKEY: ${1}"
  XOR_KEY=${1}
fi

if [[ -f  $DST_ELF_FILE  ]]
then
  /bin/rm $DST_ELF_FILE
fi

cmake --build /home/dev/Code/elfpack/cmake-build-debug --target clean
cmake --build /home/dev/Code/elfpack/cmake-build-debug --target all

echo $ELFPACK ${HOST_ELF_FILE} ${PAYLOAD_FILE} ${DST_ELF_FILE} "${DST_ELF_SECTION}" ${DST_DESC_NAME} "${XOR_KEY}"
$ELFPACK ${HOST_ELF_FILE} ${PAYLOAD_FILE} ${DST_ELF_FILE} "${DST_ELF_SECTION}" ${DST_DESC_NAME} "${XOR_KEY}"


