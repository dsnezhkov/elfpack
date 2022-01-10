//
// Created by dev on 1/3/22.
//

#ifndef ELFLDR_H
#define ELFLDR_H

#include <iostream>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <cstdlib>
#include <cerrno>
#include <climits>
#include <filesystem>

//Vendor
#include "elfioutil.h"
extern "C" {
    #include "libreflect/reflect.h"
    #include "lsecutil/lsecutil.h"
}

std::filesystem::path get_executable_path();
bool find_section_by_name(ELFIO::elfio& r, const char * sec_name, unsigned int* sec_num, unsigned long* sec_size);
void read_section_data_to_buffer(ELFIO::elfio& r, char** data, unsigned int sec_num, ELFIO::Elf_Xword sec_sz);
unsigned int get_section_entries_n(ELFIO::elfio& r, unsigned int sec_num);
bool get_ksection_data(ELFIO::elfio& r, unsigned int ksec_num,
                       void ** key_data, ELFIO::Elf_Word * key_data_sz,
                       void ** algo_data, ELFIO::Elf_Word * algo_data_sz);
bool get_psection_data(ELFIO::elfio& r, unsigned int psec_num,
                       void ** p_data, ELFIO::Elf_Word * p_data_sz);

#ifndef PSEC_NAME
#define PSEC_NAME ".note.gnu.buf[...]"
#define PSEC_NENTRY 1
#endif

#ifndef KSEC_NAME
#define KSEC_NAME ".note.gnu.buf"
#define KSEC_NENTRY 2
#endif
#endif //ELFLDR_H

