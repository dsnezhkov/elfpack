//
// Created by dev on 1/3/22.
//

#ifndef ELFPACK_H
#define ELFPACK_H

#include <iostream>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>

//Vendor
#include <cxxopts/cxxopts.hpp>
#include <elfio/elfio.hpp>
#include "elfioutil.h"

extern "C" {
    #include "lsecutil/lsecutil.h"
}

bool find_section_by_name(ELFIO::elfio& r, const char * sec_name, unsigned int* sec_num, unsigned long* sec_size);
void read_section_data_to_buffer(ELFIO::elfio& r, char** data, unsigned int sec_num, ELFIO::Elf_Xword sec_sz);
size_t write_buffer_to_file(char* dst_file_name, char ** data, ELFIO::Elf_Xword sz);

#endif //ELFPACK_H

