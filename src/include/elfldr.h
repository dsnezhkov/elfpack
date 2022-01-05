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
    #include "lsecutil/lsecutil.h"
}

std::filesystem::path get_executable_path();
bool find_section_by_name(ELFIO::elfio& r, const char * sec_name, unsigned int* sec_num, unsigned long* sec_size);
void read_section_data_to_buffer(ELFIO::elfio& r, char** data, unsigned int sec_num, ELFIO::Elf_Xword sec_sz);
#endif //ELFLDR_H

