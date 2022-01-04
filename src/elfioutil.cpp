//
// Created by dev on 1/4/22.
//

#include "elfioutil.h"
using namespace std;
using namespace ELFIO;

void read_section_data_to_buffer(ELFIO::elfio& r, char** data,
                                 unsigned int sec_num, Elf_Xword sec_sz){

    *data = (char*) calloc(sec_sz, 1);
    if (*data == nullptr) {
        cerr << "calloc() failed" << endl;
        exit(AFAULT);
    }
    section * cur_sec = r.sections[sec_num];
    // Only assuming data begins at section boundary, without offset
    if (cur_sec->get_type() == SHT_PROGBITS){
        *data = (char*) r.sections[sec_num]->get_data();
    }
}

bool find_section_by_name(ELFIO::elfio& r, const char * sec_name, unsigned int* sec_num, unsigned long* sec_size){
    int sec_name_found = FALSE;
    Elf_Half sec_num_total = r.sections.size();

    for (int i = 0; i < sec_num_total; i++) {
        const section* psec = r.sections[i];
        if (strncmp(psec->get_name().c_str(), sec_name, strlen(sec_name) ) == 0 ) {
            *sec_size = psec->get_size();
            *sec_num = i;
            sec_name_found = TRUE;
        }
    }

    return sec_name_found;
}
