#include <elfldr.h>

using namespace std;
using namespace ELFIO;

int main(int argc, char **argv) {

    char *psec_name = (char*) PSEC_NAME;
    char *ksec_name = (char*) KSEC_NAME;
    unsigned int psec_num=0, ksec_num=0;
    unsigned long psec_size=0, ksec_size=0;

    void* key_data = nullptr;
    void* algo_data = nullptr;
    void *p_data = nullptr;
    Elf_Word key_data_sz, algo_data_sz, p_data_sz;

    elfio reader;

    // What is the path of this exe running
    filesystem::path my_path = get_executable_path();

    // Load host ELF data
    if (!reader.load(my_path)) {
        cerr << "Can't find or process src ELF file: " << argv[0] << endl;
        exit(AFAULT);
    }
    // Get Key and Algo information
    if (find_section_by_name(reader, ksec_name, &ksec_num, &ksec_size) == TRUE) {
        cout << "Found section " << ksec_name << " at position " << ksec_num << " of size: " << ksec_size << endl;
        if (get_ksection_data(reader, ksec_num, &key_data, &key_data_sz, &algo_data, &algo_data_sz) == TRUE) {
            //uxor_buffer(reinterpret_cast<unsigned char **>(&desc), (unsigned long) descsz, xor_key );
            //dump_buffer(desc, descsz, (char *) "/tmp/lspay.dmp");
            //reflect_execves((const unsigned char*) desc, argv + 1, nullptr, (size_t *) argv - 1);
            //reflect_execv( (unsigned char const  *) desc, argv);
            cout << "Key: " << ((unsigned long*) key_data)[0]  << "(" << key_data_sz << ")" << endl;
            cout << "Algo: " << (unsigned char*) algo_data  << "(" << algo_data_sz << ")" << endl;

            if (find_section_by_name(reader, psec_name, &psec_num, &psec_size) == TRUE) {
                cout << "Found section " << psec_name << " at position " << psec_num << " of size: " << psec_size << endl;
                if (get_psection_data(reader, psec_num, &p_data, &p_data_sz) == TRUE) {
                    cout << "Dumping p_data: " <<  endl;
                    if (strcmp((char*) algo_data, "X") == 0)
                    {
                        // XOR method
                        uxor_buffer((unsigned char **)(&p_data), (unsigned long) p_data_sz,
                                    ((unsigned long* ) key_data)[0] );
                        dump_buffer(p_data, p_data_sz, (char *) "/tmp/lspay.dmp");
                    }
                    else if (strcmp((char *)algo_data, "A") == 0)
                    {
                        // AES ...
                        ;
                    }
                    else /* default: */
                    {
                        err(EXIT_FAILURE, "%s not in algo choices <X|A>", (char*) algo_data);
                    }
                }else{
                    err(EXIT_FAILURE, "Data context cannot be retrieved for psec_num %d ",  psec_num);
                }
            }else{
                // Section not properly setup, TBD
                err(EXIT_FAILURE, "%s not found, last seen sec num: %d", ksec_name, ksec_num);
            }

        }else{
            err(EXIT_FAILURE, "Key context cannot be retrieved for ksec_num %d ",  ksec_num);
        }

    }else{
        // Section not properly setup, TBD
        err(EXIT_FAILURE, "%s not found, last seen sec num: %d", ksec_name, ksec_num);
    }

    return 0;
}

bool get_psection_data(ELFIO::elfio& reader,
                       unsigned int psec_num,
                       void ** p_data, Elf_Word *p_data_sz ){
    Elf_Word    type;
    std::string name;
    bool found = FALSE;

    // There should be at least 2 entries in section: key and algo
    cout << "Checking psec_num: " << psec_num << endl;
    Elf_Word sec_entries_n = get_section_entries_n(reader, psec_num);
    if (sec_entries_n < PSEC_NENTRY) {
        err(EXIT_FAILURE, "ksec ix is %d, < %d", sec_entries_n, PSEC_NENTRY);
    }

    section * note_sec = reader.sections[psec_num];
    note_section_accessor notes_reader(reader, note_sec);

    if ( notes_reader.get_note( 0x0, type, name, *p_data, *p_data_sz ) ) {
        // 'name' usually contains \0 at the end. Try to fix it
        name = name.c_str();
        cout << "[" << 0x0 << "]" << " type: " << type << " name: " << name << " " << " Data sz:" << p_data_sz << endl;
        found = TRUE;
    }

    return found;
}
bool get_ksection_data(ELFIO::elfio& reader,
                                unsigned int ksec_num,
                                void ** key_data, Elf_Word *key_data_sz,
                                void ** algo_data, Elf_Word *algo_data_sz ){
    Elf_Word    type;
    std::string name;
    bool found = FALSE;

    // There should be at least 2 entries in section: key and algo
    cout << "Checking ksec_num: " << ksec_num << endl;
    Elf_Word sec_entries_n = get_section_entries_n(reader, ksec_num);
    if (sec_entries_n != KSEC_NENTRY) {
        err(EXIT_FAILURE, "ksec ix is %d, != %d", sec_entries_n, KSEC_NENTRY);
    }

    section * note_sec = reader.sections[ksec_num];
    note_section_accessor notes_reader(reader, note_sec);

    if ( notes_reader.get_note( 0x0, type, name, *key_data, *key_data_sz ) ) {
        // 'name' usually contains \0 at the end. Try to fix it
        name = name.c_str();
        cout << "[" << 0x0 << "]" << " type: " << type << " name: " << name << " " << " data: " << key_data << " sz:" << key_data_sz << endl;
        found = TRUE;
    }
    if ( notes_reader.get_note( 0x1, type, name, *algo_data, *algo_data_sz ) ) {
        // 'name' usually contains \0 at the end. Try to fix it
        name = name.c_str();
        cout << "[" << 0x1 << "]" << " type: " << type << " name: " << name << " " << " data: " << algo_data << " sz:" << algo_data_sz << endl;
        found = TRUE;
    }

    return found;
}
Elf_Word get_section_entries_n(ELFIO::elfio& reader, unsigned int section_number){
    note_section_accessor notes_reader(reader, reader.sections[section_number]);
    return  notes_reader.get_notes_num();
}
std::filesystem::path get_executable_path()
{
    return std::filesystem::canonical("/proc/self/exe");
}


