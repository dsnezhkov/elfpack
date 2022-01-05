#include <elfldr.h>

using namespace std;
using namespace ELFIO;

int main(int argc, char **argv) {

    char *sec_name = (char *) (".note.gnu.buf[...]");
    unsigned int sec_num;
    unsigned long sec_size;

    unsigned char xor_key = 29;
    unsigned char *data = nullptr;

    ssize_t data_sz;
    section *note_sec = nullptr;
    Elf_Word note_entry_seq = 0x01;

    elfio reader;

    filesystem::path my_path = get_executable_path();

    // Load host ELF data
    if (!reader.load(my_path)) {
        cerr << "Can't find or process src ELF file: " << argv[0] << endl;
        exit(AFAULT);
    }

    // get section
    if (find_section_by_name(reader, sec_name, &sec_num, &sec_size) == TRUE) {
        note_sec = reader.sections[sec_num];
        note_section_accessor notes_reader(reader, note_sec);
        Elf_Word no_notes = notes_reader.get_notes_num();
        cout << "Currently there " << no_notes << "records in section" << endl;
        cout << "Section name: " << note_sec->get_name() << endl;

        for ( Elf_Word j = 0; j < no_notes; ++j ) { // For all notes
            Elf_Word    type;
            std::string name;
            void*       desc;
            Elf_Word    descsz;

            if ( notes_reader.get_note( j, type, name, desc, descsz ) ) {
                // 'name' usually contains \0 at the end. Try to fix it
                name = name.c_str();
                cout << "[" << j << "]" << " " << type << " " << name << " " << descsz << endl;
            }

        }

        Elf_Word    type;
        std::string name;
        void*       desc;
        Elf_Word    descsz;

        if ( notes_reader.get_note( 0, type, name, desc, descsz ) ) {
            // 'name' usually contains \0 at the end. Try to fix it
            name = name.c_str();
            cout << "[" << 0 << "]" << " " << type << " " << name << " " << descsz << endl;
        }

        //uxor_buffer(reinterpret_cast<unsigned char **>(&desc), (unsigned long) descsz, xor_key );
        dump_buffer(desc, descsz, (char *) "/tmp/lspay.dmp");

    } else {
        cerr << "Section " << sec_name << "not found in " << my_path << endl;
        cerr << "sec_num " << sec_num << "sec_size" << sec_size << endl;
    }

/*
    note_section_accessor note_writer(reader_writer, note_sec);
    cout << "Entry: "
         << note_entry_seq
         << ", Desc: "
         << dst_desc_name
         << ", Data Sz: "
         << data_sz
         << endl;

    // XOR data with tricks?
    if (xor_key != 0x00) {
        uxor_buffer(&data, data_sz, xor_key);
    }

*/

    return 0;
}

std::filesystem::path get_executable_path()
{
    return std::filesystem::canonical("/proc/self/exe");
}


