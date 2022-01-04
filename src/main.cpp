#include <elfpack.h>

using namespace std;
using namespace ELFIO;

int main(int argc, char **argv) {

    if (argc < 6 || argc > 7) {
        cerr << "Usage: " << argv[0]
             << " <host_elf_file_in> <payload_file> <dst_elf_file_out> <dst_sec> <dst_descriptor_name> <key>" << endl;
        exit(AFAULT);
    }


    char *host_elf_file = argv[1];
    char *payload_file = argv[2];
    char *dst_elf_file = argv[3];
    char *dst_sec_name = argv[4];
    char *dst_desc_name = argv[5];

    unsigned char xor_key = 0x00;
    unsigned int sec_num;
    unsigned long sec_size;
    unsigned char *data = nullptr;
    ssize_t data_sz;
    section *note_sec = nullptr;
    Elf_Word note_entry_seq = 0x01;

    elfio reader_writer;

    // Check that host file exists and readable
    if (access(host_elf_file, F_OK | R_OK) != 0) {
        cerr << "Host file not accessible: " << host_elf_file << endl;
        exit(AFAULT);
    }

    // Check that payload file exists and readable
    if (access(payload_file, F_OK | R_OK) != 0) {
        cerr << "Payload file not accessible: " << payload_file << endl;
        exit(AFAULT);
    }

    // Check that dst ELF does not exist
    if (access(dst_elf_file, F_OK) == 0) {
        cerr << "dst ELF file exists. Remove it first: " << dst_elf_file << endl;
        exit(AFAULT);
    }

    if (argc == 7) {

        char *endptr = nullptr;
        errno = 0;

        xor_key = strtol(argv[6], nullptr, 16);
        if (errno != 0) {
            perror("strtol() conversion of key parameter");
            exit(AFAULT);
        }

        if (endptr == argv[6]) {
            cerr << "No digits were found" << endl;
            exit(AFAULT);
        }

        cout << "Xor key: " << hex << xor_key << endl;
    }
    // Load host ELF data
    if (!reader_writer.load(host_elf_file)) {
        cerr << "Can't find or process src ELF file: " << host_elf_file << endl;
        exit(AFAULT);
    }

    // Read payload
    data_sz = read_file_to_buffer(payload_file, &data);

    // Add new section or add new entry in existing section (chaining)
    if (find_section_by_name(reader_writer, dst_sec_name, &sec_num, &sec_size) == TRUE) {
        note_sec = reader_writer.sections[sec_num];
        note_section_accessor notes_reader(reader_writer, note_sec);
        Elf_Word no_notes = notes_reader.get_notes_num();
        cout << "Currently there " << no_notes << "records in section" << endl;
        note_entry_seq += 1;
        cout << "Next record sequence is " << note_entry_seq << endl;
    } else {
        note_sec = reader_writer.sections.add(dst_sec_name);
        note_sec->set_type(SHT_NOTE);
    }

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
        xor_buffer(&data, data_sz, xor_key);
    }

    // Write data to section
    note_writer.add_note(note_entry_seq, dst_desc_name, data, data_sz);
    if (reader_writer.save(dst_elf_file) == TRUE) {
        cout << "Packed " << dst_elf_file << " OK" << endl;
    }

    return 0;
}


