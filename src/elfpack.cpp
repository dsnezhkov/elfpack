#include <elfpack.h>

using namespace std;
using namespace ELFIO;

int main(int argc, char **argv) {

    if (argc != 8) {
        cerr << "Usage: " << argv[0]
             << " <path/host_elf_file_in> <path/payload_file> <path/dst_elf_file_out> <.dst_sec> <dst_descriptor_name> <algo:X|A> <key>" << endl;
        exit(AFAULT);
    }

    char *host_elf_file = argv[1];
    char *payload_file = argv[2];
    char *dst_elf_file = argv[3];
    char *dst_sec_name = argv[4];
    char *dst_desc_name = argv[5];
    char *algo = argv[6];
    char *key = argv[7];
    unsigned long* xor_key_store = nullptr;

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

    note_section_accessor pnote_writer(reader_writer, note_sec);
    cout << "Entry: "
         << note_entry_seq
         << ", Desc: "
         << dst_desc_name
         << ", Data Sz: "
         << data_sz
         << endl;


    if (strcmp(algo, "X") == 0)
    {
        // XOR method
        xKey2Buf(key,&xor_key_store);
        cout << "Xor key: " << hex << xor_key_store[0] << endl;

        // XOR data
        xor_buffer(&data, data_sz, xor_key_store[0]);

        // Write data to section
        pnote_writer.add_note(note_entry_seq, dst_desc_name, data, data_sz);
    }
    else if (strcmp(algo, "A") == 0)
    {
        // AES ...
    }
    else /* default: */
    {
        err(EXIT_FAILURE, "%s not in algo choices <X|A>", algo);
    }


    // Write meta data to meta section
    note_sec = reader_writer.sections.add(".note.gnu.buf"); // TODO: add external argument
    note_sec->set_type(SHT_NOTE);

    note_section_accessor knote_writer(reader_writer, note_sec);


    unsigned int canary_buffer_sz = 4;
    unsigned char * canary_buffer = (unsigned char*) calloc (sizeof(unsigned char), canary_buffer_sz);
    canary_buffer[0] = KSEC_CANARY_CHAR;
    canary_buffer[1] = KSEC_CANARY_CHAR;
    canary_buffer[2] = KSEC_CANARY_CHAR;
    canary_buffer[3] = KSEC_CANARY_CHAR;
    xor_buffer( &canary_buffer, canary_buffer_sz, xor_key_store[0]);



    // Key store
    // knote_writer.add_note(0x0, "0x0", xor_key_store, strlen(key)); // TODO: add external arguments, etc.
    knote_writer.add_note(0x0, "0x0", canary_buffer, canary_buffer_sz); // TODO: add external arguments, etc.
    knote_writer.add_note(0x1, "0x1", "X", strlen(algo)); // TODO: add external arguments, etc.


    if (reader_writer.save(dst_elf_file) == TRUE) {
        cout << "Packed " << dst_elf_file << " OK" << endl;
    }

    return 0;
}


