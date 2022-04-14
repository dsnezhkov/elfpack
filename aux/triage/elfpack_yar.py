import io
import yara
import hexdump

import unittest


class TestELFPack(unittest.TestCase):
    def setUp(self):
        self.scanner = ELFPAckScanner(file_path='/tmp/elf_loader/injected-cradle')

    def test_list_probable(self):
        sections = self.scanner.elf_test_notes_sections()
        self.assertTrue(len(sections) > 0, "Seeking ELFs with at least one SHT_NOTE section")

        print("=== SHT_NOTES Sections === ")
        for section_name, section_size in sections.items():
            print('{0:25s} : {1:6d} bytes'.format(section_name, section_size))

    def test_show_probbale(self):
        section_data = self.scanner.elf_section_by_name('.note.ABI-tag')
        self.assertTrue(len(section_data) > 0, "Seeking ELFs with at most one SHT_NOTE section of non-zero size")
        print(hexdump.hexdump(section_data))


class ELFPAckScanner:
    def __init__(self, file_path=None, rawdata=None):
        if file_path:
            file_object = open(file_path, 'rb')
        else:
            file_object = io.BytesIO(rawdata)
            file_object.name = "DummyFile.ext"
        self.file_name = file_object.name
        self.file_data = file_object.read()
        self.file_size = len(self.file_data)
        self.malware_name = 'ELFPack'
        self.res_data = b''
        self.rules = ""
        file_object.close()

    def elf_test_notes_sections(self) -> dict:
        try:
            self.rules = yara.compile(source='import "elf" rule a { condition: false }')
        except yara.SyntaxError:
            print("Error using Yara ELF did you enable it?")
        section_names = {}

        def modules_callback(data):
            for i, section in enumerate(data.get('sections', [])):
                if section['type'] == 7:  # SHT_NOTE
                    section_names[section['name'].decode('utf-8')] = section['size']
            return yara.CALLBACK_CONTINUE

        self.rules.match(data=self.file_data, modules_callback=modules_callback)

        return section_names

    def elf_section_by_name(self, resource_name):
        try:
            self.rules = yara.compile(source='import "elf" rule a { condition: false }')
        except yara.SyntaxError:
            print("Error using Yara ELF did you enable it?")

        def modules_callback(data):
            for i, section in enumerate(data.get('sections', [])):
                if section['name'].decode('utf-8') == resource_name:
                    offset = section['offset']
                    length = section['size']
                    self.res_data = self.file_data[offset:offset + length]
            return yara.CALLBACK_CONTINUE

        self.rules.match(data=self.file_data, modules_callback=modules_callback)
        return self.res_data


if __name__ == '__main__':
    unittest.main()


