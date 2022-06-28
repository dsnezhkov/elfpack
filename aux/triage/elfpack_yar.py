import sys
import io
import yara
import hexdump

import unittest


class TestELFPack(unittest.TestCase):
    test_file = ""
    elf_section = ""
    def setUp(self):
        self.scanner = ELFPAckScanner(file_path=self.test_file)

    def test_list_probable(self):
        sections = self.scanner.elf_test_notes_sections()
        if len(sections) > 0:
          print("=== SHT_NOTES Sections in %s === " % self.test_file)
          for section_name, section_size in sections.items():
            print('{0:25s} : {1:6d} bytes'.format(section_name, section_size))

    def test_show_probable(self):
        section_data = self.scanner.elf_section_by_name(self.elf_section)
        if len(section_data) > 0:
           print("=== Section %s content ===" % self.elf_section)
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
    if len(sys.argv) > 2:
       TestELFPack.elf_section = sys.argv.pop()

    if len(sys.argv) > 1:
       TestELFPack.test_file = sys.argv.pop()
       unittest.main(verbosity=0)
    else:
       print("Usage: %s <path/to/elf/file> [elf_section]" %  (sys.argv[0]) ) 


