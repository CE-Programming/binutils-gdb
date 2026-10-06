#source: cfi-address-size.s
#as: -march=z80 --defsym SLOT=2
#ld: -Ttext=0x1234 -e 0x1234
#objdump: --dwarf=frames
#name: Z80 linked CFI 2-byte addresses
.*:     file format elf32-z80
Contents of the .eh_frame section:


00000000 001c 00000000 CIE
  Version:               4
  Augmentation:          "zR"
  Pointer Size:          2
  Segment Size:          0
  Code alignment factor: 1
  Data alignment factor: -1
  Return address column: 5
  Augmentation data:     0b
  DW_CFA_def_cfa: r4 ofs 0
  DW_CFA_def_cfa: r4 ofs 2
  DW_CFA_offset: r5 at cfa-2
  DW_CFA_same_value: r6
  DW_CFA_nop
  DW_CFA_nop
  DW_CFA_nop

00000020 0020 00000024 FDE cie=00000000 pc=1234\.\.1241
  DW_CFA_advance_loc: 2 to 1236
  DW_CFA_def_cfa_offset: 4
  DW_CFA_offset: r6 at cfa-4
  DW_CFA_advance_loc: 6 to 123c
  DW_CFA_def_cfa_register: r6
  DW_CFA_advance_loc: 2 to 123e
  DW_CFA_def_cfa: r4 ofs 4
  DW_CFA_advance_loc: 2 to 1240
  DW_CFA_def_cfa_offset: 2
  DW_CFA_restore: r6
  DW_CFA_nop
  DW_CFA_nop
  DW_CFA_nop

Contents of the .debug_frame section:


00000000 0016 ffffffff CIE
  Version:               4
  Augmentation:          ""
  Pointer Size:          2
  Segment Size:          0
  Code alignment factor: 1
  Data alignment factor: -1
  Return address column: 5

  DW_CFA_def_cfa: r4 ofs 0
  DW_CFA_def_cfa: r4 ofs 2
  DW_CFA_offset: r5 at cfa-2
  DW_CFA_same_value: r6
  DW_CFA_nop

0000001a 0018 00000000 FDE cie=00000000 pc=1234\.\.1241
  DW_CFA_advance_loc: 2 to 1236
  DW_CFA_def_cfa_offset: 4
  DW_CFA_offset: r6 at cfa-4
  DW_CFA_advance_loc: 6 to 123c
  DW_CFA_def_cfa_register: r6
  DW_CFA_advance_loc: 2 to 123e
  DW_CFA_def_cfa: r4 ofs 4
  DW_CFA_advance_loc: 2 to 1240
  DW_CFA_def_cfa_offset: 2
  DW_CFA_restore: r6

