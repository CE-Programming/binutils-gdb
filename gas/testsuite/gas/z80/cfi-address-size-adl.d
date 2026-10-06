#source: cfi-address-size.s
#as: -march=ez80+adl --defsym SLOT=3
#objdump: --dwarf=frames
#name: Z80 CFI 3-byte addresses
.*:     file format elf32-z80
Contents of the .eh_frame section:


00000000 00001c 00000000 CIE
  Version:               4
  Augmentation:          "zR"
  Pointer Size:          3
  Segment Size:          0
  Code alignment factor: 1
  Data alignment factor: -1
  Return address column: 5
  Augmentation data:     0b
  DW_CFA_def_cfa: r4 ofs 0
  DW_CFA_def_cfa: r4 ofs 3
  DW_CFA_offset: r5 at cfa-3
  DW_CFA_same_value: r6
  DW_CFA_nop
  DW_CFA_nop
  DW_CFA_nop

00000020 000020 00000024 FDE cie=00000000 pc=000000\.\.00000e
  DW_CFA_advance_loc: 2 to 000002
  DW_CFA_def_cfa_offset: 6
  DW_CFA_offset: r6 at cfa-6
  DW_CFA_advance_loc: 7 to 000009
  DW_CFA_def_cfa_register: r6
  DW_CFA_advance_loc: 2 to 00000b
  DW_CFA_def_cfa: r4 ofs 6
  DW_CFA_advance_loc: 2 to 00000d
  DW_CFA_def_cfa_offset: 3
  DW_CFA_restore: r6
  DW_CFA_nop
  DW_CFA_nop
  DW_CFA_nop

Contents of the .debug_frame section:


00000000 000015 ffffffff CIE
  Version:               4
  Augmentation:          ""
  Pointer Size:          3
  Segment Size:          0
  Code alignment factor: 1
  Data alignment factor: -1
  Return address column: 5

  DW_CFA_def_cfa: r4 ofs 0
  DW_CFA_def_cfa: r4 ofs 3
  DW_CFA_offset: r5 at cfa-3
  DW_CFA_same_value: r6

00000019 00001a 00000000 FDE cie=00000000 pc=000000\.\.00000e
  DW_CFA_advance_loc: 2 to 000002
  DW_CFA_def_cfa_offset: 6
  DW_CFA_offset: r6 at cfa-6
  DW_CFA_advance_loc: 7 to 000009
  DW_CFA_def_cfa_register: r6
  DW_CFA_advance_loc: 2 to 00000b
  DW_CFA_def_cfa: r4 ofs 6
  DW_CFA_advance_loc: 2 to 00000d
  DW_CFA_def_cfa_offset: 3
  DW_CFA_restore: r6

