#name: eZ80 suffix output with multiple text fragments
#as: -march=ez80
#objdump: -d

.*:[     ]+file format (coff)|(elf32)\-z80


Disassembly of section \.text:

00000000 <\.text>:
[   ]+0:[\t]+40 ed 30[ \t]+defb.sis 0xed, 0x30
[   ]+3:[\t]+49 ed 30[ \t]+defb.lis 0xed, 0x30
[   ]+6:[\t]+52 ed 30[ \t]+defb.sil 0xed, 0x30
[   ]+9:[\t]+5b ed 30[ \t]+defb.lil 0xed, 0x30
