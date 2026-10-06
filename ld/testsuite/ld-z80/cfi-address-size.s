.text
.cfi_sections .debug_frame, .eh_frame
frame:
.cfi_startproc
.cfi_def_cfa sp, SLOT
.cfi_offset pc, -SLOT
.cfi_same_value ix
push ix
.cfi_def_cfa_offset 2*SLOT
.cfi_offset ix, -2*SLOT
ld ix, 0
add ix, sp
.cfi_def_cfa_register ix
ld sp, ix
.cfi_def_cfa sp, 2*SLOT
pop ix
.cfi_def_cfa_offset SLOT
.cfi_restore ix
ret
.cfi_endproc
