/* Target-dependent code for the Z80.

   Copyright (C) 1986-2026 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "arch-utils.h"
#include "dis-asm.h"
#include "extract-store-integer.h"
#include "frame.h"
#include "frame-unwind.h"
#include "frame-base.h"
#include "trad-frame.h"
#include "cli/cli-cmds.h"
#include "gdbcore.h"
#include "gdbtypes.h"
#include "inferior.h"
#include "objfiles.h"
#include "symfile.h"
#include "gdbarch.h"

#include "z80-tdep.h"
#include "features/z80.c"

/* You need to define __gdb_break_handler symbol pointing to the breakpoint
   handler.  The value of the symbol will be used to determine the instruction
   for software breakpoint.  If __gdb_break_handler points to one of standard
   RST addresses (0x00, 0x08, 0x10,... 0x38) then RST __gdb_break_handler
   instruction will be used, else CALL __gdb_break_handler

;breakpoint handler
	.globl	__gdb_break_handler
	.org	8
__gdb_break_handler:
	jp	_debug_swbreak

*/

/* Meaning of terms "previous" and "next":
     previous frame - frame of callee, which is called by current function
     current frame - frame of current function which has called callee
     next frame - frame of caller, which has called current function
*/

struct z80_gdbarch_tdep : gdbarch_tdep_base
{
  /* Number of bytes used for address:
      2 bytes for all Z80 family
      3 bytes for eZ80 CPUs operating in ADL mode */
  int addr_length = 0;

  /* Type for void.  */
  struct type *void_type = nullptr;

  /* Type for a function returning void.  */
  struct type *func_void_type = nullptr;

  /* Type for a pointer to a function.  Used for the type of PC.  */
  struct type *pc_type = nullptr;
};

/* At any time stack frame contains following parts:
   [<current PC>]
   [<temporaries, y bytes>]
   [<local variables, x bytes>
   <next frame FP>]
   [<saved state (critical or interrupt functions), 2 or 10 bytes>]
   In simplest case <next PC> is pointer to the call instruction
   (or call __call_hl). There are more difficult cases: interrupt handler or
   push/ret and jp; but they are untrackable.
*/

struct z80_unwind_cache
{
  /* The previous frame's inner most stack address (SP after call executed),
     it is current frame's frame_id.  */
  CORE_ADDR prev_sp;

  /* Size of the frame, prev_sp + size = next_frame.prev_sp */
  ULONGEST size;

  /* Bytes saved below the return address, including the caller's IX.  */
  ULONGEST state_size;

  struct
  {
    unsigned int called : 1;    /* there is return address on stack */
    unsigned int load_args : 1; /* prologues loads args using POPs */
    unsigned int ix_saved : 1;  /* prologue saves IX */
    unsigned int fp_sdcc : 1;   /* prologue saves and adjusts frame pointer IX */
    unsigned int interrupt : 1; /* __interrupt handler */
    unsigned int critical : 1;  /* __critical function */
  } prologue_type;

  /* Table indicating the location of each and every register.  */
  struct trad_frame_saved_reg *saved_regs;
};

enum z80_instruction_type
{
  insn_default,
  insn_z80,
  insn_adl,
  insn_z80_ed,
  insn_adl_ed,
  insn_z80_ddfd,
  insn_adl_ddfd,
  insn_djnz_d,
  insn_jr_d,
  insn_jr_cc_d,
  insn_jp_nn,
  insn_jp_rr,
  insn_jp_cc_nn,
  insn_call_nn,
  insn_call_cc_nn,
  insn_rst_n,
  insn_ret,
  insn_ret_cc,
  insn_push_rr,
  insn_pop_rr,
  insn_dec_sp,
  insn_inc_sp,
  insn_ld_sp_nn,
  insn_ld_sp_6nn9, /* ld sp, (nn) */
  insn_ld_sp_rr,
  insn_force_nop /* invalid opcode prefix */
};

struct z80_insn_info
{
  gdb_byte code;
  gdb_byte mask;
  gdb_byte size; /* without prefix(es) */
  enum z80_instruction_type type;
};

/* Constants */

static const struct z80_insn_info *
z80_get_insn_info (struct gdbarch *gdbarch, const gdb_byte *buf, int *size);

static const char *z80_reg_names[] =
{
  /* 24 bit on eZ80, else 16 bit */
  "af", "bc", "de", "hl",
  "sp", "pc", "ix", "iy",
  "af'", "bc'", "de'", "hl'",
  "ir",
  /* eZ80 only */
  "sps"
};

/* Return the name of register REGNUM.  */
static const char *
z80_register_name (struct gdbarch *gdbarch, int regnum)
{
  if (regnum < ARRAY_SIZE (z80_reg_names))
    return z80_reg_names[regnum];

  return "";
}

/* Return the type of a register specified by the architecture.  Only
   the register cache should call this function directly; others should
   use "register_type".  */
static struct type *
z80_register_type (struct gdbarch *gdbarch, int reg_nr)
{
  return builtin_type (gdbarch)->builtin_data_ptr;
}

/* The next 2 functions check BUF for instruction.  If it is pop/push rr, then
   it returns register number OR'ed with 0x100 */
static int
z80_is_pop_rr (const gdb_byte buf[], int len, int *size)
{
  if (len == 0)
    return 0;
  switch (buf[0])
    {
    case 0xc1:
      *size = 1;
      return Z80_BC_REGNUM | 0x100;
    case 0xd1:
      *size = 1;
      return Z80_DE_REGNUM | 0x100;
    case 0xe1:
      *size = 1;
      return Z80_HL_REGNUM | 0x100;
    case 0xf1:
      *size = 1;
      return Z80_AF_REGNUM | 0x100;
    case 0xdd:
      *size = 2;
      return (len >= 2 && buf[1] == 0xe1) ? (Z80_IX_REGNUM | 0x100) : 0;
    case 0xfd:
      *size = 2;
      return (len >= 2 && buf[1] == 0xe1) ? (Z80_IY_REGNUM | 0x100) : 0;
    }
  *size = 0;
  return 0;
}

static int
z80_is_push_rr (const gdb_byte buf[], int len, int *size)
{
  if (len == 0)
    return 0;
  switch (buf[0])
    {
    case 0xc5:
      *size = 1;
      return Z80_BC_REGNUM | 0x100;
    case 0xd5:
      *size = 1;
      return Z80_DE_REGNUM | 0x100;
    case 0xe5:
      *size = 1;
      return Z80_HL_REGNUM | 0x100;
    case 0xf5:
      *size = 1;
      return Z80_AF_REGNUM | 0x100;
    case 0xdd:
      *size = 2;
      return (len >= 2 && buf[1] == 0xe5) ? (Z80_IX_REGNUM | 0x100) : 0;
    case 0xfd:
      *size = 2;
      return (len >= 2 && buf[1] == 0xe5) ? (Z80_IY_REGNUM | 0x100) : 0;
    }
  *size = 0;
  return 0;
}

/* Function: z80_scan_prologue

   This function decodes a function prologue to determine:
     1) the size of the stack frame
     2) which registers are saved on it
     3) the offsets of saved regs
   This information is stored in the z80_unwind_cache structure.
   Small SDCC functions may just load args using POP instructions in prologue:
	pop	af
	pop	de
	pop	hl
	pop	bc
	push	bc
	push	hl
	push	de
	push	af
   SDCC function prologue may have up to 3 sections (all are optional):
     1) save state
       a) __critical functions:
	ld	a,i
	di
	push	af
       b) __interrupt (both int and nmi) functions:
	push	af
	push	bc
	push	de
	push	hl
	push	iy
     2) save and adjust frame pointer
       a) call to special function (size optimization)
	call	___sdcc_enter_ix
       b) inline (speed optimization)
	push	ix
	ld	ix, #0
	add	ix, sp
       c) without FP, but saving it (IX is optimized out)
	push	ix
     3) allocate local variables
       a) via series of PUSH AF and optional DEC SP (size optimization)
	push	af
	...
	push	af
	dec	sp	;optional, if allocated odd numbers of bytes
       b) via SP decrements
	dec	sp
	...
	dec	sp
       c) via addition (for large frames: 5+ for speed and 9+ for size opt.)
	ld	hl, #xxxx	;size of stack frame
	add	hl, sp
	ld	sp, hl
       d) same, but using register IY (arrays or for __z88dk_fastcall functions)
	ld	iy, #xxxx	;size of stack frame
	add	iy, sp
	ld	sp, iy
       e) same as c, but for eZ80
	lea	hl, ix - #nn
	ld	sp, hl
       f) same as d, but for eZ80
	lea	iy, ix - #nn
	ld	sp, iy
*/

static int
z80_scan_prologue (struct gdbarch *gdbarch, CORE_ADDR pc_beg, CORE_ADDR pc_end,
		   struct z80_unwind_cache *info)
{
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  z80_gdbarch_tdep *tdep = gdbarch_tdep<z80_gdbarch_tdep> (gdbarch);
  int addr_len = tdep->addr_length;
  /* Include space for an interrupt prologue with local storage.  */
  gdb_byte prologue[32] = {};
  int pos = 0;
  int len;
  int reg;
  int first_size = 0;
  CORE_ADDR value;

  len = pc_end - pc_beg;
  if (len > (int)sizeof (prologue))
    len = sizeof (prologue);

  read_memory (pc_beg, prologue, len);

  /* stage0: check for series of POPs and then PUSHs */
  if ((reg = z80_is_pop_rr (prologue, len, &first_size)))
    {
      pos = first_size;
      int i;
      int size = pos;
      int regs[8]; /* Register numbers include the matching flag.  */
      regs[0] = reg;
      for (i = 1; i < 8
	   && (regs[i] = z80_is_pop_rr (&prologue[pos], len - pos, &size));
	   ++i, pos += size);
      /* now we expect series of PUSHs in reverse order */
      for (--i; i >= 0
	   && regs[i] == z80_is_push_rr (&prologue[pos], len - pos, &size);
	   --i, pos += size);
      if (i == -1 && pos > 0)
	info->prologue_type.load_args = 1;
      else
	pos = 0;
    }
  /* stage1: check for __interrupt handlers and __critical functions */
  else if (len >= 4 && !memcmp (&prologue[pos], "\355\127\363\365", 4))
    { /* ld a, i; di; push af */
      info->prologue_type.critical = 1;
      pos += 4;
    }
  else if (len >= 6 && !memcmp (&prologue[pos], "\365\305\325\345\375\345", 6))
    { /* push af; push bc; push de; push hl; push iy */
      info->prologue_type.interrupt = 1;
      pos += 6;
    }

  /* stage2: check for FP saving scheme */
  if (pos + 1 + addr_len <= len && prologue[pos] == 0xcd) /* call nn */
    {
      bound_minimal_symbol msymbol
	= lookup_minimal_symbol (current_program_space, "__sdcc_enter_ix");
      if (msymbol.minsym)
	{
	  value = msymbol.value_address ();
	  if (value == extract_unsigned_integer (&prologue[pos+1], addr_len, byte_order))
	    {
	      pos += 1 + addr_len;
	      info->prologue_type.ix_saved = 1;
	      info->prologue_type.fp_sdcc = 1;
	    }
	}
    }
  else if (pos + 4 + addr_len + 2 <= len
	   && !memcmp (&prologue[pos], "\335\345\335\041\000\000", 4+addr_len)
	   && !memcmp (&prologue[pos+4+addr_len], "\335\071", 2))
    { /* push ix; ld ix, #0; add ix, sp; optional ld sp, ix */
      pos += 4 + addr_len + 2;
      if (pos + 2 <= len && !memcmp (&prologue[pos], "\335\371", 2))
	pos += 2;
      info->prologue_type.ix_saved = 1;
      info->prologue_type.fp_sdcc = 1;
    }
  else if (pos + 2 <= len && !memcmp (&prologue[pos], "\335\345", 2))
    { /* push ix */
      pos += 2;
      info->prologue_type.ix_saved = 1;
    }

  /* stage3: check for local variables allocation */
  switch (pos < len ? prologue[pos] : 0)
    {
      case 0xf5: /* push af */
	info->size = 0;
	while (pos < len && prologue[pos] == 0xf5)
	  {
	    info->size += addr_len;
	    pos++;
	  }
	if (pos < len && prologue[pos] == 0x3b) /* dec sp */
	  {
	    info->size++;
	    pos++;
	  }
	break;
      case 0x3b: /* dec sp */
	info->size = 0;
	while (pos < len && prologue[pos] == 0x3b)
	  {
	    info->size++;
	    pos++;
	  }
	break;
      case 0x21: /*ld hl, -nn */
	if (pos + addr_len + 3 <= len && prologue[pos+addr_len] >= 0x80 &&
	    prologue[pos+addr_len+1] == 0x39 &&
	    prologue[pos+addr_len+2] == 0xf9)
	  { /* add hl, sp; ld sp, hl */
	    info->size = -extract_signed_integer(&prologue[pos+1], addr_len, byte_order);
	    pos += 1 + addr_len + 2;
	  }
	break;
      case 0xfd: /* ld iy, -nn */
	if (pos + addr_len + 6 <= len && prologue[pos+1] == 0x21
	    && prologue[pos+1+addr_len] >= 0x80 &&
	    !memcmp (&prologue[pos+2+addr_len], "\375\071\375\371", 4))
	  {
	    info->size = -extract_signed_integer(&prologue[pos+2], addr_len, byte_order);
	    pos += 2 + addr_len + 4;
	  }
	break;
      case 0xed: /* check for lea xx, ix - n */
	switch (pos + 1 < len ? prologue[pos+1] : 0)
	  {
	  case 0x22: /* lea hl, ix - n */
	    if (pos + 4 <= len && prologue[pos+2] >= 0x80 && prologue[pos+3] == 0xf9)
	      { /* ld sp, hl */
		info->size = -extract_signed_integer(&prologue[pos+2], 1, byte_order);
		pos += 4;
	      }
	    break;
	  case 0x55: /* lea iy, ix - n */
	    if (pos + 5 <= len && prologue[pos+2] >= 0x80 && prologue[pos+3] == 0xfd &&
		prologue[pos+4] == 0xf9)
	      { /* ld sp, iy */
		info->size = -extract_signed_integer(&prologue[pos+2], 1, byte_order);
		pos += 5;
	      }
	    break;
	  }
	  break;
    }
  /* Saved registers are numbered from one, below the return address.  */
  len = 1;

  if (info->prologue_type.interrupt)
    {
      info->saved_regs[Z80_AF_REGNUM].set_addr (len++);
      info->saved_regs[Z80_BC_REGNUM].set_addr (len++);
      info->saved_regs[Z80_DE_REGNUM].set_addr (len++);
      info->saved_regs[Z80_HL_REGNUM].set_addr (len++);
      info->saved_regs[Z80_IY_REGNUM].set_addr (len++);
    }

  if (info->prologue_type.critical)
    len++; /* just skip IFF2 saved state */

  if (info->prologue_type.ix_saved)
    info->saved_regs[Z80_IX_REGNUM].set_addr (len++);

  info->state_size += (len - 1) * addr_len;

  return pc_beg + pos;
}

static CORE_ADDR
z80_skip_prologue (struct gdbarch *gdbarch, CORE_ADDR pc)
{
  CORE_ADDR func_addr, func_end;
  CORE_ADDR prologue_end;

  if (!find_pc_partial_function (pc, NULL, &func_addr, &func_end))
    return pc;

  prologue_end = skip_prologue_using_sal (gdbarch, func_addr);
  if (prologue_end != 0)
    return std::max (pc, prologue_end);

  {
    struct z80_unwind_cache info = {0};
    struct trad_frame_saved_reg saved_regs[Z80_NUM_REGS];

    info.saved_regs = saved_regs;

    /* Need to run the prologue scanner to figure out if the function has a
       prologue.  */

    prologue_end = z80_scan_prologue (gdbarch, func_addr, func_end, &info);

    if (info.prologue_type.fp_sdcc || info.prologue_type.interrupt ||
	info.prologue_type.critical)
      return std::max (pc, prologue_end);
  }

  if (prologue_end != 0)
    {
      struct symtab_and_line prologue_sal = find_sal_for_pc (func_addr, 0);

      if (prologue_sal.symtab != nullptr)
	{
	  const char *debug_format
	    = prologue_sal.symtab->compunit ().debugformat ();

	  if (debug_format != nullptr
	      && !strncasecmp ("dwarf", debug_format, strlen ("dwarf")))
	    return std::max (pc, prologue_end);
	}
    }

  return pc;
}

/* Return the return-value convention that will be used by FUNCTION
   to return a value of type VALTYPE.  FUNCTION may be NULL in which
   case the return convention is computed based only on VALTYPE.

   If READBUF is not NULL, extract the return value and save it in this buffer.

   If WRITEBUF is not NULL, it contains a return value which will be
   stored into the appropriate register.  This can be used when we want
   to force the value returned by a function (see the "return" command
   for instance).  */
static enum return_value_convention
z80_return_value (struct gdbarch *gdbarch, struct value *function,
		  struct type *valtype, struct regcache *regcache,
		  gdb_byte *readbuf, const gdb_byte *writebuf)
{
  /* Scalars use HL, then DE.  Each pair holds three bytes in ADL mode.  */
  int register_len = gdbarch_tdep<z80_gdbarch_tdep> (gdbarch)->addr_length;
  int len = valtype->length ();

  if ((valtype->code () == TYPE_CODE_STRUCT
       || valtype->code () == TYPE_CODE_UNION
       || valtype->code () == TYPE_CODE_ARRAY)
      && len > 4)
    return RETURN_VALUE_STRUCT_CONVENTION;

  int hl_len = std::min (len, register_len);
  if (writebuf != nullptr)
    {
      if (len > register_len)
	regcache->cooked_write_part (Z80_DE_REGNUM, 0, len - register_len,
				    writebuf + register_len);
      regcache->cooked_write_part (Z80_HL_REGNUM, 0, hl_len, writebuf);
    }

  if (readbuf != nullptr)
    {
      if (len > register_len)
	regcache->cooked_read_part (Z80_DE_REGNUM, 0, len - register_len,
				   readbuf + register_len);
      regcache->cooked_read_part (Z80_HL_REGNUM, 0, hl_len, readbuf);
    }

  return RETURN_VALUE_REGISTER_CONVENTION;
}

/* function unwinds current stack frame and returns next one */
static struct z80_unwind_cache *
z80_frame_unwind_cache (const frame_info_ptr &this_frame,
			void **this_prologue_cache)
{
  CORE_ADDR start_pc, current_pc;
  ULONGEST this_base;
  int i;
  gdb_byte buf[sizeof(void*)];
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  z80_gdbarch_tdep *tdep = gdbarch_tdep<z80_gdbarch_tdep> (gdbarch);
  int addr_len = tdep->addr_length;

  if (*this_prologue_cache)
    return (struct z80_unwind_cache *) *this_prologue_cache;

  auto *info = frame_obstack_zalloc<z80_unwind_cache> ();
  memset (info, 0, sizeof (*info));
  info->saved_regs = trad_frame_alloc_saved_regs (this_frame);
  *this_prologue_cache = info;

  start_pc = get_frame_func (this_frame);
  current_pc = get_frame_pc (this_frame);
  if ((start_pc > 0) && (start_pc <= current_pc))
    z80_scan_prologue (get_frame_arch (this_frame),
		       start_pc, current_pc, info);

  if (info->prologue_type.fp_sdcc)
    {
      /*  With SDCC standard prologue, IX points to the end of current frame
	  (where previous frame pointer and state are saved).  */
      this_base = get_frame_register_unsigned (this_frame, Z80_IX_REGNUM);
      info->prev_sp = this_base + info->state_size;
    }
  else
    {
      CORE_ADDR addr;
      CORE_ADDR sp;
      CORE_ADDR addr_space_max = (1 << gdbarch_ptr_bit(gdbarch)) - 1;
      enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
      int loop_count = 0;
      /* Assume that the FP is this frame's SP but with that pushed
	 stack space added back.  */
      this_base = get_frame_register_unsigned (this_frame, Z80_SP_REGNUM);
      sp = this_base + info->size + info->state_size;
      for (;; ++sp)
	{
	  /* Limit the scan to 2 * addr_len iterations.  If the unwinder's
	     frame size calculation is slightly off (e.g. due to unpopped
	     arguments or temporary pushes), the return address might be
	     hidden a few bytes deeper.  Scanning up to 2 * addr_len bytes
	     comfortably covers two misplaced pointer-sized values.
	     Scanning further drastically increases the risk of false
	     positives: we might wander into the caller's local variables,
	     hit a random CALL or conditional CALL opcode, and generate a
	     corrupted backtrace.  It also prevents massive slow-downs on
	     remote serial targets if the stack is severely corrupted.  */
	  if (++loop_count > 2 * addr_len || sp > addr_space_max)
	    { /* Limit reached or end of address space, assume end of stack.  */
	      sp = this_base + info->size + info->state_size;
	      break;
	    }
	  /* find return address */
	  read_memory (sp, buf, addr_len);
	  addr = extract_unsigned_integer(buf, addr_len, byte_order);
	  read_memory (addr-addr_len-1, buf, addr_len+1);
	  if (buf[0] == 0xcd || (buf[0] & 0307) == 0304) /* Is it CALL */
	    { /* CALL nn or CALL cc,nn */
	      static const char *names[] =
		{
		  "__sdcc_call_ix", "__sdcc_call_iy", "__sdcc_call_hl"
		};
	      addr = extract_unsigned_integer(buf+1, addr_len, byte_order);
	      if (addr == start_pc)
		break; /* found */
	      for (i = sizeof(names)/sizeof(*names)-1; i >= 0; --i)
		{
		  bound_minimal_symbol msymbol
		    = lookup_minimal_symbol (current_program_space, names[i]);
		  if (!msymbol.minsym)
		    continue;
		  if (addr == msymbol.value_address ())
		    break;
		}
	      if (i >= 0)
		break;
	      continue;
	    }
	  else
	    continue; /* it is not call_nn, call_cc_nn */
	}
      info->prev_sp = sp;
    }

  /* Adjust all the saved registers so that they contain addresses and not
     offsets.  */
  for (i = 0; i < gdbarch_num_regs (gdbarch) - 1; i++)
    {
      if (info->saved_regs[i].is_addr ())
	{
	  if (info->saved_regs[i].addr () > 0)
	    info->saved_regs[i].set_addr
	      (info->prev_sp - info->saved_regs[i].addr () * addr_len);
	}
    }

  /* Except for the startup code, the return PC is always saved on
     the stack and is at the base of the frame.  */
  info->saved_regs[Z80_PC_REGNUM].set_addr (info->prev_sp);

  /* The previous frame's SP needed to be computed.  Save the computed
     value.  */
  info->saved_regs[Z80_SP_REGNUM].set_value (info->prev_sp + addr_len);
  return info;
}

/* Given a GDB frame, determine the address of the calling function's
   frame.  This will be used to create a new GDB frame struct.  */
static void
z80_frame_this_id (const frame_info_ptr &this_frame, void **this_cache,
		   struct frame_id *this_id)
{
  struct frame_id id;
  struct z80_unwind_cache *info;
  CORE_ADDR base;
  CORE_ADDR func;

  /* The FUNC is easy.  */
  func = get_frame_func (this_frame);

  info = z80_frame_unwind_cache (this_frame, this_cache);
  /* Hopefully the prologue analysis either correctly determined the
     frame's base (which is the SP from the previous frame), or set
     that base to "NULL".  */
  base = info->prev_sp;
  if (base == 0)
    return;

  id = frame_id_build (base, func);
  *this_id = id;
}

static struct value *
z80_frame_prev_register (const frame_info_ptr &this_frame,
			 void **this_prologue_cache, int regnum)
{
  struct z80_unwind_cache *info
    = z80_frame_unwind_cache (this_frame, this_prologue_cache);

  if (regnum == Z80_PC_REGNUM)
    {
      if (info->saved_regs[Z80_PC_REGNUM].is_addr ())
	{
	  /* Reading the return PC from the PC register is slightly
	     abnormal.  */
	  ULONGEST pc;
	  gdb_byte buf[3];
	  struct gdbarch *gdbarch = get_frame_arch (this_frame);
	  z80_gdbarch_tdep *tdep = gdbarch_tdep<z80_gdbarch_tdep> (gdbarch);
	  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);

	  read_memory (info->saved_regs[Z80_PC_REGNUM].addr (),
		       buf, tdep->addr_length);
	  pc = extract_unsigned_integer (buf, tdep->addr_length, byte_order);
	  return frame_unwind_got_constant (this_frame, regnum, pc);
	}

      return frame_unwind_got_optimized (this_frame, regnum);
    }

  return trad_frame_get_prev_register (this_frame, info->saved_regs, regnum);
}

/* Return the breakpoint kind for this target based on *PCPTR.  */
static int
z80_breakpoint_kind_from_pc (struct gdbarch *gdbarch, CORE_ADDR *pcptr)
{
  static int addr = -1;
  if (addr == -1)
    {
      bound_minimal_symbol bh
	= lookup_minimal_symbol (current_program_space, "_break_handler");
      if (bh.minsym)
	addr = bh.value_address ();
      else
	{
	  warning(_("Unable to determine inferior's software breakpoint type: "
		    "couldn't find `_break_handler' function in inferior. Will "
		    "be used default software breakpoint instruction RST 0x08."));
	  addr = 0x0008;
	}
    }
  return addr;
}

/* Return the software breakpoint from KIND. KIND is just address of breakpoint
   handler.  If address is on of standard RSTs, then RST n instruction is used
   as breakpoint.
   SIZE is set to the software breakpoint's length in memory.  */
static const gdb_byte *
z80_sw_breakpoint_from_kind (struct gdbarch *gdbarch, int kind, int *size)
{
  static gdb_byte break_insn[8];

  if ((kind & 070) == kind)
    {
      break_insn[0] = kind | 0307;
      *size = 1;
    }
  else /* kind is non-RST address, use CALL instead, but it is dangerous */
    {
      z80_gdbarch_tdep *tdep = gdbarch_tdep<z80_gdbarch_tdep> (gdbarch);
      gdb_byte *p = break_insn;
      *p++ = 0xcd;
      *p++ = (kind >> 0) & 0xff;
      *p++ = (kind >> 8) & 0xff;
      if (tdep->addr_length > 2)
	*p++ = (kind >> 16) & 0xff;
      *size = p - break_insn;
    }
  return break_insn;
}

/* Return a vector of addresses on which the software single step
   breakpoints should be inserted.  NULL means software single step is
   not used.
   Only one breakpoint address will be returned: conditional branches
   will be always evaluated. */
static std::vector<CORE_ADDR>
z80_software_single_step (struct regcache *regcache)
{
  static const int flag_mask[] = {1 << 6, 1 << 0, 1 << 2, 1 << 7};
  gdb_byte buf[8];
  ULONGEST t;
  ULONGEST addr;
  int opcode;
  int size;
  const struct z80_insn_info *info;
  std::vector<CORE_ADDR> ret (1);
  gdbarch *gdbarch = current_inferior ()->arch ();

  regcache->cooked_read (Z80_PC_REGNUM, &addr);
  read_memory (addr, buf, sizeof(buf));
  info = z80_get_insn_info (gdbarch, buf, &size);
  ret[0] = addr + size;
  if (info == NULL) /* possible in case of double prefix */
    { /* forced NOP, TODO: replace by NOP */
      return ret;
    }
  opcode = buf[size - info->size]; /* take opcode instead of prefix */
  /* stage 1: check for conditions */
  switch (info->type)
    {
    case insn_djnz_d:
      regcache->cooked_read (Z80_BC_REGNUM, &t);
      if ((t & 0xff00) != 0x100)
	return ret;
      break;
    case insn_jr_cc_d:
      opcode &= 030; /* JR NZ,d has cc equal to 040, but others 000 */
      [[fallthrough]];
    case insn_jp_cc_nn:
    case insn_call_cc_nn:
    case insn_ret_cc:
      regcache->cooked_read (Z80_AF_REGNUM, &t);
      /* lower bit of condition inverts match, so invert flags if set */
      if ((opcode & 010) != 0)
	t = ~t;
      /* two higher bits of condition field defines flag, so use them only
	 to check condition of "not execute" */
      if (t & flag_mask[(opcode >> 4) & 3])
	return ret;
      break;
    }
  /* stage 2: compute address */
  /* TODO: implement eZ80 MADL support */
  switch (info->type)
    {
    default:
      return ret;
    case insn_djnz_d:
    case insn_jr_d:
    case insn_jr_cc_d:
      addr += size;
      addr += (signed char)buf[size-1];
      break;
    case insn_jp_rr:
      if (size == 1)
	opcode = Z80_HL_REGNUM;
      else
	opcode = (buf[size-2] & 0x20) ? Z80_IY_REGNUM : Z80_IX_REGNUM;
      regcache->cooked_read (opcode, &addr);
      break;
    case insn_jp_nn:
    case insn_jp_cc_nn:
    case insn_call_nn:
    case insn_call_cc_nn:
      addr = buf[size-1] * 0x100 + buf[size-2];
      if (info->size > 3) /* long instruction mode */
	addr = addr * 0x100 + buf[size-3];
      break;
    case insn_rst_n:
      addr = opcode & 070;
      break;
    case insn_ret:
    case insn_ret_cc:
      regcache->cooked_read (Z80_SP_REGNUM, &addr);
      {
	int addr_len = gdbarch_tdep<z80_gdbarch_tdep> (gdbarch)->addr_length;
	read_memory (addr, buf, addr_len);
	addr = extract_unsigned_integer (buf, addr_len,
					 gdbarch_byte_order (gdbarch));
      }
      break;
    }
  ret[0] = addr;
  return ret;
}

/* Cached, dynamically allocated copies of the target data structures: */
static unsigned (*cache_ovly_region_table)[3] = 0;
static unsigned cache_novly_regions;
static CORE_ADDR cache_ovly_region_table_base = 0;
enum z80_ovly_index
  {
    Z80_VMA, Z80_OSIZE, Z80_MAPPED_TO_LMA
  };

static void
z80_free_overlay_region_table (void)
{
  if (cache_ovly_region_table)
    xfree (cache_ovly_region_table);
  cache_novly_regions = 0;
  cache_ovly_region_table = NULL;
  cache_ovly_region_table_base = 0;
}

/* Read an array of ints of size SIZE from the target into a local buffer.
   Convert to host order.  LEN is number of ints.  */

static void
read_target_long_array (CORE_ADDR memaddr, unsigned int *myaddr,
			int len, int size, enum bfd_endian byte_order)
{
  /* alloca is safe here, because regions array is very small. */
  gdb_byte *buf = (gdb_byte *) alloca (len * size);
  int i;

  read_memory (memaddr, buf, len * size);
  for (i = 0; i < len; i++)
    myaddr[i] = extract_unsigned_integer (size * i + buf, size, byte_order);
}

static int
z80_read_overlay_region_table ()
{
  struct gdbarch *gdbarch;
  int word_size;
  enum bfd_endian byte_order;

  z80_free_overlay_region_table ();
  bound_minimal_symbol novly_regions_msym
    = lookup_minimal_symbol (current_program_space, "_novly_regions");
  if (! novly_regions_msym.minsym)
    {
      error (_("Error reading inferior's overlay table: "
	       "couldn't find `_novly_regions'\n"
	       "variable in inferior.  Use `overlay manual' mode."));
      return 0;
    }

  bound_minimal_symbol ovly_region_table_msym
    = lookup_minimal_symbol (current_program_space, "_ovly_region_table");
  if (! ovly_region_table_msym.minsym)
    {
      error (_("Error reading inferior's overlay table: couldn't find "
	       "`_ovly_region_table'\n"
	       "array in inferior.  Use `overlay manual' mode."));
      return 0;
    }

  const enum overlay_debugging_state save_ovly_dbg = overlay_debugging;
  /* prevent infinite recurse */
  overlay_debugging = ovly_off;

  gdbarch = ovly_region_table_msym.objfile->arch ();
  word_size = gdbarch_long_bit (gdbarch) / TARGET_CHAR_BIT;
  byte_order = gdbarch_byte_order (gdbarch);

  cache_novly_regions = read_memory_integer (novly_regions_msym.value_address (),
					     4, byte_order);
  cache_ovly_region_table
    = (unsigned int (*)[3]) xmalloc (cache_novly_regions *
					sizeof (*cache_ovly_region_table));
  cache_ovly_region_table_base
    = ovly_region_table_msym.value_address ();
  read_target_long_array (cache_ovly_region_table_base,
			  (unsigned int *) cache_ovly_region_table,
			  cache_novly_regions * 3, word_size, byte_order);

  overlay_debugging = save_ovly_dbg;
  return 1;                     /* SUCCESS */
}

static int
z80_overlay_update_1 (struct obj_section *osect)
{
  int i;
  asection *bsect = osect->the_bfd_section;
  unsigned lma;
  unsigned vma = bfd_section_vma (bsect);

  /* find region corresponding to the section VMA */
  for (i = 0; i < cache_novly_regions; i++)
    if (cache_ovly_region_table[i][Z80_VMA] == vma)
	break;
  if (i == cache_novly_regions)
    return 0; /* no such region */

  lma = cache_ovly_region_table[i][Z80_MAPPED_TO_LMA];
  i = 0;

  /* we have interest for sections with same VMA */
  for (objfile &objfile : current_program_space->objfiles ())
    for (obj_section &sect : objfile.sections ())
      if (section_is_overlay (&sect))
	{
	  sect.ovly_mapped = (lma == bfd_section_lma (sect.the_bfd_section));
	  i |= sect.ovly_mapped; /* true, if at least one section is mapped */
	}
  return i;
}

/* Refresh overlay mapped state for section OSECT.  */
static void
z80_overlay_update (struct obj_section *osect)
{
  /* Always need to read the entire table anew.  */
  if (!z80_read_overlay_region_table ())
    return;

  /* Were we given an osect to look up?  NULL means do all of them.  */
  if (osect != nullptr && z80_overlay_update_1 (osect))
    return;

  /* Update all sections, even if only one was requested.  */
  for (objfile &objfile : current_program_space->objfiles ())
    for (obj_section &sect : objfile.sections ())
      {
	if (!section_is_overlay (&sect))
	  continue;

	asection *bsect = sect.the_bfd_section;
	bfd_vma lma = bfd_section_lma (bsect);
	bfd_vma vma = bfd_section_vma (bsect);

	for (int i = 0; i < cache_novly_regions; ++i)
	  if (cache_ovly_region_table[i][Z80_VMA] == vma)
	    sect.ovly_mapped =
	      (cache_ovly_region_table[i][Z80_MAPPED_TO_LMA] == lma);
      }
}

/* Return true if the instruction at ADDR is a call; false otherwise.  */
static bool
z80_insn_is_call (struct gdbarch *gdbarch, CORE_ADDR addr)
{
  gdb_byte buf[8];
  int size;
  const struct z80_insn_info *info;
  read_memory (addr, buf, sizeof(buf));
  info = z80_get_insn_info (gdbarch, buf, &size);
  if (info)
    switch (info->type)
      {
      case insn_call_nn:
      case insn_call_cc_nn:
      case insn_rst_n:
	return true;
      }
  return false;
}

/* Return true if the instruction at ADDR is a return; false otherwise. */
static bool
z80_insn_is_ret (struct gdbarch *gdbarch, CORE_ADDR addr)
{
  gdb_byte buf[8];
  int size;
  const struct z80_insn_info *info;
  read_memory (addr, buf, sizeof(buf));
  info = z80_get_insn_info (gdbarch, buf, &size);
  if (info)
    switch (info->type)
      {
      case insn_ret:
      case insn_ret_cc:
	return true;
      }
  return false;
}

/* Return true if the instruction at ADDR is a jump; false otherwise.  */
static bool
z80_insn_is_jump (struct gdbarch *gdbarch, CORE_ADDR addr)
{
  gdb_byte buf[8];
  int size;
  const struct z80_insn_info *info;
  read_memory (addr, buf, sizeof(buf));
  info = z80_get_insn_info (gdbarch, buf, &size);
  if (info)
    switch (info->type)
      {
      case insn_jp_nn:
      case insn_jp_cc_nn:
      case insn_jp_rr:
      case insn_jr_d:
      case insn_jr_cc_d:
      case insn_djnz_d:
	return true;
      }
  return false;
}

static const struct frame_unwind_legacy z80_frame_unwind (
  "z80",
  NORMAL_FRAME,
  FRAME_UNWIND_ARCH,
  default_frame_unwind_stop_reason,
  z80_frame_this_id,
  z80_frame_prev_register,
  NULL, /*unwind_data*/
  default_frame_sniffer
  /*dealloc_cache*/
  /*prev_arch*/
);

/* Initialize the gdbarch struct for the Z80 arch */
static struct gdbarch *
z80_gdbarch_init (struct gdbarch_info info, struct gdbarch_list *arches)
{
  struct gdbarch_list *best_arch;
  tdesc_arch_data_up tdesc_data;
  unsigned long mach = info.bfd_arch_info->mach;
  const struct target_desc *tdesc = info.target_desc;

  if (!tdesc_has_registers (tdesc))
    {
      /* Pick a default target description.  */
      tdesc = tdesc_z80.get ();
    }

  /* Check any target description for validity.  */
  if (tdesc_has_registers (tdesc))
    {
      const struct tdesc_feature *feature;
      int valid_p;

      feature = tdesc_find_feature (tdesc, "org.gnu.gdb.z80.cpu");
      if (feature == NULL)
	return NULL;

      tdesc_data = tdesc_data_alloc ();

      valid_p = 1;

      for (unsigned i = 0; i < Z80_NUM_REGS; i++)
	valid_p &= tdesc_numbered_register (feature, tdesc_data.get (), i,
					    z80_reg_names[i]);

      if (!valid_p)
	return NULL;
    }

  /* If there is already a candidate, use it.  */
  for (best_arch = gdbarch_list_lookup_by_info (arches, &info);
       best_arch != NULL;
       best_arch = gdbarch_list_lookup_by_info (best_arch->next, &info))
    {
      if (mach == gdbarch_bfd_arch_info (best_arch->gdbarch)->mach)
	return best_arch->gdbarch;
    }

  /* None found, create a new architecture from the information provided.  */
  gdbarch *gdbarch
    = gdbarch_alloc (&info, gdbarch_tdep_up (new z80_gdbarch_tdep));
  z80_gdbarch_tdep *tdep = gdbarch_tdep<z80_gdbarch_tdep> (gdbarch);

  if (mach == bfd_mach_ez80_adl)
    {
      tdep->addr_length = 3;
      set_gdbarch_max_insn_length (gdbarch, 6);
    }
  else
    {
      tdep->addr_length = 2;
      set_gdbarch_max_insn_length (gdbarch, 4);
    }

  /* Create a type for PC.  We can't use builtin types here, as they may not
     be defined.  */
  type_allocator alloc (gdbarch);
  tdep->void_type = alloc.new_type (TYPE_CODE_VOID, TARGET_CHAR_BIT,
				    "void");
  tdep->func_void_type = lookup_function_type (tdep->void_type);
  tdep->pc_type = init_pointer_type (alloc,
				     tdep->addr_length * TARGET_CHAR_BIT,
				     NULL, tdep->func_void_type);

  set_gdbarch_short_bit (gdbarch, TARGET_CHAR_BIT);
  set_gdbarch_int_bit (gdbarch, 2 * TARGET_CHAR_BIT);
  set_gdbarch_long_bit (gdbarch, 4 * TARGET_CHAR_BIT);
  set_gdbarch_ptr_bit (gdbarch, tdep->addr_length * TARGET_CHAR_BIT);
  set_gdbarch_addr_bit (gdbarch, tdep->addr_length * TARGET_CHAR_BIT);

  set_gdbarch_num_regs (gdbarch, (mach == bfd_mach_ez80_adl) ? EZ80_NUM_REGS
							     : Z80_NUM_REGS);
  set_gdbarch_sp_regnum (gdbarch, Z80_SP_REGNUM);
  set_gdbarch_pc_regnum (gdbarch, Z80_PC_REGNUM);

  set_gdbarch_register_name (gdbarch, z80_register_name);
  set_gdbarch_register_type (gdbarch, z80_register_type);

  /* TODO: get FP type from binary (extra flags required) */
  set_gdbarch_float_bit (gdbarch, 4 * TARGET_CHAR_BIT);
  set_gdbarch_double_bit (gdbarch, 4 * TARGET_CHAR_BIT);
  set_gdbarch_long_double_bit (gdbarch, 4 * TARGET_CHAR_BIT);
  set_gdbarch_float_format (gdbarch, floatformats_ieee_single);
  set_gdbarch_double_format (gdbarch, floatformats_ieee_single);
  set_gdbarch_long_double_format (gdbarch, floatformats_ieee_single);

  set_gdbarch_return_value (gdbarch, z80_return_value);

  set_gdbarch_skip_prologue (gdbarch, z80_skip_prologue);
  set_gdbarch_inner_than (gdbarch, core_addr_lessthan); // falling stack

  set_gdbarch_get_next_pcs (gdbarch, z80_software_single_step);
  set_gdbarch_breakpoint_kind_from_pc (gdbarch, z80_breakpoint_kind_from_pc);
  set_gdbarch_sw_breakpoint_from_kind (gdbarch, z80_sw_breakpoint_from_kind);
  set_gdbarch_insn_is_call (gdbarch, z80_insn_is_call);
  set_gdbarch_insn_is_jump (gdbarch, z80_insn_is_jump);
  set_gdbarch_insn_is_ret (gdbarch, z80_insn_is_ret);

  set_gdbarch_overlay_update (gdbarch, z80_overlay_update);

  frame_unwind_append_unwinder (gdbarch, &z80_frame_unwind);
  if (tdesc_data)
    tdesc_use_registers (gdbarch, tdesc, std::move (tdesc_data));

  return gdbarch;
}

/* Table to disassemble machine codes without prefix.  */
static const struct z80_insn_info
ez80_main_insn_table[] =
{ /* table with double prefix check */
  { 0100, 0377, 0, insn_force_nop}, //double prefix
  { 0111, 0377, 0, insn_force_nop}, //double prefix
  { 0122, 0377, 0, insn_force_nop}, //double prefix
  { 0133, 0377, 0, insn_force_nop}, //double prefix
  /* initial table for eZ80_z80 */
  { 0100, 0377, 1, insn_z80      }, //eZ80 mode prefix
  { 0111, 0377, 1, insn_z80      }, //eZ80 mode prefix
  { 0122, 0377, 1, insn_adl      }, //eZ80 mode prefix
  { 0133, 0377, 1, insn_adl      }, //eZ80 mode prefix
  /* here common Z80/Z180/eZ80 opcodes */
  { 0000, 0367, 1, insn_default  }, //"nop", "ex af,af'"
  { 0061, 0377, 3, insn_ld_sp_nn }, //"ld sp,nn"
  { 0001, 0317, 3, insn_default  }, //"ld rr,nn"
  { 0002, 0347, 1, insn_default  }, //"ld (rr),a", "ld a,(rr)"
  { 0042, 0347, 3, insn_default  }, //"ld (nn),hl/a", "ld hl/a,(nn)"
  { 0063, 0377, 1, insn_inc_sp   }, //"inc sp"
  { 0073, 0377, 1, insn_dec_sp   }, //"dec sp"
  { 0003, 0303, 1, insn_default  }, //"inc rr", "dec rr", ...
  { 0004, 0307, 1, insn_default  }, //"inc/dec r/(hl)"
  { 0006, 0307, 2, insn_default  }, //"ld r,n", "ld (hl),n"
  { 0020, 0377, 2, insn_djnz_d   }, //"djnz dis"
  { 0030, 0377, 2, insn_jr_d     }, //"jr dis"
  { 0040, 0347, 2, insn_jr_cc_d  }, //"jr cc,dis"
  { 0100, 0300, 1, insn_default  }, //"ld r,r", "halt"
  { 0200, 0300, 1, insn_default  }, //"alu_op a,r"
  { 0300, 0307, 1, insn_ret_cc   }, //"ret cc"
  { 0301, 0317, 1, insn_pop_rr   }, //"pop rr"
  { 0302, 0307, 3, insn_jp_cc_nn }, //"jp cc,nn"
  { 0303, 0377, 3, insn_jp_nn    }, //"jp nn"
  { 0304, 0307, 3, insn_call_cc_nn}, //"call cc,nn"
  { 0305, 0317, 1, insn_push_rr  }, //"push rr"
  { 0306, 0307, 2, insn_default  }, //"alu_op a,n"
  { 0307, 0307, 1, insn_rst_n    }, //"rst n"
  { 0311, 0377, 1, insn_ret      }, //"ret"
  { 0313, 0377, 2, insn_default  }, //CB prefix
  { 0315, 0377, 3, insn_call_nn  }, //"call nn"
  { 0323, 0367, 2, insn_default  }, //"out (n),a", "in a,(n)"
  { 0335, 0337, 1, insn_z80_ddfd }, //DD/FD prefix
  { 0351, 0377, 1, insn_jp_rr    }, //"jp (hl)"
  { 0355, 0377, 1, insn_z80_ed   }, //ED prefix
  { 0371, 0377, 1, insn_ld_sp_rr }, //"ld sp,hl"
  { 0000, 0000, 1, insn_default  }  //others
} ;

static const struct z80_insn_info
ez80_adl_main_insn_table[] =
{ /* table with double prefix check */
  { 0100, 0377, 0, insn_force_nop}, //double prefix
  { 0111, 0377, 0, insn_force_nop}, //double prefix
  { 0122, 0377, 0, insn_force_nop}, //double prefix
  { 0133, 0377, 0, insn_force_nop}, //double prefix
  /* initial table for eZ80_adl */
  { 0000, 0367, 1, insn_default  }, //"nop", "ex af,af'"
  { 0061, 0377, 4, insn_ld_sp_nn }, //"ld sp,Mmn"
  { 0001, 0317, 4, insn_default  }, //"ld rr,Mmn"
  { 0002, 0347, 1, insn_default  }, //"ld (rr),a", "ld a,(rr)"
  { 0042, 0347, 4, insn_default  }, //"ld (Mmn),hl/a", "ld hl/a,(Mmn)"
  { 0063, 0377, 1, insn_inc_sp   }, //"inc sp"
  { 0073, 0377, 1, insn_dec_sp   }, //"dec sp"
  { 0003, 0303, 1, insn_default  }, //"inc rr", "dec rr", ...
  { 0004, 0307, 1, insn_default  }, //"inc/dec r/(hl)"
  { 0006, 0307, 2, insn_default  }, //"ld r,n", "ld (hl),n"
  { 0020, 0377, 2, insn_djnz_d   }, //"djnz dis"
  { 0030, 0377, 2, insn_jr_d     }, //"jr dis"
  { 0040, 0347, 2, insn_jr_cc_d  }, //"jr cc,dis"
  { 0100, 0377, 1, insn_z80      }, //eZ80 mode prefix (short instruction)
  { 0111, 0377, 1, insn_z80      }, //eZ80 mode prefix (short instruction)
  { 0122, 0377, 1, insn_adl      }, //eZ80 mode prefix (long instruction)
  { 0133, 0377, 1, insn_adl      }, //eZ80 mode prefix (long instruction)
  { 0100, 0300, 1, insn_default  }, //"ld r,r", "halt"
  { 0200, 0300, 1, insn_default  }, //"alu_op a,r"
  { 0300, 0307, 1, insn_ret_cc   }, //"ret cc"
  { 0301, 0317, 1, insn_pop_rr   }, //"pop rr"
  { 0302, 0307, 4, insn_jp_cc_nn }, //"jp cc,nn"
  { 0303, 0377, 4, insn_jp_nn    }, //"jp nn"
  { 0304, 0307, 4, insn_call_cc_nn}, //"call cc,Mmn"
  { 0305, 0317, 1, insn_push_rr  }, //"push rr"
  { 0306, 0307, 2, insn_default  }, //"alu_op a,n"
  { 0307, 0307, 1, insn_rst_n    }, //"rst n"
  { 0311, 0377, 1, insn_ret      }, //"ret"
  { 0313, 0377, 2, insn_default  }, //CB prefix
  { 0315, 0377, 4, insn_call_nn  }, //"call Mmn"
  { 0323, 0367, 2, insn_default  }, //"out (n),a", "in a,(n)"
  { 0335, 0337, 1, insn_adl_ddfd }, //DD/FD prefix
  { 0351, 0377, 1, insn_jp_rr    }, //"jp (hl)"
  { 0355, 0377, 1, insn_adl_ed   }, //ED prefix
  { 0371, 0377, 1, insn_ld_sp_rr }, //"ld sp,hl"
  { 0000, 0000, 1, insn_default  }  //others
};

/* ED prefix opcodes table.
   Note the instruction length does include the ED prefix (+ 1 byte)
*/
static const struct z80_insn_info
ez80_ed_insn_table[] =
{
  /* eZ80 only instructions */
  { 0002, 0366, 2, insn_default    }, //"lea rr,ii+d"
  { 0124, 0376, 2, insn_default    }, //"lea ix,iy+d", "lea iy,ix+d"
  { 0145, 0377, 2, insn_default    }, //"pea ix+d"
  { 0146, 0377, 2, insn_default    }, //"pea iy+d"
  { 0164, 0377, 2, insn_default    }, //"tstio n"
  /* Z180/eZ80 only instructions */
  { 0060, 0376, 1, insn_default    }, //not an instruction
  { 0000, 0306, 2, insn_default    }, //"in0 r,(n)", "out0 (n),r"
  { 0144, 0377, 2, insn_default    }, //"tst a, n"
  /* common instructions */
  { 0173, 0377, 3, insn_ld_sp_6nn9 }, //"ld sp,(nn)"
  { 0103, 0307, 3, insn_default    }, //"ld (nn),rr", "ld rr,(nn)"
  { 0105, 0307, 1, insn_ret        }, //"retn", "reti"
  { 0000, 0000, 1, insn_default    }
};

static const struct z80_insn_info
ez80_adl_ed_insn_table[] =
{
  { 0002, 0366, 2, insn_default }, //"lea rr,ii+d"
  { 0124, 0376, 2, insn_default }, //"lea ix,iy+d", "lea iy,ix+d"
  { 0145, 0377, 2, insn_default }, //"pea ix+d"
  { 0146, 0377, 2, insn_default }, //"pea iy+d"
  { 0164, 0377, 2, insn_default }, //"tstio n"
  { 0060, 0376, 1, insn_default }, //not an instruction
  { 0000, 0306, 2, insn_default }, //"in0 r,(n)", "out0 (n),r"
  { 0144, 0377, 2, insn_default }, //"tst a, n"
  { 0173, 0377, 4, insn_ld_sp_6nn9 }, //"ld sp,(nn)"
  { 0103, 0307, 4, insn_default }, //"ld (nn),rr", "ld rr,(nn)"
  { 0105, 0307, 1, insn_ret     }, //"retn", "reti"
  { 0000, 0000, 1, insn_default }
};

/* table for FD and DD prefixed instructions */
static const struct z80_insn_info
ez80_ddfd_insn_table[] =
{
  /* ez80 only instructions */
  { 0007, 0307, 2, insn_default }, //"ld rr,(ii+d)"
  { 0061, 0377, 2, insn_default }, //"ld ii,(ii+d)"
  /* common instructions */
  { 0011, 0317, 1, insn_default }, //"add ii,rr"
  { 0041, 0377, 3, insn_default }, //"ld ii,nn"
  { 0042, 0367, 3, insn_default }, //"ld (nn),ii", "ld ii,(nn)"
  { 0043, 0367, 1, insn_default }, //"inc ii", "dec ii"
  { 0044, 0366, 1, insn_default }, //"inc/dec iih/iil"
  { 0046, 0367, 2, insn_default }, //"ld iih,n", "ld iil,n"
  { 0064, 0376, 2, insn_default }, //"inc (ii+d)", "dec (ii+d)"
  { 0066, 0377, 3, insn_default }, //"ld (ii+d),n"
  { 0166, 0377, 0, insn_default }, //not an instruction
  { 0160, 0370, 2, insn_default }, //"ld (ii+d),r"
  { 0104, 0306, 1, insn_default }, //"ld r,iih", "ld r,iil"
  { 0106, 0307, 2, insn_default }, //"ld r,(ii+d)"
  { 0140, 0360, 1, insn_default }, //"ld iih,r", "ld iil,r"
  { 0204, 0306, 1, insn_default }, //"alu_op a,iih", "alu_op a,iil"
  { 0206, 0307, 2, insn_default }, //"alu_op a,(ii+d)"
  { 0313, 0377, 3, insn_default }, //DD/FD CB dd oo instructions
  { 0335, 0337, 0, insn_force_nop}, //double DD/FD prefix, exec DD/FD as NOP
  { 0341, 0373, 1, insn_default }, //"pop ii", "push ii"
  { 0343, 0377, 1, insn_default }, //"ex (sp),ii"
  { 0351, 0377, 1, insn_jp_rr   }, //"jp (ii)"
  { 0371, 0377, 1, insn_ld_sp_rr}, //"ld sp,ii"
  { 0000, 0000, 0, insn_default }  //not an instruction, exec DD/FD as NOP
};

static const struct z80_insn_info
ez80_adl_ddfd_insn_table[] =
{
  { 0007, 0307, 2, insn_default }, //"ld rr,(ii+d)"
  { 0061, 0377, 2, insn_default }, //"ld ii,(ii+d)"
  { 0011, 0317, 1, insn_default }, //"add ii,rr"
  { 0041, 0377, 4, insn_default }, //"ld ii,nn"
  { 0042, 0367, 4, insn_default }, //"ld (nn),ii", "ld ii,(nn)"
  { 0043, 0367, 1, insn_default }, //"inc ii", "dec ii"
  { 0044, 0366, 1, insn_default }, //"inc/dec iih/iil"
  { 0046, 0367, 2, insn_default }, //"ld iih,n", "ld iil,n"
  { 0064, 0376, 2, insn_default }, //"inc (ii+d)", "dec (ii+d)"
  { 0066, 0377, 3, insn_default }, //"ld (ii+d),n"
  { 0166, 0377, 0, insn_default }, //not an instruction
  { 0160, 0370, 2, insn_default }, //"ld (ii+d),r"
  { 0104, 0306, 1, insn_default }, //"ld r,iih", "ld r,iil"
  { 0106, 0307, 2, insn_default }, //"ld r,(ii+d)"
  { 0140, 0360, 1, insn_default }, //"ld iih,r", "ld iil,r"
  { 0204, 0306, 1, insn_default }, //"alu_op a,iih", "alu_op a,iil"
  { 0206, 0307, 2, insn_default }, //"alu_op a,(ii+d)"
  { 0313, 0377, 3, insn_default }, //DD/FD CB dd oo instructions
  { 0335, 0337, 0, insn_force_nop}, //double DD/FD prefix, exec DD/FD as NOP
  { 0341, 0373, 1, insn_default }, //"pop ii", "push ii"
  { 0343, 0377, 1, insn_default }, //"ex (sp),ii"
  { 0351, 0377, 1, insn_jp_rr   }, //"jp (ii)"
  { 0371, 0377, 1, insn_ld_sp_rr}, //"ld sp,ii"
  { 0000, 0000, 0, insn_default }  //not an instruction, exec DD/FD as NOP
};

/* Return pointer to instruction information structure corresponded to opcode
   in buf.  */
static const struct z80_insn_info *
z80_get_insn_info (struct gdbarch *gdbarch, const gdb_byte *buf, int *size)
{
  int code;
  const struct z80_insn_info *info;
  unsigned long mach = gdbarch_bfd_arch_info (gdbarch)->mach;
  *size = 0;
  switch (mach)
    {
    case bfd_mach_ez80_z80:
      info = &ez80_main_insn_table[4]; /* skip force_nops */
      break;
    case bfd_mach_ez80_adl:
      info = &ez80_adl_main_insn_table[4]; /* skip force_nops */
      break;
    default:
      info = &ez80_main_insn_table[8]; /* skip eZ80 prefixes and force_nops */
      break;
    }
  do
    {
      for (; ((code = buf[*size]) & info->mask) != info->code; ++info)
	;
      *size += info->size;
      /* process instruction type */
      switch (info->type)
	{
	case insn_z80:
	  if (mach == bfd_mach_ez80_z80 || mach == bfd_mach_ez80_adl)
	    info = &ez80_main_insn_table[0];
	  else
	    info = &ez80_main_insn_table[8];
	  break;
	case insn_adl:
	  info = &ez80_adl_main_insn_table[0];
	  break;
	/*  These two (for Game Boy Z80 & Z80 Next CPUs) haven't been tested.

	case bfd_mach_gbz80:
	  info = &gbz80_main_insn_table[0];
	  break;
	case bfd_mach_z80n:
	  info = &z80n_main_insn_table[0];
	  break;
	*/
	case insn_z80_ddfd:
	  if (mach == bfd_mach_ez80_z80 || mach == bfd_mach_ez80_adl)
	    info = &ez80_ddfd_insn_table[0];
	  else
	    info = &ez80_ddfd_insn_table[2];
	  break;
	case insn_adl_ddfd:
	  info = &ez80_adl_ddfd_insn_table[0];
	  break;
	case insn_z80_ed:
	  info = &ez80_ed_insn_table[0];
	  break;
	case insn_adl_ed:
	  info = &ez80_adl_ed_insn_table[0];
	  break;
	case insn_force_nop:
	  return NULL;
	default:
	  return info;
	}
    }
  while (1);
}

#if GDB_SELF_TEST
#include "gdbsupport/selftest.h"
#include "scoped-mock-context.h"
#include "test-target.h"

namespace selftests {

/* Exercise the software stepper with real regcache and target memory reads.
   Only the return address is readable at SP, to catch oversized reads in
   16-bit mode as well as incorrect byte ordering in ADL mode.  */
class z80_step_target : public test_target_ops
{
public:
  gdb_byte code[32] = {};
  gdb_byte stack[3] = {0x57, 0xa9, 0xd1};
  int addr_len = 0;
  ULONGEST stack_bytes_read = 0;

  target_xfer_status xfer_partial (target_object object, const char *annex,
				  gdb_byte *readbuf, const gdb_byte *writebuf,
				  ULONGEST offset, ULONGEST len,
				  ULONGEST *xfered_len) override
  {
    if (object != TARGET_OBJECT_MEMORY || readbuf == nullptr)
      return TARGET_XFER_E_IO;
    if (offset >= 0x1000 && offset + len <= 0x1000 + sizeof (code))
      memcpy (readbuf, code + offset - 0x1000, len);
    else if (offset >= 0x2000 && offset + len <= 0x2000 + addr_len)
      {
	memcpy (readbuf, stack + offset - 0x2000, len);
	stack_bytes_read += len;
      }
    else
      return TARGET_XFER_E_IO;
    *xfered_len = len;
    return TARGET_XFER_OK;
  }
};

static void
z80_step_ret_test ()
{
  for (unsigned long mach : {bfd_mach_z80, bfd_mach_ez80_z80,
			     bfd_mach_ez80_adl})
    {
      gdbarch_info info;
      info.bfd_arch_info = bfd_lookup_arch (bfd_arch_z80, mach);
      info.byte_order = BFD_ENDIAN_LITTLE;
      gdbarch *arch = gdbarch_find_by_info (info);
      SELF_CHECK (arch != nullptr);
      scoped_mock_context<z80_step_target> ctx (arch);
      ctx.mock_target.addr_len
	= gdbarch_tdep<z80_gdbarch_tdep> (arch)->addr_length;
      regcache *regs = get_thread_arch_regcache (&ctx.mock_inferior,
						ctx.mock_ptid, arch);
      gdb_byte value[3];
      store_unsigned_integer (value, ctx.mock_target.addr_len,
			      BFD_ENDIAN_LITTLE, 0x1000);
      regs->raw_supply (Z80_PC_REGNUM, value);
      store_unsigned_integer (value, ctx.mock_target.addr_len,
			      BFD_ENDIAN_LITTLE, 0x2000);
      regs->raw_supply (Z80_SP_REGNUM, value);
      CORE_ADDR destination = mach == bfd_mach_ez80_adl ? 0xd1a957 : 0xa957;

      /* RET, RETN, RETI, and both outcomes of all eight conditional RETs.  */
      for (int condition = -3; condition < 8; ++condition)
	for (bool taken : {false, true})
	  {
	    if (condition < 0 && !taken)
	      continue;
	    memset (ctx.mock_target.code, 0, sizeof (ctx.mock_target.code));
	    int size = condition < -1 ? 2 : 1;
	    ctx.mock_target.code[0] = size == 2 ? 0xed
	      : condition == -1 ? 0xc9 : 0xc0 + condition * 8;
	    if (size == 2)
	      ctx.mock_target.code[1] = condition == -3 ? 0x45 : 0x4d;
	    const int flags[] = {0x40, 0x01, 0x04, 0x80};
	    int af = condition < 0 ? 0
	      : (((condition & 1) != 0) == taken ? flags[condition / 2] : 0);
	    store_unsigned_integer (value, register_size (arch, Z80_AF_REGNUM),
				    BFD_ENDIAN_LITTLE, af);
	    regs->raw_supply (Z80_AF_REGNUM, value);
	    ctx.mock_target.stack_bytes_read = 0;
	    std::vector<CORE_ADDR> next = z80_software_single_step (regs);
	    SELF_CHECK (next.size () == 1);
	    SELF_CHECK (next[0] == (taken ? destination : 0x1000 + size));
	    SELF_CHECK (ctx.mock_target.stack_bytes_read
			== (taken ? ctx.mock_target.addr_len : 0));
	  }
    }
}

/* LLVM and SDCC frame setup, in both register widths.  Every instruction
   boundary (and every truncated instruction) must stay within the read.  */
static void
z80_prologue_test ()
{
  for (unsigned long mach : {bfd_mach_z80, bfd_mach_ez80_z80,
			     bfd_mach_ez80_adl})
    {
      gdbarch_info arch_info;
      arch_info.bfd_arch_info = bfd_lookup_arch (bfd_arch_z80, mach);
      arch_info.byte_order = BFD_ENDIAN_LITTLE;
      gdbarch *arch = gdbarch_find_by_info (arch_info);
      scoped_mock_context<z80_step_target> ctx (arch);
      int width = gdbarch_tdep<z80_gdbarch_tdep> (arch)->addr_length;
      for (int state = 0; state < 3; ++state)
	for (bool reset_sp : {false, true})
	  for (bool use_iy : {false, true})
	    {
	      std::vector<gdb_byte> code;
	      if (state == 1)
		code = {0xed, 0x57, 0xf3, 0xf5};
	      else if (state == 2)
		code = {0xf5, 0xc5, 0xd5, 0xe5, 0xfd, 0xe5};
	      code.insert (code.end (), {0xdd, 0xe5, 0xdd, 0x21});
	      code.insert (code.end (), width, 0);
	      code.insert (code.end (), {0xdd, 0x39});
	      int frame_len = code.size ();
	      if (reset_sp)
		code.insert (code.end (), {0xdd, 0xf9});
	      if (use_iy)
		code.push_back (0xfd);
	      code.push_back (0x21);
	      code.push_back (0xf4); /* Allocate twelve bytes.  */
	      code.insert (code.end (), width - 1, 0xff);
	      if (use_iy)
		code.insert (code.end (), {0xfd, 0x39, 0xfd, 0xf9});
	      else
		code.insert (code.end (), {0x39, 0xf9});
	      memcpy (ctx.mock_target.code, code.data (), code.size ());
	      for (int len = 0; len <= code.size (); ++len)
		{
		  z80_unwind_cache cache {};
		  trad_frame_saved_reg saved[Z80_NUM_REGS];
		  cache.saved_regs = saved;
		  int end = z80_scan_prologue (arch, 0x1000,
					      0x1000 + len, &cache);
		  SELF_CHECK (end <= 0x1000 + len);
		  SELF_CHECK (cache.prologue_type.fp_sdcc
			      == (len >= frame_len));
		  if (len == code.size ())
		    {
		      int slots = state == 2 ? 6 : state == 1 ? 2 : 1;
		      SELF_CHECK (end == 0x1000 + len);
		      SELF_CHECK (cache.size == 12);
		      SELF_CHECK (cache.state_size == slots * width);
		      SELF_CHECK (saved[Z80_IX_REGNUM].addr () == slots);
		      if (state == 2)
			{
			  SELF_CHECK (saved[Z80_AF_REGNUM].addr () == 1);
			  SELF_CHECK (saved[Z80_IY_REGNUM].addr () == 5);
			}
		    }
		}
	    }
      const gdb_byte args[] = {0xf1, 0xd1, 0xe1, 0xc1,
			       0xc5, 0xe5, 0xd5, 0xf5};
      memcpy (ctx.mock_target.code, args, sizeof (args));
      {
	z80_unwind_cache cache {};
	trad_frame_saved_reg saved[Z80_NUM_REGS];
	cache.saved_regs = saved;
	SELF_CHECK (z80_scan_prologue (arch, 0x1000,
				      0x1000 + sizeof (args), &cache)
		    == 0x1000 + sizeof (args));
	SELF_CHECK (cache.prologue_type.load_args);
	SELF_CHECK (cache.size == 0);
      }
      /* Saving IX alone must not make the caller's IX this frame's base.  */
      ctx.mock_target.code[0] = 0xdd;
      ctx.mock_target.code[1] = 0xe5;
      z80_unwind_cache cache {};
      trad_frame_saved_reg saved[Z80_NUM_REGS];
      cache.saved_regs = saved;
      SELF_CHECK (z80_scan_prologue (arch, 0x1000, 0x1002, &cache) == 0x1002);
      SELF_CHECK (!cache.prologue_type.fp_sdcc);
      SELF_CHECK (cache.state_size == width);
      SELF_CHECK (saved[Z80_IX_REGNUM].addr () == 1);
    }
}

static void
z80_return_value_test ()
{
  for (unsigned long mach : {bfd_mach_z80, bfd_mach_ez80_z80,
			     bfd_mach_ez80_adl})
    {
      gdbarch_info info;
      info.bfd_arch_info = bfd_lookup_arch (bfd_arch_z80, mach);
      info.byte_order = BFD_ENDIAN_LITTLE;
      gdbarch *arch = gdbarch_find_by_info (info);
      scoped_mock_context<z80_step_target> ctx (arch);
      regcache *regs = get_thread_arch_regcache (&ctx.mock_inferior,
						ctx.mock_ptid, arch);
      gdb_byte zero[3] {};
      regs->raw_supply (Z80_HL_REGNUM, zero);
      regs->raw_supply (Z80_DE_REGNUM, zero);
      int width = gdbarch_tdep<z80_gdbarch_tdep> (arch)->addr_length;
      auto *types = builtin_type (arch);
      for (type *type : {types->builtin_uint8, types->builtin_uint16,
			 types->builtin_uint24, types->builtin_uint32})
	{
	  gdb_byte input[] = {0x56, 0x34, 0x12, 0x78};
	  gdb_byte output[4] {};
	  int len = type->length ();
	  SELF_CHECK (z80_return_value (arch, nullptr, type, regs, nullptr,
					input) == RETURN_VALUE_REGISTER_CONVENTION);
	  ULONGEST hl, de;
	  regs->cooked_read (Z80_HL_REGNUM, &hl);
	  regs->cooked_read (Z80_DE_REGNUM, &de);
	  SELF_CHECK (hl == extract_unsigned_integer (input,
			  std::min (len, width), BFD_ENDIAN_LITTLE));
	  if (len > width)
	    SELF_CHECK (de == extract_unsigned_integer (input + width,
			    len - width, BFD_ENDIAN_LITTLE));
	  z80_return_value (arch, nullptr, type, regs, output, nullptr);
	  SELF_CHECK (memcmp (input, output, len) == 0);
	  regs->raw_supply (Z80_HL_REGNUM, zero);
	  regs->raw_supply (Z80_DE_REGNUM, zero);
	}
    }
}

} /* namespace selftests */
#endif /* GDB_SELF_TEST */

INIT_GDB_FILE (z80_tdep)
{
  gdbarch_register (bfd_arch_z80, z80_gdbarch_init);
  initialize_tdesc_z80 ();
#if GDB_SELF_TEST
  selftests::register_test ("z80-step-ret", selftests::z80_step_ret_test);
  selftests::register_test ("z80-prologue", selftests::z80_prologue_test);
  selftests::register_test ("z80-return-value", selftests::z80_return_value_test);
#endif
}
