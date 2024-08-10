/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      Instruction decoder
 *
 */
#include "necv850.hpp"

static const int bcond_map[16] =
{
  NEC850_BV,   NEC850_BL,
  NEC850_BZ,   NEC850_BNH,
  NEC850_BN,   NEC850_BR,
  NEC850_BLT,  NEC850_BLE,
  NEC850_BNV,  NEC850_BNC,
  NEC850_BNZ,  NEC850_BH,
  NEC850_BP,   NEC850_BSA,
  NEC850_BGE,  NEC850_BGT
};

//------------------------------------------------------------------------
// The instruction formats 5 to 10 have bit10 and bit9 on and are a word
// The rest of the instructions are half-word and their format is 1 to 4
int detect_inst_len(uint16 w)
{
  return ((w & 0x600) == 0x600) ? 4 : 2;
}

//------------------------------------------------------------------------
// Fetchs an instruction (uses ua_next_xxx(insn)) of a correct size (ready for decoding)
// Returns the size of the instruction
int fetch_instruction(uint32 *w, insn_t &insn)
{
  uint16 hw = insn.get_next_word();
  int r = detect_inst_len(hw);
  if ( r == 4 )
    *w = (insn.get_next_word() << 16) | hw;
  else
    *w = hw;
  return r;
}

//------------------------------------------------------------------------
static sval_t fetch_disp32(const uint32 w, insn_t &ins)
{
  // 15             0 31            16 47            32
  // xxxxxxxxxxxxxxxx ddddddddddddddd0 DDDDDDDDDDDDDDDD
  uint32 d_low = (w >> 16);// ddddddddddddddd0
  if ( ins.size == 2 )
    d_low = ins.get_next_word();
  else if ( ins.size != 4 )
  {
    // bad format
    ins.size = 0;
    ins.itype = 0;
    return 1;
  }
  uint16 d_high = ins.get_next_word(); // DDDDDDDDDDDDDDDD
  int32 addr = (d_high<<16) | d_low;
  return sval_t(addr);
}

//------------------------------------------------------------------------
static bool decode_disp23(const uint32 w, insn_t &ins, int opidx, op_dtype_t dt)
{
  // LD.B disp23 [reg1] , reg3
  // 00000111100RRRRR wwwwwddddddd0101 DDDDDDDDDDDDDDDD
  // ddddddd is the lower 7 bits of disp23.
  // DDDDDDDDDDDDDDDD is the higher 16 bits of disp23
  // LD.H disp23[reg1], reg3
  // 00000111100RRRRR wwwwwdddddd00111 DDDDDDDDDDDDDDDD
  // dddddd is the lower side bits 6 to 1 of disp23.
  // DDDDDDDDDDDDDDDD is the higher 16 bits of disp23.

  // we need at least 32 bits of opcode here
  if ( ins.size != 4 )
    return false;

  uint16 d_low = ( w >> 20 ) & 0x7F; // ddddddd
  if ( dt != dt_byte && ( d_low & 1 ) != 0 )
    return false;
  uint16 d_high = ins.get_next_word(); // DDDDDDDDDDDDDDDD
  sval_t addr = ( d_high << 7 ) | d_low;
  SIGN_EXTEND(sval_t, addr, 23);

  op_t &op = ins.ops[opidx];
  op.type = o_displ;
  op.reg = w & 0x1F;
  op.addr = addr;
  op.dtype = dt;
  op.specflag1 = N850F_USEBRACKETS | N850F_OUTSIGNED | N850F_VAL32;
  return true;
}

//------------------------------------------------------------------------
static void set_opreg(op_t &op, int reg, op_dtype_t dtyp = dt_dword)
{
  op.type = o_reg;
  op.dtype = dtyp;
  op.reg = reg;
}

//----------------------------------------------------------------------
// Create operand of condition type
inline void set_opcond(op_t &x, uval_t value)
{
  x.type = o_cond;
  x.dtype = dt_qword;
  x.value = value;
}


//------------------------------------------------------------------------
static void set_opimm(op_t &op, uval_t value, int dtyp = dt_dword)
{
  op.type = o_imm;
  op.dtype = dtyp;
  op.value = value;
}

//------------------------------------------------------------------------
// Decodes an instruction "w" into cmd structure
bool nec850_t::decode_coprocessor(const uint32 w, insn_t &ins) const
{ // 11111  1            33222 2 222 22 2111 1
  // 54321  098765 43210 10987 6 543 21 0987 6
  // reg2  |opcode|reg1 |reg3 |b|cat|ty|subo|b|
  // ..... |111111|.....|.....|1|...|..|....|0|
  int r1 = w & 0x1F;
  int r2 = ( w & 0xF800 ) >> 11;
  int r3 = ( w & 0xF8000000 ) >> 27;
  int cat = ( w >> 23 ) & 7;
  int typ = ( w >> 21 ) & 3;
  int subop = ( w >> 17 ) & 0xF;
  ins.itype = NEC850_NULL;
  // we only support V850E2M and RH850 FP instructions
  if ( !is_v850e2m() )
    return false;
  if ( typ == 0 && cat == 0 )
  {
    // CMOVF.D: cat = 000, type = 00, subop = 1fff, reg3 != 0
    // CMOVF.S : cat = 000, type = 00, subop = 0fff, reg3 != 0
    // TRFSR: cat = 000, type = 00, subop = 0fff, reg1 = 0, reg3 = 0
    if ( r3 != 0 )
    {
      // CMOVF.S|D fcbit, reg1, reg2, reg3
      ins.itype = ( subop & 8 ) ? NEC850_CMOVF_D : NEC850_CMOVF_S;
      int fcbit = subop & 7;
      set_opimm(ins.Op1, fcbit);
      set_opreg(ins.Op2, r1);
      set_opreg(ins.Op3, r2);
      set_opreg(ins.Op4, r3);
    }
    else if ( subop < 8 )
    {
      ins.itype = NEC850_TRFSR;
      int fcbit = subop & 7;
      set_opimm(ins.Op1, fcbit);
    }
  }
  else if ( typ == 1 && cat == 0 && r3 < 0x10 )
  {
    // CMPF.D:  cat = 000, type = 01, subop = 1fff, reg3 = 0FFFF
    // CMPF.S : cat = 000, type = 01, subop = 0fff, reg3 = 0FFFF
    // CMPF.S|D fcond, reg2, reg1, fcbit
    ins.itype = ( subop & 8 ) ? NEC850_CMPF_D : NEC850_CMPF_S;
    int fcbit = subop & 7;
    set_opcond(ins.Op1, r3);
    set_opreg(ins.Op2, r2);
    set_opreg(ins.Op3, r1);
    set_opimm(ins.Op4, fcbit);
  }
  else if ( typ == 3 )
  {
    // reg1, reg2, reg3
    if ( cat == 0 )
    {
      switch ( subop & 7 )
      {
        case 0:
          ins.itype = ( subop & 8 ) ? NEC850_ADDF_D : NEC850_ADDF_S;
          break;
        case 1:
          ins.itype = ( subop & 8 ) ? NEC850_SUBF_D : NEC850_SUBF_S;
          break;
        case 2:
          ins.itype = ( subop & 8 ) ? NEC850_MULF_D : NEC850_MULF_S;
          break;
        case 4:
          ins.itype = ( subop & 8 ) ? NEC850_MAXF_D : NEC850_MAXF_S;
          break;
        case 5:
          ins.itype = ( subop & 8 ) ? NEC850_MINF_D : NEC850_MINF_S;
          break;
        case 7:
          ins.itype = ( subop & 8 ) ? NEC850_DIVF_D : NEC850_DIVF_S;
          break;

      }
    }
    else if ( cat == 1 && subop < 4 )
    {
      if ( is_rh850() )
      {
        uint16 itypes[] = { NEC850_FMAF_S, NEC850_FMSF_S, NEC850_FNMAF_S, NEC850_FNMSF_S };
        ins.itype = itypes[subop];
      }
    }
    if ( ins.itype != NEC850_NULL )
    {
      bool dbl = ( subop & 8 ) != 0;
      op_dtype_t dt = dbl ? dt_double : dt_float;
      set_opreg(ins.Op1, r1, dt);
      set_opreg(ins.Op2, r2, dt);
      set_opreg(ins.Op3, r3, dt);
    }
  }
  else if ( typ == 2 && cat == 0 )
  {
    // reg2, reg3 conversions
    op_dtype_t dtsrc = dt_float, dtdst = dt_float;
    switch ( subop )
    {
      case 0:
        {
          // ROUNDF.SW cat = 0 type = 2 subop = 0 reg1 = 0
          // TRNCF.SW cat = 0 type = 2 subop = 0 reg1 = 1
          // CEILF.SW cat = 0 type = 2 subop = 0 reg1 = 2
          // FLOORF.SW cat = 0 type = 2 subop = 0 reg1 = 3
          // CVTF.SW cat = 0 type = 2 subop = 0 reg1 = 4
          // ROUNDF.SUW cat = 0 type = 2 subop = 0 reg1 = 16
          // TRNCF.SUW cat = 0 type = 2 subop = 0 reg1 = 17
          // CEILF.SUW cat = 0 type = 2 subop = 0 reg1 = 18
          // FLOORF.SUW cat = 0 type = 2 subop = 0 reg1 = 19
          // CVTF.SUW cat = 0 type = 2 subop = 0 reg1 = 20
          static const int ops[] =
          {
            NEC850_ROUNDF_SW, NEC850_TRNCF_SW, NEC850_CEILF_SW, NEC850_FLOORF_SW, // 0-3
            NEC850_CVTF_SW, NEC850_NULL, NEC850_NULL, NEC850_NULL,  // 4-7
            NEC850_NULL, NEC850_NULL, NEC850_NULL, NEC850_NULL, // 8-11
            NEC850_NULL, NEC850_NULL, NEC850_NULL, NEC850_NULL, // 12-15
            NEC850_ROUNDF_SUW, NEC850_TRNCF_SUW, NEC850_CEILF_SUW, NEC850_FLOORF_SUW, // 16-19
            NEC850_CVTF_SUW  // 20
          };
          if ( r1 < qnumber(ops) )
            ins.itype = ops[r1];
          dtsrc = dt_float;
          dtdst = dt_dword;
        }
        break;
      case 1:
        {
          // CVTF.WS cat=0 type=2 subop=1 reg1=0   dw f
          // CVTF.LS cat=0 type=2 subop=1 reg1=1   dq f
          // CVTF.HS cat=0 type=2 subop=1 reg1=2   h f
          // CVTF.SH cat=0 type=2 subop=1 reg1=3   f h
          // CVTF.UWS cat=0 type=2 subop=1 reg1=16 dw f
          // CVTF.ULS cat=0 type=2 subop=1 reg1=17 dq f
          static const int ops[] =
          {
            NEC850_CVTF_WS, NEC850_CVTF_LS, NEC850_CVTF_HS, NEC850_CVTF_SH, // 0-3
            NEC850_CVTF_SW, NEC850_NULL, NEC850_NULL, NEC850_NULL,  // 4-7
            NEC850_NULL, NEC850_NULL, NEC850_NULL, NEC850_NULL, // 8-11
            NEC850_NULL, NEC850_NULL, NEC850_NULL, NEC850_NULL, // 12-15
            NEC850_CVTF_UWS, NEC850_CVTF_ULS // 16-17
          };
          if ( r1 < qnumber(ops) )
            ins.itype = ops[r1];
          // NB: we use dt_float for half-precision
          op_dtype_t srct[] = { dt_dword, dt_qword, dt_float, dt_float };
          dtsrc = srct[r1&3];
          dtdst = dt_float;
        }
        break;
      case 2:
        {
          // ROUNDF.SL cat=0 type=2 subop=2 reg1=0
          // TRNCF.SL cat=0 type=2 subop=2 reg1=1
          // CEILF.SL cat=0 type=2 subop=2 reg1=2
          // FLOORF.SL cat=0 type=2 subop=2 reg1=3
          // CVTF.SL cat=0 type=2 subop=2 reg1=4
          // ROUNDF.SUL cat=0 type=2 subop=2 reg1=16
          // TRNCF.SUL cat=0 type=2 subop=2 reg1=17
          // CEILF.SUL cat=0 type=2 subop=2 reg1=18
          // FLOORF.SUL cat=0 type=2 subop=2 reg1=19
          // CVTF.SUL cat=0 type=2 subop=2 reg1=20
          static const int ops[] =
          {
            NEC850_ROUNDF_SL, NEC850_TRNCF_SL, NEC850_CEILF_SL, NEC850_FLOORF_SL, // 0-3
            NEC850_CVTF_SL, NEC850_NULL, NEC850_NULL, NEC850_NULL,  // 4-7
            NEC850_NULL, NEC850_NULL, NEC850_NULL, NEC850_NULL, // 8-11
            NEC850_NULL, NEC850_NULL, NEC850_NULL, NEC850_NULL, // 12-15
            NEC850_ROUNDF_SUL, NEC850_TRNCF_SUL, NEC850_CEILF_SUL, NEC850_FLOORF_SUL, // 16-19
            NEC850_CVTF_SUL  // 20
          };
          if ( r1 < qnumber(ops) )
            ins.itype = ops[r1];
          dtsrc = dt_float;
          dtdst = dt_qword;
        }
        break;
      case 4:
      case 12:
        {
          // ABSF.S cat = 0 type = 2 subop = 4 reg1 = 0
          // NEGF.S cat = 0 type = 2 subop = 4 reg1 = 1
          // ABSF.D cat = 0 type = 2 subop = 12 reg1 = 0
          // NEGF.D cat = 0 type = 2 subop = 12 reg1 = 1
          if ( r1 == 0 )
            ins.itype = subop == 4 ? NEC850_ABSF_S : NEC850_ABSF_D;
          else if ( r1 == 1 )
            ins.itype = subop == 4 ? NEC850_NEGF_S : NEC850_NEGF_D;

          dtsrc = subop == 4 ? dt_float: dt_double;
          dtdst = dtsrc;
        }
        break;
      case 7:
      case 15:
        {
          // SQRTF.S cat=0 type=2 subop=7 reg1=0
          // RECIPF.S cat=0 type=2 subop=7 reg1=1
          // RSQRTF.S cat=0 type=2 subop=7 reg1=2
          // SQRTF.D cat=0 type=2 subop=15 reg1=0
          // RECIPF.D cat=0 type=2 subop=15 reg1=1
          // RSQRTF.D cat=0 type=2 subop=15 reg1=2

          if ( r1 == 0 )
            ins.itype = subop == 7 ? NEC850_SQRTF_S : NEC850_SQRTF_D;
          else if ( r1 == 1 )
            ins.itype = subop == 7 ? NEC850_RECIPF_S : NEC850_RECIPF_D;
          else if ( r1 == 2 )
            ins.itype = subop == 7 ? NEC850_RSQRTF_S : NEC850_RSQRTF_D;

          dtsrc = subop == 7 ? dt_float : dt_double;
          dtdst = dtsrc;
        }
        break;
      case 8:
        {
          // ROUNDF.DW cat=0 type=2 subop=8 reg1=0
          // TRNCF.DW cat=0 type=2 subop=8 reg1=1
          // CEILF.DW cat=0 type=2 subop=8 reg1=2
          // FLOORF.DW cat=0 type=2 subop=8 reg1=3
          // CVTF.DW cat=0 type=2 subop=8 reg1=4
          // TRNCF.DUW cat=0 type=2 subop=8 reg1=17
          // CEILF.DUW cat=0 type=2 subop=8 reg1=18
          // FLOORF.DUW cat=0 type=2 subop=8 reg1=19
          // CVTF.DUW cat=0 type=2 subop=8 reg1=20
          static const int ops[] =
          {
            NEC850_ROUNDF_DW, NEC850_TRNCF_DW, NEC850_CEILF_DW, NEC850_FLOORF_DW, // 0-3
            NEC850_CVTF_DW, NEC850_NULL, NEC850_NULL, NEC850_NULL,  // 4-7
            NEC850_NULL, NEC850_NULL, NEC850_NULL, NEC850_NULL, // 8-11
            NEC850_NULL, NEC850_NULL, NEC850_NULL, NEC850_NULL, // 12-15
            NEC850_ROUNDF_DUW, NEC850_TRNCF_DUW, NEC850_CEILF_DUW, NEC850_FLOORF_DUW, // 16-19
            NEC850_CVTF_DUW  // 20
          };
          if ( r1 < qnumber(ops) )
            ins.itype = ops[r1];
          dtsrc = dt_double;
          dtdst = dt_dword;
        }
        break;
      case 9:
        {
          // CVTF.WD cat=0 type=2 subop=9 reg1=0 dw d
          // CVTF.LD cat=0 type=2 subop=9 reg1=1 dq d
          // CVTF.SD cat=0 type=2 subop=9 reg1=2 f d
          // CVTF.DS cat=0 type=2 subop=9 reg1=3 d f
          // CVTF.UWD cat=0 type=2 subop=9 reg1=16 dw d
          // CVTF.ULD cat=0 type=2 subop=9 reg1=17 dq d
          static const int ops[] =
          {
            NEC850_CVTF_WD, NEC850_CVTF_LD, NEC850_CVTF_SD, NEC850_CVTF_DS, // 0-3
            NEC850_NULL, NEC850_NULL, NEC850_NULL, NEC850_NULL,  // 4-7
            NEC850_NULL, NEC850_NULL, NEC850_NULL, NEC850_NULL, // 8-11
            NEC850_NULL, NEC850_NULL, NEC850_NULL, NEC850_NULL, // 12-15
            NEC850_CVTF_UWD, NEC850_CVTF_ULD  // 16-17
          };
          if ( r1 < qnumber(ops) )
            ins.itype = ops[r1];
          op_dtype_t srct[] = { dt_dword, dt_qword, dt_float, dt_double };
          dtsrc = srct[r1 & 3];
          dtdst = r1 == 3 ? dt_float : dt_double;
        }
        break;
      case 10:
        {
          // ROUNDF.DL cat=0 type=2 subop=10 reg1=0
          // TRNCF.DL cat=0 type=2 subop=10 reg1=1
          // CEILF.DL cat=0 type=2 subop=10 reg1=2
          // FLOORF.DL cat=0 type=2 subop=10 reg1=3
          // CVTF.DL cat=0 type=2 subop=10 reg1=4
          // ROUNDF.DUL cat=0 type=2 subop=10 reg1=4
          // TRNCF.DUL cat=0 type=2 subop=10 reg1=17
          // CEILF.DUL cat=0 type=2 subop=10 reg1=18
          // FLOORF.DUL cat=0 type=2 subop=10 reg1=19
          // CVTF.DUL cat=0 type=2 subop=10 reg1=20
          static const int ops[] =
          {
            NEC850_ROUNDF_DL, NEC850_TRNCF_DL, NEC850_CEILF_DL, NEC850_FLOORF_DL, // 0-3
            NEC850_CVTF_DL, NEC850_NULL, NEC850_NULL, NEC850_NULL, // 4-7
            NEC850_NULL, NEC850_NULL, NEC850_NULL, NEC850_NULL, // 8-11
            NEC850_NULL, NEC850_NULL, NEC850_NULL, NEC850_NULL, // 12-15
            NEC850_ROUNDF_DUL, NEC850_TRNCF_DUL, NEC850_CEILF_DUL, NEC850_FLOORF_DUL, // 16-19
            NEC850_CVTF_DUL // 20
          };
          if ( r1 < qnumber(ops) )
            ins.itype = ops[r1];

          dtsrc = dt_double;
          dtdst = dt_qword;
        }
        break;
    }
    if ( ins.itype != NEC850_NULL )
    {
      set_opreg(ins.Op1, r2, dtsrc);
      set_opreg(ins.Op2, r3, dtdst);
    }
  }
  if ( ins.itype == NEC850_NULL && is_v850e2m() && ( cat >> 1 ) == 1 )
  {
    // reg1, reg2, reg3, reg4
    // MADDF.S: cat = 01W type = 00, subop = WWWW
    // MSUBF.S : cat = 01W type = 01, subop = WWWW
    // NMADDF.S : cat = 01W type = 10, subop = WWWW
    // NMSUBF.S : cat = 01W type = 11, subop = WWWW
    // WWWWW: reg4. (The least significant bit of reg4 is bit 23.)

    int r4 = (subop << 1) | (cat & 1);
    static const uint16 itypes[] = { NEC850_MADDF_S, NEC850_MSUBF_S, NEC850_NMADDF_S, NEC850_NMSUBF_S };
    ins.itype = itypes[typ];
    set_opreg(ins.Op1, r1, dt_float);
    set_opreg(ins.Op2, r2, dt_float);
    set_opreg(ins.Op3, r3, dt_float);
    set_opreg(ins.Op4, r4, dt_float);
  }


  if ( ins.itype != NEC850_NULL )
  {
    ins.auxpref |= N850F_FP;
    return true;
  }
  return false;
}

  //------------------------------------------------------------------------
// Decodes an instruction "w" into cmd structure
bool nec850_t::decode_instruction(const uint32 w, insn_t &ins)
{
#define PARSE_L12 (((w & 1) << 11) | (w >> 21))
#define PARSE_R1  (w & 0x1F)
#define PARSE_R2  ((w & 0xF800) >> 11)

  typedef struct
  {
    int itype;
    int flags;
  } itype_flags_t;
  // If an instruction deals with displacement it should
  // initialize this pointer to the operand location.
  // At the end we will transform the operand to o_mem
  // if we know how to resolve its address
  op_t *displ_op = nullptr;

  do
  {
    uint32 op;

    //
    // Format I
    //
    op = (w & 0x7E0) >> 5; // Take bit5->bit10
    if ( op <= 0xF )
    {
      static const int inst_1[] =
      {
        /* MOV reg1, reg2 */ NEC850_MOV,             /* NOT reg1, reg2 */ NEC850_NOT,
        /* DIVH  reg1, reg2 */ NEC850_DIVH,          /* JMP [reg1] */ NEC850_JMP,
        /* SATSUBR reg1, reg2 */ NEC850_SATSUBR,     /* SATSUB reg1, reg2 */ NEC850_SATSUB,
        /* SATADD reg1, reg2 */ NEC850_SATADD,       /* MULH reg1, reg2 */ NEC850_MULH,
        /* OR reg1, reg2 */ NEC850_OR,               /* XOR reg1, reg2 */ NEC850_XOR,
        /* AND reg1, reg2 */ NEC850_AND,             /* TST reg1, reg2 */ NEC850_TST,
        /* SUBR reg1, reg2 */ NEC850_SUBR,           /* SUB reg1, reg2 */ NEC850_SUB,
        /* ADD reg1, reg2 */ NEC850_ADD,             /* CMP reg1, reg2 */ NEC850_CMP
      };

      //
      // NOP, Equivalent to MOV R, r (where R=r=0)
      if ( w == 0 )
      {
        ins.itype     = NEC850_NOP;
        ins.Op1.type  = o_void;
        ins.Op1.dtype = dt_void;
        break;
      }

      uint16 r1 = PARSE_R1;
      uint16 r2 = PARSE_R2;
      if ( is_v850e() && op == 2 && r1 == 0 )
      {
        switch ( r2 )
        {
          case 0:
            if ( is_v850e2m() )
              ins.itype = NEC850_RIE;
            break;
          case 0x1C:
            if ( is_rh850() )
              ins.itype = NEC850_DBHVTRAP;
            break;
          case 0x1D:
            if ( is_rh850() )
              ins.itype = NEC850_DBCP;
            break;
          case 0x1E:
            if ( is_v850e2m() )
              ins.itype = NEC850_RMTRAP;
            break;
          case 0x1F:
            ins.itype = NEC850_DBTRAP;
            break;
          default:
            if ( is_v850e2() && r2 < 0x10 )
            {
              ins.itype = NEC850_FETRAP;
              set_opimm(ins.Op1, r2);
            }
            break;
        }
        if ( ins.itype != 0 )
          break;
      }

      ins.itype = inst_1[op];
      set_opreg(ins.Op1, r1);

      if ( is_v850e() )
      {
        if ( r2 == 0 )
        {
          if ( is_v850e2m() && op == 0 )
          {
            switch ( r1 )
            {
              case 0x1C:
                if ( is_rh850() )
                  ins.itype = NEC850_SYNCI;
                else
                  ins.itype = NEC850_NULL;
                break;
              case 0x1D:
                ins.itype = NEC850_SYNCE;
                break;
              case 0x1E:
                ins.itype = NEC850_SYNCM;
                break;
              case 0x1F:
                ins.itype = NEC850_SYNCP;
                break;
              default:
                ins.itype = NEC850_NULL;
                break;
            }
            if ( ins.itype != NEC850_NULL )
            {
              ins.Op1.type = o_void;
              ins.Op2.type = o_void;
              break;
            }
          }
          else if ( ins.itype == NEC850_DIVH )
          {
            ins.itype = NEC850_SWITCH;
            break;
          }
          else if ( ins.itype == NEC850_SATSUBR )
          {
            ins.itype = NEC850_ZXB;
            break;
          }
          else if ( ins.itype == NEC850_SATSUB )
          {
            ins.itype = NEC850_SXB;
            break;
          }
          else if ( ins.itype == NEC850_SATADD )
          {
            ins.itype = NEC850_ZXH;
            break;
          }
          else if ( ins.itype == NEC850_MULH )
          {
            ins.itype = NEC850_SXH;
            break;
          }
        }
        // case when r2 != 0
        else
        {
          // SLD.BU / SLD.HU
          if ( ins.itype == NEC850_JMP )
          {
            bool   sld_hu = (w >> 4) & 1;
            uint32 addr = w & 0xF;

            if ( sld_hu )
            {
              ins.itype       = NEC850_SLD_HU;
              ins.Op1.dtype   = dt_word;
              addr <<= 1;
            }
            else
            {
              ins.itype       = NEC850_SLD_BU;
              ins.Op1.dtype   = dt_byte;
            }

            ins.Op1.type      = o_displ;
            displ_op          = &ins.Op1;
            ins.Op1.reg       = rEP;
            ins.Op1.addr      = addr;
            ins.Op1.specflag1 = N850F_USEBRACKETS;

            set_opreg(ins.Op2, r2);

            break;
          }
        }
      }
      if ( ins.itype == NEC850_JMP && r2 == 0 )
      {
        ins.Op1.specflag1 = N850F_USEBRACKETS;
      }
      else
      {
        set_opreg(ins.Op2, r2);
      }
      break;
    }
    // Format II
    else if ( op <= 0x17 )
    {
      if ( PARSE_R2 == 0 && op == 0x17 && is_v850e2m() )
      {
        // 48-bit Format VI jr/jarl
        // JARL disp32, reg1: 00000010111RRRRR ddddddddddddddd0 DDDDDDDDDDDDDDDD
        // JR  disp32:        0000001011100000 ddddddddddddddd0 DDDDDDDDDDDDDDDD
        uint16 reg = PARSE_R1;
        sval_t addr = fetch_disp32(w, ins);
        if ( (addr & 1) != 0 )
          return false;
        ins.Op1.addr = ins.ip + addr;
        ins.Op1.type = o_near;
        ins.Op1.specflag1 = N850F_VAL32;
        if ( reg == 0 )
        {
          ins.itype = NEC850_JR;
        }
        else
        {
          ins.itype = NEC850_JARL;
          set_opreg(ins.Op2, reg);
        }
        break;
      }
      // flag used for sign extension
      static const itype_flags_t inst_2[] =
      {
        { NEC850_MOV,    1 }, /* MOV imm5, reg2 */
        { NEC850_SATADD, 1 }, /* SATADD imm5, reg2 */
        { NEC850_ADD,    1 }, /* ADD imm5, reg2 */
        { NEC850_CMP,    1 }, /* CMP imm5, reg2 */
        { NEC850_SHR,    0 }, /* SHR imm5, reg2 */
        { NEC850_SAR,    0 }, /* SAR imm5, reg2 */
        { NEC850_SHL,    0 }, /* SHL imm5, reg2 */
        { NEC850_MULH,   1 }, /* MULH imm5, reg2 */
      };
      op -= 0x10;

      ins.itype = inst_2[op].itype;
      uint16 r2 = PARSE_R2;

      if ( is_v850e() )
      {
        //
        // CALLT
        //
        if ( r2 == 0 && (ins.itype == NEC850_SATADD || ins.itype == NEC850_MOV) )
        {
          ins.itype = NEC850_CALLT;
          set_opimm(ins.Op1, w & 0x3F, dt_byte);
          if ( g_ctbp_ea != BADADDR )
          {
            // resolve callt addr using ctbp
            ea_t ctp = g_ctbp_ea + (ins.Op1.value << 1);
            ins.Op1.type = o_near;
            ins.Op1.addr = g_ctbp_ea + get_word(ctp);
          }
          break;
        }
      }

      sval_t v = PARSE_R1;
      if ( inst_2[op].flags == 1 )
      {
        SIGN_EXTEND(sval_t, v, 5);
        ins.Op1.specflag1 |= N850F_OUTSIGNED;
      }

      set_opimm(ins.Op1, v, dt_byte);
      set_opreg(ins.Op2, r2);

      // ADD imm, reg -> reg = reg + imm
      if ( ins.itype == NEC850_ADD && r2 == rSP )
        ins.auxpref |= N850F_SP;
      break;
    }
    // Format VI
    else if ( op >= 0x30 && op <= 0x37 )
    {
      static const itype_flags_t inst_6[] =
      { // itype         flags (1=signed)
        { NEC850_ADDI,      1 }, /* ADDI imm16, reg1, reg2 */
        { NEC850_MOVEA,     1 }, /* MOVEA imm16, reg1, reg2 */
        { NEC850_MOVHI,     0 }, /* MOVHI imm16, reg1, reg2 */
        { NEC850_SATSUBI,   1 }, /* SATSUBI imm16, reg1, reg2 */
        { NEC850_ORI,       0 }, /* ORI imm16, reg1, reg2 */
        { NEC850_XORI,      0 }, /* XORI imm16, reg1, reg2 */
        { NEC850_ANDI,      0 }, /* ANDI imm16, reg1, reg2 */
        { NEC850_MULHI,     0 }, /* MULHI  imm16, reg1, reg2 */
      };
      op -= 0x30;
      ins.itype = inst_6[op].itype;

      uint16 r1     = PARSE_R1;
      uint16 r2     = PARSE_R2;
      uint32 imm    = w >> 16;

      //
      // V850E instructions
      if ( is_v850e() && r2 == 0 )
      {
        if ( ins.itype == NEC850_MULHI )
        {
          if ( !is_v850e2() )
            return false; // "Do not specify r0 as the destination register reg2."
          if ( ( imm & 1 ) != 0 )
          {
            // RH850: LOOP reg1,disp16
            // 00000110111RRRRR ddddddddddddddd1
            if ( !is_rh850() || r1 == 0 )
              return false; // "Do not specify r0 for reg1."
            ins.itype = NEC850_LOOP;
            set_opreg(ins.Op1, r1);
            imm ^= 1; // clear bit 0
            sval_t addr = ins.ip - imm;
            ins.Op2.addr = addr;
            ins.Op2.type = o_near;
          }
          else
          {
            // V850E2: jmp disp32 [reg1]
            // 00000110111RRRRR ddddddddddddddd0 DDDDDDDDDDDDDDDD
            sval_t addr = fetch_disp32(w, ins);
            if ( ( addr & 1 ) != 0 )
              return false;
            ins.Op1.addr = addr;
            ins.Op1.type = o_displ;
            ins.Op1.specflag1 = N850F_OUTSIGNED | N850F_VAL32 | N850F_USEBRACKETS;
            ins.Op1.reg = r1;
            ins.itype = NEC850_JMP;
          }
          break;
        }
        // MOV imm32, R
        if ( ins.itype == NEC850_MOVEA )
        {
          imm |= ins.get_next_word() << 16;
          set_opimm(ins.Op1, imm);
          ins.itype = NEC850_MOV;

          set_opreg(ins.Op2, r1);
          break;
        }
        // DISPOSE imm5, list12 (reg1 == 0)
        // DISPOSE imm5, list12, [reg1]
        else if ( ins.itype == NEC850_SATSUBI || ins.itype == NEC850_MOVHI )
        {
          r1 = (w >> 16) & 0x1F;
          uint16 L = PARSE_L12;

          ins.auxpref |= N850F_SP; // SP reference

          set_opimm(ins.Op1, (w & 0x3E) >> 1, dt_byte);

          ins.Op2.value  = L;
          ins.Op2.type   = o_reglist;
          ins.Op2.dtype  = dt_word;

          if ( r1 != 0 )
          {
            set_opreg(ins.Op3, r1);
            ins.Op3.specflag1 = N850F_USEBRACKETS;

            ins.itype = NEC850_DISPOSE_r;
          }
          else
          {
            ins.itype = NEC850_DISPOSE_r0;
          }
          break;
        }
      }
      bool is_signed     = inst_6[op].flags == 1;
      set_opimm(ins.Op1, is_signed ? sval_t(int16(imm)) : imm);
      ins.Op1.specflag1 |= N850F_OUTSIGNED;

      set_opreg(ins.Op2, r1);

      set_opreg(ins.Op3, r2);

      // (ADDI|MOVEA) imm, sp, sp -> sp = sp + imm
      if ( (ins.itype == NEC850_ADDI || ins.itype == NEC850_MOVEA)
        && ((r1 == rSP) && (r2 == rSP)) )
      {
        ins.auxpref |= N850F_SP;
      }
      break;
    }
    // Format VII - LD.x
    else if ( op == 0x38 || op == 0x39 )
    {
      displ_op       = &ins.Op1;
      ins.Op1.type   = o_displ;
      ins.Op1.phrase = PARSE_R1; // R

      set_opreg(ins.Op2, PARSE_R2);

      uint32 addr;
      // LD.B
      if ( op == 0x38 )
      {
        addr          = w >> 16;
        ins.itype     = NEC850_LD_B;
        ins.Op1.dtype = dt_byte;
      }
      else
      {
        // Bit16 is cleared for LD.H
        if ( (w & (1 << 16)) == 0 )
        {
          ins.itype      = NEC850_LD_H;
          ins.Op1.dtype  = dt_word;
        }
        // LD.W
        else
        {
          ins.itype      = NEC850_LD_W;
          ins.Op1.dtype  = dt_dword;
        }
        addr = ((w & 0xFFFE0000) >> 17) << 1;
      }
      ins.Op1.specflag1 = N850F_USEBRACKETS | N850F_OUTSIGNED;
      ins.Op1.addr = int16(addr);

      break;
    }
    // Format VII - ST.x
    else if ( op == 0x3A || op == 0x3B )
    {
      // (1) ST.B  reg2, disp16 [reg1]
      // (2) ST.H  reg2, disp16 [reg1]
      // (3) ST.W  reg2, disp16 [reg1]
      set_opreg(ins.Op1, PARSE_R2);

      ins.Op2.type  = o_displ;
      displ_op      = &ins.Op2;
      ins.Op2.reg   = PARSE_R1;
      ins.Op2.specflag1 = N850F_USEBRACKETS | N850F_OUTSIGNED;
      // ST.B
      uint32 addr;
      if ( op == 0x3A )
      {
        addr          = w >> 16;
        ins.itype     = NEC850_ST_B;
        ins.Op2.dtype = dt_byte;
      }
      else
      {
        // Bit16 is cleared for ST.H
        if ( (w & (1 << 16)) == 0 )
        {
          ins.itype      = NEC850_ST_H;
          ins.Op2.dtype  = dt_word;
        }
        else
        {
          ins.itype      = NEC850_ST_W;
          ins.Op2.dtype  = dt_dword;
        }
        addr = ((w & 0xFFFE0000) >> 17) << 1;
      }
      ins.Op2.addr = int16(addr);
      break;
    }
    // Format XIII - PREPARE / LD.BU
    else if ( is_v850e()
           && ((w >> 16) & 0x1) // this bit is important to differentiate between JARL/JR instructions
           && (op == 0x3C || op == 0x3D) )
    {
      uint16 r2 = PARSE_R2;

      uint16 subop = (w >> 16) & 0x1F;
      // PREPARE
      if ( r2 == 0 && (subop == 1 || (subop & 7) == 3) )
      {
        ins.auxpref   |= N850F_SP;
        ins.Op1.value  = PARSE_L12;
        ins.Op1.type   = o_reglist;
        ins.Op1.dtype  = dt_word;

        set_opimm(ins.Op2, (w & 0x3E) >> 1, dt_byte);

        if ( subop == 1 )
        {
          ins.itype = NEC850_PREPARE_i;
        }
        else
        {
          ins.itype = NEC850_PREPARE_sp;
          uint16 ff = subop >> 3;
          switch ( ff )
          {
            case 0:
              // disassembles as: PREPARE list12, imm5, sp
              // meaning: load sp into ep
              set_opreg(ins.Op3, rSP);
              break;
              // the other cases disassemble with imm (the 3rd operand) directly processed:
              // f=1->ep=sign_extend(imm16), f=2->ep=imm16 shl 16, f=3->ep=imm32
            case 1:
              //  c:   a8 07 0b 80     prepare {r24}, 20, 0x1
              // 10:   01 00
              set_opimm(ins.Op3, sval_t(int16(ins.get_next_word())));
              break;
            case 2:
              // 2:   a8 07 13 80     prepare {r24}, 20, 0x10000
              // 6:   01 00
              set_opimm(ins.Op3, ins.get_next_word() << 16);
              break;
            case 3:
              // 2:   a8 07 1b 80     prepare {r24}, 20, 0x1
              // 6:   01 00 00 00
              set_opimm(ins.Op3, ins.get_next_dword());
              break;
          }
        }
      }
      else if ( r2 == 0 && is_v850e2m() )
      {
        // disp23 variants (Format XIV)
        // LD.BU disp23 [reg1] , reg3
        // 00000111101RRRRR wwwwwddddddd0101 DDDDDDDDDDDDDDDD
        // LD.HU disp23 [reg1] , reg3
        // 00000111101RRRRR wwwwwdddddd00111 DDDDDDDDDDDDDDDD
        // ST.H reg3, disp23 [reg1]
        // 00000111101RRRRR wwwwwdddddd01101 DDDDDDDDDDDDDDDD
        // ST.H reg3, disp23 [reg1]
        // 00000111101RRRRR wwwwwdddddd01101 DDDDDDDDDDDDDDDD
        // LD.B disp23 [reg1] , reg3
        // 00000111100RRRRR wwwwwddddddd0101 DDDDDDDDDDDDDDDD
        // LD.H disp23 [reg1] , reg3
        // 00000111100RRRRR wwwwwdddddd00111 DDDDDDDDDDDDDDDD
        // LD.W disp23 [reg1] , reg3
        // 00000111100RRRRR wwwwwdddddd01001 DDDDDDDDDDDDDDDD
        // LD.DW disp23[reg1], reg3
        // 00000111101RRRRR wwwwwdddddd01001 DDDDDDDDDDDDDDDD
        // ST.B reg3, disp23 [reg1]
        // 00000111100RRRRR wwwwwddddddd1101 DDDDDDDDDDDDDDDD
        // ST.W reg3, disp23 [reg1]
        // 00000111100RRRRR wwwwwdddddd01111 DDDDDDDDDDDDDDDD
        // ST.DW reg3, disp23[reg1]
        // 00000111101RRRRR wwwwwdddddd01111 DDDDDDDDDDDDDDDD
        // RRRRR = reg1, wwwww = reg3.
        // ddddddd is the lower 7 bits of disp23.
        // DDDDDDDDDDDDDDDD is the higher 16 bits of disp23.
        subop = ( w >> 16 ) & 0xF;
        bool sign = ( op & 1 ) == 0;
        uint32 r3 = ( w & 0xF8000000 ) >> 27;
        switch ( subop )
        {
          case 5:
            ins.itype = sign ? NEC850_LD_B : NEC850_LD_BU;
            if ( !decode_disp23(w, ins, 0, dt_byte) )
              return false;
            set_opreg(ins.Op2, r3);
            break;
          case 7:
            ins.itype = sign ? NEC850_LD_H : NEC850_LD_HU;
            if ( !decode_disp23(w, ins, 0, dt_word) )
              return false;
            set_opreg(ins.Op2, r3);
            break;
          case 9:
            if ( !sign && !is_rh850() )
              return false;
            ins.itype = sign ? NEC850_LD_W : NEC850_LD_DW;
            if ( !decode_disp23(w, ins, 0, dt_dword) )
              return false;
            set_opreg(ins.Op2, r3);
            break;
          case 13:
            ins.itype = sign ? NEC850_ST_B : NEC850_ST_H;
            if ( !decode_disp23(w, ins, 1, sign ? dt_byte : dt_word) )
              return false;
            set_opreg(ins.Op1, r3);
            break;
          case 15:
            if ( !sign && !is_rh850() )
              return false;
            ins.itype = sign ? NEC850_ST_W : NEC850_ST_DW;
            if ( !decode_disp23(w, ins, 1, dt_dword) )
              return false;
            set_opreg(ins.Op1, r3);
            break;
        }
      }
      else
      {
        // LD.BU disp16 [reg1] , reg2
        // rrrrr11110bRRRRR ddddddddddddddd1
        // ddddddddddddddd is the higher 15 bits of disp16, and b is bit 0 of disp16.
        // rrrrr != 00000 ( Do not specify r0 for reg2. )
        if ( r2 == 0 )
          return false;
        uint16 r1 = PARSE_R1;

        ins.itype = NEC850_LD_BU;

        ins.Op1.type  = o_displ;
        displ_op      = &ins.Op1;
        ins.Op1.reg   = r1;
        ins.Op1.addr  = int16(((w >> 16) & ~1) | ((w & 0x20) >> 5));
        ins.Op1.dtype = dt_byte;
        ins.Op1.specflag1 = N850F_USEBRACKETS | N850F_OUTSIGNED;

        set_opreg(ins.Op2, r2);
      }
      break;
    }
    // Format VIII
    else if ( op == 0x3E )
    {
      // parse sub-opcode (b15..b14)
      op = ((w & 0xC000) >> 14);
      static const int inst_8[] =
      {
        NEC850_SET1, NEC850_NOT1,
        NEC850_CLR1, NEC850_TST1
      };
      ins.itype = inst_8[op];
      set_opimm(ins.Op1, ((w & 0x3800) >> 11), dt_byte);


      ins.Op2.type      = o_displ;
      displ_op          = &ins.Op2;
      ins.Op2.addr      = int16(w >> 16);
      ins.Op2.offb      = 2;
      ins.Op2.dtype     = dt_byte;
      ins.Op2.reg       = PARSE_R1; // R
      ins.Op2.specflag1 = N850F_USEBRACKETS | N850F_OUTSIGNED;
      break;
    }
    //
    // Format IX, X
    //
    else if ( op == 0x3F )
    {
      if ( (w & ( 1 << 16 )) == 0 && ( w & ( 1 << 26 ) ) != 0 )
        // coprocessor insn
        return decode_coprocessor(w, ins);
      //
      // Format X
      //

      // Const opcodes
      if ( w == 0x16087E0 ) // EI
        ins.itype = NEC850_EI;
      else if ( w == 0x16007E0 ) // DI
        ins.itype = NEC850_DI;
      else if ( w == 0x14007E0 ) // RETI
        ins.itype = NEC850_RETI;
      else if ( w == 0x12007E0 ) // HALT
        ins.itype = NEC850_HALT;
      else if ( w == 0xffffffff )
        ins.itype = NEC850_BREAKPOINT;
      else if ( (w >> 5) == 0x8003F ) //lint !e587 predicate always false // TRAP
      {
        ins.itype = NEC850_TRAP;
        set_opimm(ins.Op1, PARSE_R1, dt_byte);
        break;
      }
      if ( ins.itype != 0 )
        break;
      if ( is_v850e1f() && !is_v850e2m() )
      {
        // E1F opcodes (ref. U16374EJ1V0UM)
        int subop = ( w >> 16 ) & 0x7FF;
        int r3 = ( w & 0xF8000000 ) >> 27;
        switch ( subop )
        {
// Format F:I reg1, reg2, reg3
          case 0x3E0:
            ins.itype = NEC850_DIVF_S;
            goto OPS_FI;
          case 0x3E4:
            ins.itype = NEC850_SUBF_S;
            goto OPS_FI;
          case 0x3E8:
            ins.itype = NEC850_ADDF_S;
            goto OPS_FI;
          case 0x3EC:
            ins.itype = NEC850_MULF_S;
            goto OPS_FI;
          case 0x3F0:
            ins.itype = NEC850_MINF_S;
            goto OPS_FI;
          case 0x3F4:
            ins.itype = NEC850_MAXF_S;
OPS_FI:
            set_opreg(ins.Op1, PARSE_R1);
            set_opreg(ins.Op2, PARSE_R2);
            set_opreg(ins.Op3, r3);
            break;
// Format F:II reg2, reg3
          case 0x360:
            ins.itype = NEC850_CVT_SW;
OPS_FII:
            set_opreg(ins.Op1, PARSE_R2);
            set_opreg(ins.Op2, r3);
            break;
          case 0x368:
            ins.itype = NEC850_TRNC_SW;
            goto OPS_FII;
          case 0x370:
            ins.itype = NEC850_CVT_WS;
            goto OPS_FII;
          case 0x3F8:
            ins.itype = NEC850_NEGF_S;
            goto OPS_FII;
          case 0x3FC:
            ins.itype = NEC850_ABSF_S;
            goto OPS_FII;

// Format F:IV reg2 or reg3
          case 0x378:
            if ( r3 != 0 )
            {
              // STFF EFG,reg2
              ins.itype = NEC850_STFF;
              set_opreg(ins.Op1, EFG);
              set_opreg(ins.Op2, r3);
            }
            else
            {
              ins.itype = NEC850_TRFF;
              // no operands
            }
            break;
          case 0x37C:
            // STFC ECT,reg2
            ins.itype = NEC850_STFC;
            set_opreg(ins.Op1, ECT);
            set_opreg(ins.Op2, r3);
            break;

          case 0x37A:
            if ( r3 == 0 )
            {
              // LDFF reg2,EFG
              ins.itype = NEC850_LDFF;
              set_opreg(ins.Op1, PARSE_R2);
              set_opreg(ins.Op2, EFG);
            }
            break;

          case 0x37E:
            if ( r3 == 0 )
            {
              // LDFC reg2,ECT
              ins.itype = NEC850_LDFC;
              set_opreg(ins.Op1, PARSE_R2);
              set_opreg(ins.Op2, ECT);
            }
            break;

        }
        if ( ins.itype != 0 )
          break;
      }
      // Still in format 10 (op = 0x3F)
      if ( is_v850e() )
      {
        if ( is_v850e2m() )
        {
          if ( w == 0x14807E0 )
            ins.itype = NEC850_EIRET;
          else if ( w == 0x14a07E0 )
            ins.itype = NEC850_FERET;
          else if ( ( w & 0xc7ffffe0 ) == 0x0160d7e0 )
          {
            ins.itype = NEC850_SYSCALL;
            int v8 = (w & 0x1f) | ((w >> (27 - 5)) & 0xe0);
            set_opimm(ins.Op1, v8);
          }
          else if ( is_rh850() )
          {
            int subop = ( w >> 16 ) & 0x7FF;
            switch ( subop )
            {
              case 0x8:
                ins.itype = NEC850_CLIP_B;
                set_opreg(ins.Op1, PARSE_R1, dt_byte);
                set_opreg(ins.Op2, PARSE_R2, dt_word);
                break;
              case 0xA:
                ins.itype = NEC850_CLIP_BU;
                set_opreg(ins.Op1, PARSE_R1, dt_byte);
                set_opreg(ins.Op2, PARSE_R2, dt_word);
                break;
              case 0xC:
                ins.itype = NEC850_CLIP_H;
                set_opreg(ins.Op1, PARSE_R1, dt_dword);
                set_opreg(ins.Op2, PARSE_R2, dt_word);
                break;
              case 0xE:
                ins.itype = NEC850_CLIP_HU;
                set_opreg(ins.Op1, PARSE_R1, dt_dword);
                set_opreg(ins.Op2, PARSE_R2, dt_word);
                break;
              case 0x20:
              case 0x40:
                {
                  // LDSR reg2, regID, selID
                  // rrrrr111111RRRRR sssss00000100000
                  // rrrrr: regID, sssss: selID, RRRRR: reg2
                  // STSR regID, reg2, selID
                  // rrrrr111111RRRRR sssss00001000000
                  // rrrrr: regID, sssss: selID, RRRRR: reg2
                  bool is_ld = subop == 0x20;
                  ins.itype = is_ld ? NEC850_LDSR : NEC850_STSR;
                  uint32 selid = ( w & 0xF8000000 ) >> 27;
                  uint32 regid = PARSE_R1;
                  uint32 r2 = PARSE_R2;
                  if ( is_ld )
                  {
                    // In this instruction, general-purpose register reg2 is used as the source register, but, for
                    // mnemonic description convenience, the general - purpose register reg1 field is used in the
                    // opcode.The meanings of the register specifications in the mnemonic descriptions and
                    // opcode therefore differ from those of other instructions.
                    set_opreg(ins.Op1, regid);
                    set_opreg(ins.Op2, r2 + rSR0);
                  }
                  else
                  {
                    set_opreg(ins.Op1, regid + rSR0);
                    set_opreg(ins.Op2, r2);
                  }
                  if ( selid != 0 )
                    set_opimm(ins.Op3, selid);
                }
                break;

              case 0x30:
              case 0x50:
                {
                  bool is_ld = subop == 0x30;
                  if ( is_ld )
                  {
                    ins.itype = NEC850_LDTC_SR;
                    set_opreg(ins.Op1, PARSE_R1);
                    set_opimm(ins.Op2, PARSE_R2);
                  }
                  else
                  {
                    ins.itype = NEC850_STTC_SR;
                    set_opimm(ins.Op1, PARSE_R1);
                    set_opreg(ins.Op2, PARSE_R2);
                  }
                  uint32 selid = ( w & 0xF8000000 ) >> 27;
                  set_opimm(ins.Op3, selid);
                }
                break;

              case 0x32:
              case 0x52:
                {
                  bool is_ld = subop == 0x32;
                  uint32 selid = ( w & 0xF8000000 ) >> 27;
                  switch ( selid )
                  {
                    case 0:
                      ins.itype = is_ld ? NEC850_LDTC_GR: NEC850_STTC_GR;
                      set_opreg(ins.Op2, PARSE_R2);
                      set_opreg(ins.Op1, PARSE_R1);
                      break;
                    case 1:
                      ins.itype = is_ld ? NEC850_LDTC_VR : NEC850_STTC_VR;
                      set_opreg(ins.Op1, is_ld ? PARSE_R2 : PARSE_R1);
                      set_opreg(ins.Op2, is_ld ? PARSE_R1 : PARSE_R2);
                      break;
                    case 31:
                      ins.itype = is_ld ? NEC850_LDTC_PC : NEC850_STTC_PC;
                      set_opreg(ins.Op1, is_ld ? PARSE_R1 : PARSE_R2);
                      break;
                    default:
                      break;
                  }
                }
                break;

              case 0x34:
              case 0x54:
                {
                  bool is_ld = subop == 0x34;
                  if ( is_ld )
                  {
                    ins.itype = NEC850_LDVC_SR;
                    set_opreg(ins.Op1, PARSE_R1);
                    set_opimm(ins.Op2, PARSE_R2);
                  }
                  else
                  {
                    ins.itype = NEC850_STVC_SR;
                    set_opimm(ins.Op1, PARSE_R1);
                    set_opreg(ins.Op2, PARSE_R2);

                  }
                  uint32 selid = ( w & 0xF8000000 ) >> 27;
                  set_opimm(ins.Op3, selid);
                }
                break;

              case 0xC4:
              case 0xC6:
                {
                  // ROTL imm5, reg2, reg3
                  // rrrrr111111iiiii wwwww00011000100
                  // ROTL reg1, reg2, reg3
                  // rrrrr111111RRRRR wwwww00011000110
                  ins.itype = NEC850_ROTL;
                  uint32 r1 = PARSE_R1;
                  uint32 r2 = PARSE_R2;
                  uint32 r3 = (w & 0xF8000000) >> 27;
                  if ( subop == 0xC4 )
                  {
                    set_opimm(ins.Op1, r1);
                  }
                  else
                  {
                    set_opreg(ins.Op1, r1);
                  }
                  set_opreg(ins.Op2, r2);
                  set_opreg(ins.Op3, r3);
                }
                break;

              case 0x110:
                ins.itype = NEC850_HVTRAP;
                set_opimm(ins.Op1, PARSE_R1, dt_byte);
                break;

              case 0x132:
                ins.itype = NEC850_EST;
                break;

              case 0x134:
                ins.itype = NEC850_DST;
                break;
              case 0x164:
                {
                  // stm.mp:
                  // STM.MP eh-et, [reg1]
                  //
                  // rrrrr111111RRRRR wwwww00101100100
                  uint32 r3 = (w & 0xF8000000) >> 27;

                  ins.itype = NEC850_STM_MP;
                  ins.Op1.type = o_regrange;
                  ins.Op1.regrange_high = PARSE_R2;
                  ins.Op1.regrange_low = r3;
                  ins.Op1.dtype = dt_word;

                  ins.Op2.specflag1 = N850F_USEBRACKETS;
                  set_opreg(ins.Op2, PARSE_R1, dt_word);
                  break;
                }
              case 0x166:
                {
                  // ldm.mp:
                  // LDM.MP [reg1], eh-et
                  //
                  // rrrrr111111RRRRR wwwww00101100110
                  uint32 r3 = (w & 0xF8000000) >> 27;
                  ins.itype = NEC850_LDM_MP;

                  ins.Op1.specflag1 = N850F_USEBRACKETS;
                  set_opreg(ins.Op1, PARSE_R1, dt_word);

                  ins.Op2.type = o_regrange;
                  ins.Op2.regrange_high = PARSE_R2;
                  ins.Op2.regrange_low = r3;
                  ins.Op2.dtype = dt_word;
                  break;
                }
              case 0x370:
                {
                  uint32 r2 = PARSE_R2;
                  uint32 r3 = (w & 0xF8000000) >> 27;

                  set_opreg(ins.Op1, PARSE_R1, dt_byte);
                  ins.Op1.specflag1 = N850F_USEBRACKETS;

                  if ( r2 != 1 )
                  {
                    // ld.bu:
                    // (3) LD.BU [reg1]+, reg3
                    // (4) LD.BU [reg1]-, reg3
                    //
                    // (3) 00011111111RRRRR wwwww01101110000
                    // (4) 00101111111RRRRR wwwww01101110000
                    ins.itype = NEC850_LD_BU;

                    switch ( r2 )
                    {
                      case 0x3:
                        ins.Op1.specflag1 |= N850F_POST_INCREMENT;
                        break;
                      case 0x5:
                        ins.Op1.specflag1 |= N850F_POST_DECREMENT;
                        break;
                      default:
                        break;
                    }
                    set_opreg(ins.Op2, r3, dt_byte);
                  }
                  else
                  {
                    // LDL.BU [reg1], reg3
                    // 00001111111RRRRR wwwww01101110000
                    ins.itype = NEC850_LDL_BU;
                  }

                  set_opreg(ins.Op2, r3, dt_byte);
                  break;
                }
              case 0x372:
                {
                  // st.b
                  // (3) ST.B reg3, [reg1]+
                  // (4) ST.B reg3, [reg1]-
                  //
                  // (3) 00010111111RRRRR wwwww01101110010
                  // (4) 00100111111RRRRR wwwww01101110010

                  uint32 r3 = (w & 0xF8000000) >> 27;

                  ins.itype = NEC850_ST_B;
                  set_opreg(ins.Op1, r3, dt_byte);

                  ins.Op2.specflag1 = N850F_USEBRACKETS;
                  switch ( PARSE_R2 )
                  {
                    case 0x2:
                      ins.Op2.specflag1 |= N850F_POST_INCREMENT;
                      break;
                    case 0x4:
                      ins.Op2.specflag1 |= N850F_POST_DECREMENT;
                      break;
                    default:
                      break;
                  }

                  set_opreg(ins.Op2, PARSE_R1, dt_byte);
                  break;
                }
              case 0x374:
                {
                  // LDL.HU [reg1], reg3
                  // 00001111111RRRRR wwwww01101110100
                  ins.itype = NEC850_LDL_HU;
                  uint32 r3 = (w & 0xF8000000) >> 27;

                  set_opreg(ins.Op1, PARSE_R1, dt_byte);
                  ins.Op1.specflag1 = N850F_USEBRACKETS;

                  set_opreg(ins.Op2, r3, dt_word);
                  break;
                }
              case 0x378:
                {
                  // LDL.W [reg1], reg3
                  // 00000111111RRRRR wwwww01101111000
                  ins.itype = NEC850_LDL_W;
                  uint32 r3 = ( w & 0xF8000000 ) >> 27;
                  set_opreg(ins.Op1, PARSE_R1);
                  ins.Op1.specflag1 = N850F_USEBRACKETS;
                  set_opreg(ins.Op2, r3);
                  break;
                }

              case 0x37A:
                {
                  // STC.W reg3, [reg1]
                  // 00000111111RRRRR wwwww01101111010
                  ins.itype = NEC850_STC_W;
                  uint32 r3 = ( w & 0xF8000000 ) >> 27;
                  set_opreg(ins.Op1, r3);
                  set_opreg(ins.Op2, PARSE_R1);
                  ins.Op2.specflag1 = N850F_USEBRACKETS;
                  break;
                }
              case 0x160:
                {
                  uint32 r1 = PARSE_R1;
                  uint32 r2 = PARSE_R2;
                  uint32 r3 = ( w & 0xF8000000 ) >> 27;
                  int w1 = w >> 16;
                  switch ( r2 )
                  {
                    case 8:   // pushsp
                    case 0xB: // dbpush
                    case 0xC: // popsp
                      {
                        // PUSHSP rh-rt
                        // 01000111111RRRRR wwwww00101100000
                        // POPSP rh-rt
                        // 01100111111RRRRR wwwww00101100000
                        // RRRRR indicates rh. wwwww indicates rt.
                        ins.itype = r2 == 8 ? NEC850_PUSHSP
                          : r2 == 0xB ? NEC850_DBPUSH
                          : NEC850_POPSP;
                        ins.Op1.type = o_regrange;
                        ins.Op1.regrange_high = r1;
                        ins.Op1.regrange_low = r3;
                      }
                      break;

                    case 0x10:
                      switch ( w1 )
                      {
                        case 0x8960:
                          ins.itype = NEC850_TLBAI;
                          break;
                        case 0x8160:
                          ins.itype = NEC850_TLBVI;
                          break;
                        case 0xC160:
                          ins.itype = NEC850_TLBS;
                          break;
                        case 0xE960:
                          ins.itype = NEC850_TLBR;
                          break;
                        case 0xE160:
                          ins.itype = NEC850_TLBW;
                          break;
                      }
                      break;

                    case 0x18:
                      {
                        // JARL [reg1], reg3
                        // 11000111111RRRRR WWWWW00101100000
                        set_opreg(ins.Op1, r1);
                        ins.Op1.specflag1 = N850F_USEBRACKETS;
                        set_opreg(ins.Op2, r3);
                        ins.itype = NEC850_JARL;
                      }
                      break;

                    case 0x19:
                      {
                        ins.itype = NEC850_DBTAG;
                        int v8 = (w & 0x1f) | ((w1 >> 6) & 0xe0);
                        set_opimm(ins.Op1, v8);
                      }
                      break;

                    case 0x1A:
                      {
                        ins.itype = NEC850_HVCALL;
                        int v8 = (w & 0x1f) | ((w1 >> 6) & 0xe0);
                        set_opimm(ins.Op1, v8);
                      }
                      break;

                    case 0x1B:
                      {
                        // PREF prefop, [reg1]
                        // 11011111111RRRRR PPPPP00101100000
                        // PPPPP indicates prefop
                        ins.itype = NEC850_PREF;
                        set_opimm(ins.Op1, r3);
                        set_opreg(ins.Op2, r1);
                      }
                      break;

                    case 0x1Cu:
                    case 0x1Du:
                    case 0x1Eu:
                    case 0x1Fu:
                      {
                        // CACHE cacheop, [reg1]
                        // 111pp111111RRRRR PPPPP00101100000
                        // ppPPPPP indicates cacheop

                        int cacheop = ( ( r2 & 3 ) << 5 ) | r3;
                        if ( r1 == 0x1f && cacheop == 0x7E )
                        {
                          ins.itype = NEC850_CLL;
                        }
                        else
                        {
                          ins.itype = NEC850_CACHE;
                          set_opimm(ins.Op1, cacheop);
                          set_opreg(ins.Op2, r1);
                        }
                      }
                      break;
                  }
                }
                break;
              default:
                if ( w == 0x1200FE0 )
                  ins.itype = NEC850_SNOOZE;
                else if ( (w&0x10000) == 0 )
                {
                  uint o0 = ( w >> 20 ) & 0x7F;
                  if ( o0 == 9 || o0 == 11 || o0 == 13 )
                  {
                    // BINS reg1, pos, width, reg2

                    // rrrrr111111RRRRR MMMMK 0001001 LLL0 msb >= 16, lsb >= 16
                    // rrrrr111111RRRRR MMMMK 0001011 LLL0 msb >= 16, lsb < 16
                    // rrrrr111111RRRRR MMMMK 0001101 LLL0 msb < 16, lsb < 16
                    // Most significant bit of field to be updated : msb = pos + width - 1
                    // Least significant bit of field to be updated : lsb = pos
                    // MMMM = lower 4 bits of msb, KLLL = lower 4 bits of lsb
                    uint16 whi = w >> 16;
                    uint lsb = ( whi >> 1 ) & 7;
                    lsb |= ( whi >> 8 ) & 8;
                    uint msb = ( whi >> 12 ) & 0xF;
                    if ( o0 == 9 || o0 == 11 )
                      msb += 16;
                    if ( o0 == 9 )
                      lsb += 16;
                    uint width = msb - lsb + 1;

                    ins.itype = NEC850_BINS;
                    set_opreg(ins.Op1, PARSE_R1);
                    set_opimm(ins.Op2, lsb);
                    set_opimm(ins.Op3, width);
                    set_opreg(ins.Op4, PARSE_R2);
                  }
                }
                break;

            }
            if ( ins.itype != 0 )
              break;
          }

          if ( ins.itype != 0 )
            break;
        }
        if ( w == 0x14607E0 )
        {
          ins.itype = NEC850_DBRET;
          break;
        }
        else if ( w == 0x14407E0 )
        {
          ins.itype = NEC850_CTRET;
          break;
        }
        else if ( (w >> 16) & 0x1 )
        {
          int r2 = PARSE_R2;
          int r1 = PARSE_R1;
          if ( r2 != 0 )
          {
            // V850E: LD.HU disp16 [reg1], reg2
            // rrrrr111111RRRRR ddddddddddddddd1
            ins.itype = NEC850_LD_HU;
            ins.Op1.type = o_displ;
            displ_op = &ins.Op1;
            ins.Op1.reg = r1;
            ins.Op1.addr = uint32(( w >> 17 ) << 1);
            ins.Op1.dtype = dt_word;
            ins.Op1.specflag1 = N850F_USEBRACKETS | N850F_OUTSIGNED;
            set_opreg(ins.Op2, r2);
          }
          else if ( is_rh850() )
          {
            // RH850: Bcond disp17
            // 00000111111DCCCC ddddddddddddddd1
            sval_t dest = uint32(( w >> 17 ) << 1);
            if ( (w & 0x10) != 0 )
              dest += 0x10000; // D
            SIGN_EXTEND(sval_t, dest, 17);
            ins.itype = bcond_map[w & 0xF];
            ins.Op1.dtype = dt_word;
            ins.Op1.type = o_near;
            ins.Op1.addr = ea_t(dest + ins.ip);
          }
          break;
        }
        //
        // XI Group match (reg1, reg2, reg3)
        //
        uint32 r1 = PARSE_R1;
        uint32 r2 = PARSE_R2;
        uint32 r3 = ( w & 0xF8000000 ) >> 27;

        op = (w & 0x7FF0000) >> 16;
        if ( op == 0x220 )
          ins.itype = NEC850_MUL;
        else if ( op == 0x222 )
          ins.itype = NEC850_MULU;
        else if ( op == 0x280 )
          ins.itype = NEC850_DIVH_r3;
        else if ( op == 0x282 )
          ins.itype = NEC850_DIVHU;
        else if ( op == 0x2C0 )
          ins.itype = NEC850_DIV;
        else if ( op == 0x2C2 )
          ins.itype = NEC850_DIVU;
        else if ( is_v850e2() )
        {
          if ( ( op & 1 ) == 0 )
          {
            if ( ( op >> 5 ) == 0x1D )
            {
              // ADF
              int cc = ( op >> 1 ) & 0xF;
              if ( cc == CC_SAT )
              {
                ins.itype = NEC850_SATADD;
              }
              else
              {
                ins.itype = NEC850_ADF;
                set_opcond(ins.Op1, cc);
                set_opreg(ins.Op2, r1);
                set_opreg(ins.Op3, r2);
                set_opreg(ins.Op4, r3);
                break;
              }
            }
            else if ( ( op >> 5 ) == 0x1C )
            {
              // SBF
              int cc = ( op >> 1 ) & 0xF;
              if ( cc == CC_SAT )
              {
                ins.itype = NEC850_SATSUB;
              }
              else
              {
                ins.itype = NEC850_SBF;
                set_opcond(ins.Op1, cc);
                set_opreg(ins.Op2, r1);
                set_opreg(ins.Op3, r2);
                set_opreg(ins.Op4, r3);
                break;
              }
            }
            else if ( ( op >> 6 ) == 0xF )
            {
              // MAC  rrrrr111111RRRRR wwww0011110mmmm0
              // MACU rrrrr111111RRRRR wwww0011111mmmm0
              ins.itype = ( op & 0x20 ) ? NEC850_MACU : NEC850_MAC;
              int r4 = op&0x1F;
              set_opreg(ins.Op1, r1);
              set_opreg(ins.Op2, r2);
              set_opreg(ins.Op3, r3);
              set_opreg(ins.Op4, r4);
              break;
            }
          }
          switch ( op )
          {
            case 0x82:
              ins.itype = NEC850_SHR;
              break;
            case 0xa2:
              ins.itype = NEC850_SAR;
              break;
            case 0xc2:
              ins.itype = NEC850_SHL;
              break;
            case 0xEE:
              ins.itype = NEC850_CAXI;
              ins.Op1.specflag1 |= N850F_USEBRACKETS;
              break;
            case 0x2FE:
              ins.itype = NEC850_DIVQU;
              break;
            case 0x2FC:
              ins.itype = NEC850_DIVQ;
              break;
          }
        }
        // process the match
        if ( ins.itype != 0 )
        {
          set_opreg(ins.Op1, r1);
          set_opreg(ins.Op2, r2);
          set_opreg(ins.Op3, r3);
          break;
        }

        //
        // XII/IX Group match (reg2, reg3)
        //
        if ( op == 0x340 )
          ins.itype = NEC850_BSW;
        else if ( op == 0x342 )
          ins.itype = NEC850_BSH;
        else if ( op == 0x344 )
          ins.itype = NEC850_HSW;
        else if ( is_v850e2() )
        {
          switch ( op )
          {
            case 0x346:
              ins.itype = NEC850_HSH;
              break;
            case 0x360:
              ins.itype = NEC850_SCH0R;
              break;
            case 0x362:
              ins.itype = NEC850_SCH1R;
              break;
            case 0x364:
              ins.itype = NEC850_SCH0L;
              break;
            case 0x366:
              ins.itype = NEC850_SCH1L;
              break;
          }
        }
            // process the match
        if ( ins.itype != 0 )
        {
          set_opreg(ins.Op1, r2);
          set_opreg(ins.Op2, r3);
          break;
        }

        //
        // match CMOV
        //
        op = w >> 16;
        op = ((op & 0x7E0) >> 4) | (op & 0x1);
        if ( op == 0x30 || op == 0x32 )
        {
          uint32 cc = (w & 0x1E0000) >> 17;
          ins.itype = NEC850_CMOV;
          set_opcond(ins.Op1, cc);

          r1 = PARSE_R1;
          r2 = PARSE_R2;
          r3 = (w & 0xF8000000) >> 27;

          if ( op == 0x32 ) // CMOV cc, reg1, reg2, reg3
          {
            set_opreg(ins.Op2, r1);
          }
          else
          {
            // CMOV cc, imm5, reg2, reg3
            sval_t v = r1;
            SIGN_EXTEND(sval_t, v, 5);
            set_opimm(ins.Op2, v, dt_byte);
            ins.Op2.specflag1 |= N850F_OUTSIGNED;
          }
          set_opreg(ins.Op3, r2);
          set_opreg(ins.Op4, r3);
          break;
        }
        //
        // match MUL[U]_i9
        //
        op = w >> 16;
        op = ((op & 0x7C0) >> 4) | (op & 0x3);
        if ( op == 0x24 || op == 0x26 )
        {
          sval_t imm = (((w & 0x3C0000) >> 18) << 5) | (w & 0x1F);
          if ( op == 0x24 )
          {
            ins.itype = NEC850_MUL;
            SIGN_EXTEND(sval_t, imm, 9);
            ins.Op1.specflag1 |= N850F_OUTSIGNED;
          }
          else
            ins.itype = NEC850_MULU;

          set_opimm(ins.Op1, imm);
          set_opreg(ins.Op2, PARSE_R2);
          set_opreg(ins.Op3, (w & 0xF8000000) >> 27);
          break;
        }
      }

      //
      // Format IX
      //
      op = w >> 16; // take 2nd half-word as the opcode
      uint32 reg1 = PARSE_R1;
      uint32 reg2 = PARSE_R2;
      // SETF
      if ( op == 0 )
      {
        if ( ( w & 0x10 ) == 0 )
        {
          ins.itype = NEC850_SETF;
          set_opcond(ins.Op1, w & 0xF);
          set_opreg(ins.Op2, reg2);
        }
        else if ( is_v850e2m() )
        {
          ins.itype = NEC850_RIE;
          uint imm5 = ( w >> 11 ) & 0x1F;
          uint imm4 = w & 0xF;
          set_opimm(ins.Op1, imm5);
          set_opimm(ins.Op2, imm4);
        }
        break;
      }

      switch ( op )
      {
        case 0x20: // LDSR
          ins.itype = NEC850_LDSR;
          ins.Op2.reg = rSR0; // designate system register
          break;
        case 0x40: // STSR
          ins.itype = NEC850_STSR;
          ins.Op1.reg = rSR0; // designate system register
          break;
        case 0x80: // SHR
          ins.itype = NEC850_SHR;
          break;
        case 0xA0: // SAR
          ins.itype = NEC850_SAR;
          break;
        case 0xC0: // SHL
          ins.itype = NEC850_SHL;
          break;
      }

      if ( ins.itype != 0 )
      {
        // Common stuff for the rest of Format 9 instructions
        ins.Op1.dtype = ins.Op2.dtype = dt_dword;
        ins.Op1.type  = ins.Op2.type  = o_reg;
        ins.Op1.reg  += reg1;
        ins.Op2.reg  += reg2;
        break;
      }

      // -> ins.itype == 0
      //
      // No match? Try V850E
      if ( is_v850e() )
      {
        // SASF
        if ( op == 0x200 )
        {
          ins.itype = NEC850_SASF;
          set_opcond(ins.Op1, w & 0xF);
          set_opreg(ins.Op2, reg2);
          break;
        }

        switch ( op )
        {
          case 0xE0: // NOT1
            ins.itype = NEC850_SET1;
            break;
          case 0xE2: // NOT1
            ins.itype = NEC850_NOT1;
            break;
          case 0xE4: // CLR1
            ins.itype = NEC850_CLR1;
            break;
          case 0xE6: // TST1
            ins.itype = NEC850_TST1;
            break;
          default:
            return 0; // No match!
        }
        // Common
        set_opreg(ins.Op1, reg2, dt_byte);

        ins.Op2.dtype = dt_byte;
        displ_op      = &ins.Op2;
        ins.Op2.type  = o_displ;
        ins.Op2.addr  = 0;
        ins.Op2.reg   = reg1;
        ins.Op2.specflag1 = N850F_USEBRACKETS;
      }

      if ( ins.itype == 0 )
        return 0; // unknown instruction

      break;
    } // Format end

    //
    // Format V
    //
    op = (w & 0x780) >> 6; // Take bit6->bit10
    // JARL and JR
    if ( op == 0x1E )
    {
      uint32 reg  = PARSE_R2;
      sval_t addr = uint32((((w & 0x3F) << 15) | ((w & 0xFFFE0000) >> 17)) << 1);
      SIGN_EXTEND(sval_t, addr, 22);

      ins.Op1.addr = ins.ip + addr;
      ins.Op1.type = o_near;
      // per the docs, if reg is zero then JARL turns to JR
      if ( reg == 0 )
      {
        ins.itype = NEC850_JR;
      }
      else
      {
        ins.itype = NEC850_JARL;
        set_opreg(ins.Op2, reg);
      }
      break;
    }

    //
    // Format III
    //
    op = (w & 0x780) >> 7; // Take bit7->bit10
    // assert: op in [0, 0xF]
    // Bcond disp9
    if ( op == 0xB )
    {
      sval_t dest = ( ((w & 0x70) >> 4) | ((w & 0xF800) >> 8) ) << 1;
      SIGN_EXTEND(sval_t, dest, 9);

      ins.itype     = bcond_map[w & 0xF];
      ins.Op1.dtype = dt_word;
      ins.Op1.type  = o_near;
      ins.Op1.addr  = ea_t(dest + ins.ip);
      break;
    }
    //
    // Format IV
    //
    else if ( op >= 6 )
    {
      uint32 reg2 = PARSE_R2;
      uint32 addr = (w & 0x7F); // zero extended
      int idx_d(-1), idx_r(-1);
      char dtyp_d(-1);

      // SLD.B
      if ( op == 6 )
      {
        ins.itype = NEC850_SLD_B;
        idx_d = 0;
        idx_r = 1;
        dtyp_d = dt_byte;
      }
      // SLD.H
      else if ( op == 8 )
      {
        ins.itype = NEC850_SLD_H;
        idx_d = 0;
        idx_r = 1;
        dtyp_d = dt_word;
        addr <<= 1;
      }
      // SLD.W
      else if ( op == 10 && ((w & 1) == 0) )
      {
        ins.itype = NEC850_SLD_W;
        idx_d = 0;
        idx_r = 1;
        dtyp_d = dt_dword;
        addr <<= 1;
      }
      // SST.B
      else if ( op == 7 )
      {
        ins.itype = NEC850_SST_B;
        idx_d = 1;
        idx_r = 0;
        dtyp_d = dt_byte;
      }
      // SST.H
      else if ( op == 9 )
      {
        ins.itype = NEC850_SST_H;
        idx_d = 1;
        idx_r = 0;
        dtyp_d = dt_byte;
        // bit0 is already cleared, so the 7bit addr we read
        // can be shifted by one to transform it to 8bit
        addr <<= 1;
      }
      // SST.W
      else if ( op == 10 && ((w & 1) == 1) )
      {
        ins.itype = NEC850_SST_W;
        idx_d = 1;
        idx_r = 0;
        dtyp_d = dt_dword;
        // clear lower bit because it is set, and shift by one
        // bit 15             0
        //     rrrrr1010dddddd1
        addr = (addr & ~1) << 1;
      }
      if ( idx_d == -1 || idx_r == -1 || dtyp_d == -1 )
        return false; // could not decode

      set_opreg(ins.ops[idx_r], reg2);

      ins.ops[idx_d].type      = o_displ;
      displ_op                 = &ins.ops[idx_d];
      ins.ops[idx_d].reg       = rEP;
      ins.ops[idx_d].addr      = addr;
      ins.ops[idx_d].dtype     = dtyp_d;
      ins.ops[idx_d].specflag1 = N850F_USEBRACKETS;
      break;
    }
    // Unknown instructions
    ins.itype = NEC850_NULL;
  } while ( false );

  // special cases when we have memory access through displacement
  if ( displ_op != nullptr )
  {
    // A displacement with GP and GP is set?
    if ( displ_op->reg == rGP && g_gp_ea != BADADDR )
    {
      displ_op->type = o_mem;
      if ( ins.itype == NEC850_SLD_BU || ins.itype == NEC850_LD_BU
        || ins.itype == NEC850_SLD_HU || ins.itype == NEC850_LD_HU )
      {
        displ_op->addr = short(displ_op->addr) + g_gp_ea;
      }
      else
      {
        displ_op->addr += g_gp_ea;
      }
    }
    // register zero access?
    else if ( displ_op->reg == rZERO )
    {
      // since r0 is always 0, we can replace the operand by the complete address
      displ_op->type = o_mem;
      displ_op->specflag1 &= ~N850F_OUTSIGNED;
      if ( ins.itype == NEC850_LD_BU || ins.itype == NEC850_LD_HU )
        displ_op->addr = short(displ_op->addr);
    }
#ifdef __EA64__
    if ( displ_op->type == o_mem )
    {
      // truncate address to 32 bits if needed
      segment_t *s = getseg(displ_op->addr);
      if ( s == nullptr || !s->is_64bit() )
        displ_op->addr = uint32(displ_op->addr);
    }
#endif
  }
  return ins.itype != 0;
}

//------------------------------------------------------------------------
// Analyze one instruction and fill 'insn' structure.
// insn.ea contains address of instruction to analyze.
// Return length of the instruction in bytes, 0 if instruction can't be decoded.
// This function shouldn't change the database, flags or anything else.
// All these actions should be performed only by u_emu() function.
int nec850_t::nec850_ana(insn_t *pinsn)
{
  insn_t &insn = *pinsn;
  if ( insn.ea & 0x1 )
    return 0;

  uint32 w;
  fetch_instruction(&w, insn);
  if ( decode_instruction(w, insn) )
    return insn.size;
  else
    return 0;
}
