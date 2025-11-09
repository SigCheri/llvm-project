include "RISCVInstrFormatsXSigCheri.td"

class RVInstPEC<bit cryptoOp, bits<3> funct3, string opcodestr>
    : RVInstKey<cryptoOp, funct3, OPC_KEY,
    (outs GPR:$rd), (ins GPR:$rs1, GPR:$rs2, uimm3:$startByte, uimm3:$endByte),
    opcodestr, "$rd, $rs1, $rs2, $startByte, $endByte">{

      let hasSideEffects = 0;
      let mayLoad = 0;
      let mayStore = 0;
}

defvar encrypt_op = 0b0;
defvar decrypt_op = 0b1;
defvar pec_funct3_mkey = 0b000;
defvar pec_funct3_skey = 0b001;

let hasSideEffects = 0, mayLoad = 1, mayStore = 0 in
class Load_sig<bits<3> funct3, string opcodestr, RegisterClass regclass>
    : RVInstI<funct3, OPC_SIG_LOAD, (outs regclass:$rd), (ins regclass:$rs1, simm12:$imm12),
              opcodestr, "$rd, ${imm12}(${rs1})">;

let hasSideEffects = 0, mayLoad = 0, mayStore = 1 in
class Store_sig<bits<3> funct3, string opcodestr, RegisterClass regclass>
    : RVInstS<funct3, OPC_SIG_STORE, (outs),
              (ins regclass:$rs2, regclass:$rs1, simm12:$imm12),
              opcodestr, "$rs2, ${imm12}(${rs1})">;

// A 12-bit signed immediate where the least significant four bits are zero.
def simm12_lsb000 : Operand<XLenVT>,
                            ImmLeaf<XLenVT,
                            [{return isShiftedInt<9, 3>(Imm);}]> {
  let ParserMatchClass = SImmAsmOperand<12, "Lsb000">;
  let EncoderMethod = "getImmOpValue";
  let DecoderMethod = "decodeSImmOperand<12>";
  let MCOperandPredicate = [{
    int64_t Imm;
    if (!MCOp.evaluateAsConstantImm(Imm))
      return false;
    return isShiftedInt<9, 3>(Imm);
  }];
}

multiclass SigCheriLdPat<PatFrag LoadOp, RVInst Inst> {
  def : Pat<(LoadOp (CapRegImm GPCR:$rs1, simm12:$imm12)),
            (Inst GPCR:$rs1, simm12:$imm12)>;
}

multiclass SigCheriStPat<PatFrag StoreOp, RVInst Inst> {
  def : Pat<(StoreOp GPCR:$rs2, (CapRegImm GPCR:$rs1, simm12:$imm12)),
            (Inst GPCR:$rs2, GPCR:$rs1, simm12:$imm12)>;
}

let Predicates = [HasSigCheri, IsRV64] in {

/*

cremk       ... ... 0  ..... ..... 000 ..... 1101011 @key_op
crdmk       ... ... 1  ..... ..... 000 ..... 1101011 @key_op
cresk       ... ... 0  ..... ..... 001 ..... 1101011 @key_op
crdsk       ... ... 1  ..... ..... 001 ..... 1101011 @key_op

*/

def CREMK : RVInstPEC<encrypt_op, pec_funct3_mkey, "cremk">, Sched<[WriteIALU, ReadIALU, ReadIALU]>;
def CRDMK : RVInstPEC<decrypt_op, pec_funct3_mkey, "crdmk">, Sched<[WriteIALU, ReadIALU, ReadIALU]>;
def CRESK : RVInstPEC<encrypt_op, pec_funct3_skey, "cresk">, Sched<[WriteIALU, ReadIALU, ReadIALU]>;
def CRDSK : RVInstPEC<decrypt_op, pec_funct3_skey, "crdsk">, Sched<[WriteIALU, ReadIALU, ReadIALU]>;

def : InstAlias<"cremk.full $rd, $rs1, $rs2", (CREMK GPR:$rd, GPR:$rs1, GPR:$rs2, 0, 7)>;
def : InstAlias<"cremk.high $rd, $rs1, $rs2", (CREMK GPR:$rd, GPR:$rs1, GPR:$rs2, 4, 7)>;
def : InstAlias<"cremk.low  $rd, $rs1, $rs2", (CREMK GPR:$rd, GPR:$rs1, GPR:$rs2, 0, 3)>;
def : InstAlias<"crdmk.full $rd, $rs1, $rs2", (CRDMK GPR:$rd, GPR:$rs1, GPR:$rs2, 0, 7)>;
def : InstAlias<"crdmk.high $rd, $rs1, $rs2", (CRDMK GPR:$rd, GPR:$rs1, GPR:$rs2, 4, 7)>;
def : InstAlias<"crdmk.low  $rd, $rs1, $rs2", (CRDMK GPR:$rd, GPR:$rs1, GPR:$rs2, 0, 3)>;
def : InstAlias<"cresk.full $rd, $rs1, $rs2", (CRESK GPR:$rd, GPR:$rs1, GPR:$rs2, 0, 7)>;
def : InstAlias<"cresk.high $rd, $rs1, $rs2", (CRESK GPR:$rd, GPR:$rs1, GPR:$rs2, 4, 7)>;
def : InstAlias<"cresk.low  $rd, $rs1, $rs2", (CRESK GPR:$rd, GPR:$rs1, GPR:$rs2, 0, 3)>;
def : InstAlias<"crdsk.full $rd, $rs1, $rs2", (CRDSK GPR:$rd, GPR:$rs1, GPR:$rs2, 0, 7)>;
def : InstAlias<"crdsk.high $rd, $rs1, $rs2", (CRDSK GPR:$rd, GPR:$rs1, GPR:$rs2, 4, 7)>;
def : InstAlias<"crdsk.low  $rd, $rs1, $rs2", (CRDSK GPR:$rd, GPR:$rs1, GPR:$rs2, 0, 3)>;

}

let Predicates = [HasSigCheri, IsRV64, NotCapMode] in {

/*

  lc_tweak    ......... ... ..... 111 ..... 0011111 @sig_load_tweak_op
  sc_tweak    ....... ..... ..... 111 ..... 0101011 @s 

*/

let hasSideEffects = 1, mayLoad = 1, mayStore = 0 in 
def LC_TWEAK : RVInstLT<0b111, OPC_SIG_LOAD, (outs GPR:$rd), (ins GPR:$rs1, simm12_lsb000:$imm12, uimm3:$offsel3),
    "lc.tweak", "$rd, $offsel3, ${imm12}(${rs1})">, Sched<[WriteLDD, ReadMemBase]>;

let hasSideEffects = 0, mayLoad = 0, mayStore = 1 in
def SC_TWEAK  : RVInstS<0b111, OPC_SIG_STORE, (outs),
              (ins GPR:$rs2, GPR:$rs1, simm12:$imm12),
              "sc.tweak", "$rs2, ${imm12}(${rs1})">;

def : InstAlias<"lc.tweak $rd, ${imm12}(${rs1})", (LC_TWEAK GPR:$rd, GPR:$rs1, simm12_lsb000:$imm12, 0)>;
def : InstAlias<"lc.tweak.t0 $rd, ${imm12}(${rs1})", (LC_TWEAK GPR:$rd, GPR:$rs1, simm12_lsb000:$imm12, 0)>;
def : InstAlias<"lc.tweak.t1 $rd, ${imm12}(${rs1})", (LC_TWEAK GPR:$rd, GPR:$rs1, simm12_lsb000:$imm12, 1)>;
def : InstAlias<"lc.tweak.t2 $rd, ${imm12}(${rs1})", (LC_TWEAK GPR:$rd, GPR:$rs1, simm12_lsb000:$imm12, 2)>;
def : InstAlias<"lc.tweak.t3 $rd, ${imm12}(${rs1})", (LC_TWEAK GPR:$rd, GPR:$rs1, simm12_lsb000:$imm12, 3)>;
def : InstAlias<"lc.tweak.t4 $rd, ${imm12}(${rs1})", (LC_TWEAK GPR:$rd, GPR:$rs1, simm12_lsb000:$imm12, 4)>;
def : InstAlias<"lc.tweak.t5 $rd, ${imm12}(${rs1})", (LC_TWEAK GPR:$rd, GPR:$rs1, simm12_lsb000:$imm12, 5)>;
def : InstAlias<"lc.tweak.t6 $rd, ${imm12}(${rs1})", (LC_TWEAK GPR:$rd, GPR:$rs1, simm12_lsb000:$imm12, 6)>;

/*

lc_sig_t0   ............  ..... 000 ..... 0011111 @i
lc_sig_t1   ............  ..... 001 ..... 0011111 @i
lc_sig_t2   ............  ..... 010 ..... 0011111 @i
lc_sig_t3   ............  ..... 011 ..... 0011111 @i
lc_sig_t4   ............  ..... 100 ..... 0011111 @i
lc_sig_t5   ............  ..... 101 ..... 0011111 @i
lc_sig_t6   ............  ..... 110 ..... 0011111 @i

*/

def LC_SIG_T0 : Load_sig<0b000, "lc.sig.t0", GPR>;
def LC_SIG_T1 : Load_sig<0b001, "lc.sig.t1", GPR>;
def LC_SIG_T2 : Load_sig<0b010, "lc.sig.t2", GPR>;
def LC_SIG_T3 : Load_sig<0b011, "lc.sig.t3", GPR>;
def LC_SIG_T4 : Load_sig<0b100, "lc.sig.t4", GPR>;
def LC_SIG_T5 : Load_sig<0b101, "lc.sig.t5", GPR>;
def LC_SIG_T6 : Load_sig<0b110, "lc.sig.t6", GPR>;

/*

sc_sig_t0   .......  .....   ..... 000 ..... 0101011 @s
sc_sig_t1   .......  .....   ..... 001 ..... 0101011 @s
sc_sig_t2   .......  .....   ..... 010 ..... 0101011 @s
sc_sig_t3   .......  .....   ..... 011 ..... 0101011 @s
sc_sig_t4   .......  .....   ..... 100 ..... 0101011 @s
sc_sig_t5   .......  .....   ..... 101 ..... 0101011 @s
sc_sig_t6   .......  .....   ..... 110 ..... 0101011 @s 

*/

def SC_SIG_T0 : Store_sig<0b000, "sc.sig.t0", GPR>;
def SC_SIG_T1 : Store_sig<0b001, "sc.sig.t1", GPR>;
def SC_SIG_T2 : Store_sig<0b010, "sc.sig.t2", GPR>;
def SC_SIG_T3 : Store_sig<0b011, "sc.sig.t3", GPR>;
def SC_SIG_T4 : Store_sig<0b100, "sc.sig.t4", GPR>;
def SC_SIG_T5 : Store_sig<0b101, "sc.sig.t5", GPR>;
def SC_SIG_T6 : Store_sig<0b110, "sc.sig.t6", GPR>;

def : InstAlias<"lc.sig $rd, ${imm12}(${rs1})", (LC_SIG_T0 GPR:$rd, GPR:$rs1, simm12:$imm12)>;
def : InstAlias<"sc.sig $rd, ${imm12}(${rs1})", (SC_SIG_T0 GPR:$rd, GPR:$rs1, simm12:$imm12)>;

}

let Predicates = [HasCheri, HasSigCheri, IsRV64, IsCapMode] in {
let DecoderNamespace = "CapModeOnly_" in {
/*

  lc_tweak    ......... ... ..... 111 ..... 0011111 @sig_load_tweak_op
  sc_tweak    ....... ..... ..... 111 ..... 0101011 @s 

*/


let hasSideEffects = 1, mayLoad = 1, mayStore = 0 in 
def CLC_TWEAK : RVInstLT<0b111, OPC_SIG_LOAD, (outs GPR:$rd), (ins GPCR:$rs1, simm12_lsb000:$imm12, uimm3:$offsel3),
    "clc.tweak", "$rd, $offsel3, ${imm12}(${rs1})">, Sched<[WriteLDD, ReadMemBase]>;

let hasSideEffects = 0, mayLoad = 0, mayStore = 1 in
def CSC_TWEAK  : RVInstS<0b111, OPC_SIG_STORE, (outs),
              (ins GPR:$rs2, GPCR:$rs1, simm12:$imm12),
              "csc.tweak", "$rs2, ${imm12}(${rs1})">;

/*

lc_sig_t0   ............  ..... 000 ..... 0011111 @i
lc_sig_t1   ............  ..... 001 ..... 0011111 @i
lc_sig_t2   ............  ..... 010 ..... 0011111 @i
lc_sig_t3   ............  ..... 011 ..... 0011111 @i
lc_sig_t4   ............  ..... 100 ..... 0011111 @i
lc_sig_t5   ............  ..... 101 ..... 0011111 @i
lc_sig_t6   ............  ..... 110 ..... 0011111 @i

*/

def CLC_SIG_T0 : Load_sig<0b000, "clc.sig.t0", GPCR>;
def CLC_SIG_T1 : Load_sig<0b001, "clc.sig.t1", GPCR>;
def CLC_SIG_T2 : Load_sig<0b010, "clc.sig.t2", GPCR>;
def CLC_SIG_T3 : Load_sig<0b011, "clc.sig.t3", GPCR>;
def CLC_SIG_T4 : Load_sig<0b100, "clc.sig.t4", GPCR>;
def CLC_SIG_T5 : Load_sig<0b101, "clc.sig.t5", GPCR>;
def CLC_SIG_T6 : Load_sig<0b110, "clc.sig.t6", GPCR>;

/*

sc_sig_t0   .......  .....   ..... 000 ..... 0101011 @s
sc_sig_t1   .......  .....   ..... 001 ..... 0101011 @s
sc_sig_t2   .......  .....   ..... 010 ..... 0101011 @s
sc_sig_t3   .......  .....   ..... 011 ..... 0101011 @s
sc_sig_t4   .......  .....   ..... 100 ..... 0101011 @s
sc_sig_t5   .......  .....   ..... 101 ..... 0101011 @s
sc_sig_t6   .......  .....   ..... 110 ..... 0101011 @s 

*/

def CSC_SIG_T0 : Store_sig<0b000, "csc.sig.t0", GPCR>;
def CSC_SIG_T1 : Store_sig<0b001, "csc.sig.t1", GPCR>;
def CSC_SIG_T2 : Store_sig<0b010, "csc.sig.t2", GPCR>;
def CSC_SIG_T3 : Store_sig<0b011, "csc.sig.t3", GPCR>;
def CSC_SIG_T4 : Store_sig<0b100, "csc.sig.t4", GPCR>;
def CSC_SIG_T5 : Store_sig<0b101, "csc.sig.t5", GPCR>;
def CSC_SIG_T6 : Store_sig<0b110, "csc.sig.t6", GPCR>;

}

def PseudoCLGC_SIG_T0 : Pseudo<(outs GPCR:$dst), (ins bare_symbol:$src), [],
                        "clgc.sig.t0", "$dst, $src">;

let Predicates = [IsSigCapMode] in { 
defm : SigCheriLdPat<load, CLC_SIG_T0>;
defm : SigCheriStPat<store, CSC_SIG_T0>;
def : Pat<(riscv_clgc tglobaladdr:$in), (PseudoCLGC_SIG_T0 tglobaladdr:$in)>;
}

def : InstAlias<"clc.tweak $rd, ${imm12}(${rs1})", (CLC_TWEAK GPR:$rd, GPCR:$rs1, simm12_lsb000:$imm12, 0)>;
def : InstAlias<"clc.tweak.t0 $rd, ${imm12}(${rs1})", (CLC_TWEAK GPR:$rd, GPCR:$rs1, simm12_lsb000:$imm12, 0)>;
def : InstAlias<"clc.tweak.t1 $rd, ${imm12}(${rs1})", (CLC_TWEAK GPR:$rd, GPCR:$rs1, simm12_lsb000:$imm12, 1)>;
def : InstAlias<"clc.tweak.t2 $rd, ${imm12}(${rs1})", (CLC_TWEAK GPR:$rd, GPCR:$rs1, simm12_lsb000:$imm12, 2)>;
def : InstAlias<"clc.tweak.t3 $rd, ${imm12}(${rs1})", (CLC_TWEAK GPR:$rd, GPCR:$rs1, simm12_lsb000:$imm12, 3)>;
def : InstAlias<"clc.tweak.t4 $rd, ${imm12}(${rs1})", (CLC_TWEAK GPR:$rd, GPCR:$rs1, simm12_lsb000:$imm12, 4)>;
def : InstAlias<"clc.tweak.t5 $rd, ${imm12}(${rs1})", (CLC_TWEAK GPR:$rd, GPCR:$rs1, simm12_lsb000:$imm12, 5)>;
def : InstAlias<"clc.tweak.t6 $rd, ${imm12}(${rs1})", (CLC_TWEAK GPR:$rd, GPCR:$rs1, simm12_lsb000:$imm12, 6)>;

def : InstAlias<"clc.sig $rd, ${imm12}(${rs1})", (CLC_SIG_T0 GPCR:$rd, GPCR:$rs1, simm12:$imm12)>;
def : InstAlias<"csc.sig $rd, ${imm12}(${rs1})", (CSC_SIG_T0 GPCR:$rd, GPCR:$rs1, simm12:$imm12)>;
def : InstAlias<"clgc.sig $rd, $label", (PseudoCLGC_SIG_T0 GPCR:$rd, bare_symbol:$label)>;

}