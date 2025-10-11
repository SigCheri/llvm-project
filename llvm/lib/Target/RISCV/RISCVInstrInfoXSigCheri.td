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

let Predicates = [HasSigCheri] in {

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
def : InstAlias<"cremk.low $rd, $rs1, $rs2",  (CREMK GPR:$rd, GPR:$rs1, GPR:$rs2, 0, 3)>;
def : InstAlias<"crdmk.full $rd, $rs1, $rs2", (CRDMK GPR:$rd, GPR:$rs1, GPR:$rs2, 0, 7)>;
def : InstAlias<"crdmk.high $rd, $rs1, $rs2", (CRDMK GPR:$rd, GPR:$rs1, GPR:$rs2, 4, 7)>;
def : InstAlias<"crdmk.low $rd, $rs1, $rs2",  (CRDMK GPR:$rd, GPR:$rs1, GPR:$rs2, 0, 3)>;
def : InstAlias<"cresk.full $rd, $rs1, $rs2", (CRESK GPR:$rd, GPR:$rs1, GPR:$rs2, 0, 7)>;
def : InstAlias<"cresk.high $rd, $rs1, $rs2", (CRESK GPR:$rd, GPR:$rs1, GPR:$rs2, 4, 7)>;
def : InstAlias<"cresk.low $rd, $rs1, $rs2",  (CRESK GPR:$rd, GPR:$rs1, GPR:$rs2, 0, 3)>;
def : InstAlias<"crdsk.full $rd, $rs1, $rs2", (CRDSK GPR:$rd, GPR:$rs1, GPR:$rs2, 0, 7)>;
def : InstAlias<"crdsk.high $rd, $rs1, $rs2", (CRDSK GPR:$rd, GPR:$rs1, GPR:$rs2, 4, 7)>;
def : InstAlias<"crdsk.low $rd, $rs1, $rs2",  (CRDSK GPR:$rd, GPR:$rs1, GPR:$rs2, 0, 3)>;

}