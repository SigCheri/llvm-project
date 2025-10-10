
class RVInstKey<bit cryptoOp, bits<3> funct3, RISCVOpcode opcode, dag outs, dag ins, string opcodestr,
              string argstr>
    : RVInst<outs, ins, opcodestr, argstr, [], InstFormatKey> {
  bits<3> startByte;
  bits<3> endByte;
  bits<5> rs2;
  bits<5> rs1;
  bits<5> rd;

  let Inst{31-29} = endByte;
  let Inst{28-26} = startByte;
  let Inst{25} = cryptoOp;
  let Inst{24-20} = rs2;
  let Inst{19-15} = rs1;
  let Inst{14-12} = funct3;
  let Inst{11-7} = rd;
  let Opcode = opcode.Value;
}




