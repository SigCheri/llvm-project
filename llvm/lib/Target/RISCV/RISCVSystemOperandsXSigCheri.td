//===- RISCVSystemOperandsXSigCheri.td ------------------------*- tablegen -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file defines the symbolic operands permitted for various kinds of
// SIGCHERI RISC-V system instruction.
//
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
// SIGCHERI CSR (control and status register read/write) instruction options.
//===----------------------------------------------------------------------===//

//===--------------------------
// Machine Key Register
//===--------------------------
def : SysReg<"mkeyl", 0x7F0>;
def : SysReg<"mkeyh", 0x7F1>;

//===--------------------------
// Supervisor Key Register
//===--------------------------
def : SysReg<"skeyl", 0x5F0>;
def : SysReg<"skeyh", 0x5F1>;

//===--------------------------
// Tweak Offset Register
//===--------------------------
def : SysReg<"tweakoff0", 0x1F0>;
def : SysReg<"tweakoff1", 0x1F1>;
def : SysReg<"tweakoff2", 0x1F2>;
def : SysReg<"tweakoff3", 0x1F3>;
def : SysReg<"tweakoff4", 0x1F4>;
def : SysReg<"tweakoff5", 0x1F5>;
def : SysReg<"tweakoff6", 0x1F6>;