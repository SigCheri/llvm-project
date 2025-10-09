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