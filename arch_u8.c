#include <r_lib.h>
#include <r_asm.h>
#include <r_arch.h>

#include "u8_disas.h"

static bool decode_u8(RArchSession *s, RAnalOp *op, RArchDecodeMask mask) {
	ut64 addr = op->addr;
	ut8 *buf = op->bytes;
	int len = op->size;

	int ret;
	struct u8_cmd cmd;
	memset (&cmd, '\0', sizeof(struct u8_cmd));
	
	memset (op, '\0', sizeof(RAnalOp));
	op->size = -1;
	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->family = R_ANAL_OP_FAMILY_CPU;
	op->stackop = R_ANAL_STACK_NULL;
	op->jump = op->fail = -1;
	op->ptr = op->val = -1;
	op->refptr = 0;

	ret = op->size = u8_decode_opcode(buf, len, &cmd);

	// Set command mnemonic
	op->mnemonic = r_str_newf("%s %s", cmd.instr, cmd.operands);

	if(ret < 0)
		return ret;

	switch(cmd.type)
	{
		// ADD instructions
		case U8_ADD_R:
		case U8_ADDC_R:
		case U8_ADD_O:
		case U8_ADDC_O:
		case U8_ADD_ER:
		case U8_ADD_ER_O:
		case U8_ADD_SP_O:
			op->type = R_ANAL_OP_TYPE_ADD; break;

		// AND instructions
		case U8_AND_R:
		case U8_AND_O:
			op->type = R_ANAL_OP_TYPE_AND; break;

		// CMP instructions
		case U8_CMP_R:
		case U8_CMPC_R:
		case U8_CMP_O:
		case U8_CMPC_O:
		case U8_CMP_ER:
			op->type = R_ANAL_OP_TYPE_CMP; break;

		// Register MOV instructions
		case U8_MOV_R:
		case U8_MOV_O:
		case U8_MOV_ER:
		case U8_MOV_ER_O:
		case U8_MOV_ECSR_R:
		case U8_MOV_ELR_ER:
		case U8_MOV_EPSW_R:
		case U8_MOV_ER_ELR:
		case U8_MOV_ER_SP:
		case U8_MOV_PSW_R:
		case U8_MOV_PSW_O:
		case U8_MOV_R_ECSR:
		case U8_MOV_R_EPSW:
		case U8_MOV_R_PSW:
		case U8_MOV_SP_ER:

		// Coprocessor MOV instructions
		case U8_MOV_CR_R:
		case U8_MOV_CER_EA:
		case U8_MOV_CER_EAP:
		case U8_MOV_CR_EA:
		case U8_MOV_CR_EAP:
		case U8_MOV_CXR_EA:
		case U8_MOV_CXR_EAP:
		case U8_MOV_CQR_EA:
		case U8_MOV_CQR_EAP:
		case U8_MOV_R_CR:
		case U8_MOV_EA_CER:
		case U8_MOV_EAP_CER:
		case U8_MOV_EA_CR:
		case U8_MOV_EAP_CR:
		case U8_MOV_EA_CXR:
		case U8_MOV_EAP_CXR:
		case U8_MOV_EA_CQR:
			op->type = R_ANAL_OP_TYPE_MOV; break;
		case U8_OR_R:
		case U8_OR_O:
			op->type = R_ANAL_OP_TYPE_OR; break;
		case U8_XOR_R:
		case U8_XOR_O:
			op->type = R_ANAL_OP_TYPE_XOR; break;
		case U8_SUB_R:
		case U8_SUBC_R:
			op->type = R_ANAL_OP_TYPE_SUB; break;
		case U8_SLL_R:
		case U8_SLLC_R:
		case U8_SLL_O:
		case U8_SLLC_O:
			op->type = R_ANAL_OP_TYPE_SHL; break;
		case U8_SRA_R:
		case U8_SRA_O:
			op->type = R_ANAL_OP_TYPE_SAR; break;
		case U8_SRL_R:
		case U8_SRLC_R:
		case U8_SRL_O:
		case U8_SRLC_O:
			op->type = R_ANAL_OP_TYPE_SHR; break;

		// Load instructions
		case U8_L_ER_EA:
		case U8_L_ER_EAP:
		case U8_L_ER_ER:
		case U8_L_ER_D16_ER:
		case U8_L_ER_D6_BP:
		case U8_L_ER_D6_FP:
		case U8_L_ER_DA:
		case U8_L_R_EA:
		case U8_L_R_EAP:
		case U8_L_R_ER:
		case U8_L_R_D16_ER:
		case U8_L_R_D6_BP:
		case U8_L_R_D6_FP:
		case U8_L_R_DA:
		case U8_L_XR_EA:
		case U8_L_XR_EAP:
		case U8_L_QR_EA:
		case U8_L_QR_EAP:
			op->type = R_ANAL_OP_TYPE_LOAD; break;

		// Store instructions
		case U8_ST_ER_EA:
		case U8_ST_ER_EAP:
		case U8_ST_ER_ER:
		case U8_ST_ER_D16_ER:
		case U8_ST_ER_D6_BP:
		case U8_ST_ER_D6_FP:
		case U8_ST_ER_DA:
		case U8_ST_R_EA:
		case U8_ST_R_EAP:
		case U8_ST_R_ER:
		case U8_ST_R_D16_ER:
		case U8_ST_R_D6_BP:
		case U8_ST_R_D6_FP:
		case U8_ST_R_DA:
		case U8_ST_XR_EA:
		case U8_ST_XR_EAP:
		case U8_ST_QR_EA:
		case U8_ST_QR_EAP:
			op->type = R_ANAL_OP_TYPE_STORE; break;

		// Push/pop instructions
		case U8_PUSH_ER:
		case U8_PUSH_QR:
		case U8_PUSH_R:
		case U8_PUSH_XR:
			op->stackop = R_ANAL_STACK_SET; 	// is this useful?
			op->type = R_ANAL_OP_TYPE_PUSH; break;
		case U8_POP_ER:
		case U8_POP_QR:
		case U8_POP_R:
		case U8_POP_XR:
			op->stackop = R_ANAL_STACK_GET;
			op->type = R_ANAL_OP_TYPE_POP; break;

		// Register list stack instructions
		// FIXME: programming model could be established here, from use of CSR, LCSR, ECSR
		case U8_PUSH_RL:
			op->type = R_ANAL_OP_TYPE_PUSH; break;

		case U8_POP_RL:
			// certain types of 'pop' may act as subroutine or interrupt returns
			// (see nX-U8/100 Core Ref. Ch.1, S.4 - Exception Levels and Backup Registers)
			switch(cmd.op1)
			{
				// FIXME: investigate 3, 7, a, b, f (also include pc).
				case 0x2:	// pc (return type A-2)
				case 0x6:	// psw, pc (return types B-1-2, C-1)
				case 0xe:	// pc, psw, lr (return types B-2-2, C-2)
					op->type = R_ANAL_OP_TYPE_RET;
					break;

				default:
					op->type = R_ANAL_OP_TYPE_POP;
					break;
			}
			break;

		// EA register data transfer instructions
		case U8_LEA_ER:
		case U8_LEA_D16_ER:
		case U8_LEA_DA:
			op->type = R_ANAL_OP_TYPE_LEA; break;

		// ALU Instructions
		case U8_DAA_R:
		case U8_DAS_R:
		case U8_NEG_R:
			op->type = R_ANAL_OP_TYPE_NULL; break;

		// Bit access instructions
		case U8_SB_R:
		case U8_RB_R:
		case U8_TB_R:
		case U8_SB_DBIT:
		case U8_RB_DBIT:
		case U8_TB_DBIT:
			op->type = R_ANAL_OP_TYPE_NULL; break;

		// PSW access instructions      (no operands)
		case U8_EI:
		case U8_DI:
		case U8_SC:
		case U8_RC:
		case U8_CPLC:
			op->type = R_ANAL_OP_TYPE_NULL; break;

		// Conditional relative branch instructions
		case U8_BGE_RAD:
		case U8_BLT_RAD:
		case U8_BGT_RAD:
		case U8_BLE_RAD:
		case U8_BGES_RAD:
		case U8_BLTS_RAD:
		case U8_BGTS_RAD:
		case U8_BLES_RAD:
		case U8_BNE_RAD:
		case U8_BEQ_RAD:
		case U8_BNV_RAD:
		case U8_BOV_RAD:
		case U8_BPS_RAD:
		case U8_BNS_RAD:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = addr + sizeof(cmd.opcode) + 		// next instruction word, plus
				((st8)cmd.op1 * sizeof(cmd.opcode));	//   op1 words (+ive or -ive)
			op->fail = addr + sizeof(cmd.opcode);
			break;
		case U8_BAL_RAD:
			op->type = R_ANAL_OP_TYPE_JMP;
			op->jump = addr + sizeof(cmd.opcode) +		// next instruction word
				((st8)cmd.op1 * sizeof(cmd.opcode));	//   op1 words (+ive or -ive)
				// cannot fail
			break;
		// Sign extension instruction
		case U8_EXTBW_ER:
			op->type = R_ANAL_OP_TYPE_NULL; break;

		// Software interrupt instructions
		case U8_SWI_O:
			op->type = R_ANAL_OP_TYPE_SWI; break;
		case U8_BRK:
			op->type = R_ANAL_OP_TYPE_TRAP; break;
		
		// Branch instructions
		case U8_B_AD:
			op->jump = (cmd.op1 * 0x10000) + cmd.s_word;
			op->type = R_ANAL_OP_TYPE_JMP; break;
		case U8_BL_AD:
			// simulate segment register
			op->jump = (cmd.op1 * 0x10000) + cmd.s_word;
			op->type = R_ANAL_OP_TYPE_CALL; break;
		case U8_B_ER:
			op->type = R_ANAL_OP_TYPE_RJMP; break;
		case U8_BL_ER:
			op->type = R_ANAL_OP_TYPE_RCALL; break;

		// Multiplication and division instructions
		case U8_MUL_ER:
			op->type = R_ANAL_OP_TYPE_MUL; break;
		case U8_DIV_ER:
			op->type = R_ANAL_OP_TYPE_DIV; break;

		// Miscellaneous (no operands)
		case U8_INC_EA:
		case U8_DEC_EA:
			op->type = R_ANAL_OP_TYPE_NULL; break;
			break;

		// Return instructions
		case U8_RT:
		case U8_RTI:
			op->type = R_ANAL_OP_TYPE_RET; break;
		case U8_NOP:
			op->type = R_ANAL_OP_TYPE_NOP; break;

		case U8_ILL:
		default:
			op->type = R_ANAL_OP_TYPE_ILL;

	}
	return op->size;
}

static char *regs(RArchSession *as) {
	const char *const p =
		"=PC	pc\n"
		"=SP	sp\n"
		"=BP    er12\n"
		"=LR    lr\n"
		"=A0    er0\n"
		"=SN    r0\n"	// Doesn't have syscalls but this stops r2 screaming

		// R0-R15
		"gpr    r0    .8  0   0\n"
		"gpr    r1    .8  1   0\n"
		"gpr    r2    .8  2   0\n"
		"gpr    r3    .8  3   0\n"
		"gpr    r4    .8  4   0\n"
		"gpr    r5    .8  5   0\n"
		"gpr    r6    .8  6   0\n"
		"gpr    r7    .8  7   0\n"
		"gpr    r8    .8  8   0\n"
		"gpr    r9    .8  9   0\n"
		"gpr    r10   .8  10  0\n"
		"gpr    r11   .8  11  0\n"
		"gpr    r12   .8  12  0\n"
		"gpr    r13   .8  13  0\n"
		"gpr    r14   .8  14  0\n"
		"gpr    r15   .8  15  0\n"

		// ER0-ER14
		"gpr    er0   .16 0   0\n"
		"gpr    er2   .16 2   0\n"
		"gpr    er4   .16 4   0\n"
		"gpr    er6   .16 6   0\n"
		"gpr    er8   .16 8   0\n"
		"gpr    er10  .16 10  0\n"
		"gpr    er12  .16 12  0\n"
		"gpr    er14  .16 14  0\n"

		// XR0-XR12
		"gpr    xr0   .32 0   0\n"
		"gpr    xr4   .32 4   0\n"
		"gpr    xr8   .32 8   0\n"
		"gpr    xr12  .32 12  0\n"

		// QR0-QR8
		"gpr    qr0   .64 0   0\n"
		"gpr    qr8   .64 8   0\n"

		// Control Registers
		"gpr    pc    .16 16  0\n"
		"gpr    sp    .16 18  0\n"
		"gpr    ea    .16 20  0\n"
		
		"gpr    lr    .16 22  0\n"
		"gpr    elr1  .16 24  0\n"
		"gpr    elr2  .16 26  0\n"
		"gpr    elr3  .16 28  0\n";
	return strdup (p);
}

RArchPlugin r_arch_plugin_u8 = {
	.name = "u8",
	.desc = "nX-U8/100 analysis plugin",
	.license = "LGPL3",
	.arch = "u8",
	.bits = 16,
	.endian = R_SYS_ENDIAN_LITTLE,
	.decode = &decode_u8,
	.regs = &regs
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_u8,
	.version = R2_VERSION
};
#endif
