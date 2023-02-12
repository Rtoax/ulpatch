#include <stdio.h>
#include <dis-asm.h>

int main(int argc, char *argv[])
{
	struct disassemble_info disasm_info;

	init_disassemble_info(&disasm_info, stdout, (fprintf_ftype)fprintf);

	return 0;
}

