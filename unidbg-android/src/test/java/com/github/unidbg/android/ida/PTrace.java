package com.github.unidbg.android.ida;

public interface PTrace {

    int PTRACE_PEEKTEXT = 1;
    int PTRACE_PEEKUSR = 3;
    int PTRACE_POKETEXT = 4;
    int PTRACE_POKEDATA = 5;
    int PTRACE_CONT = 7;
    int PTRACE_KILL = 8;
    int PTRACE_GETREGS = 12;
    int PTRACE_ATTACH = 16;
    int PTRACE_DETACH = 17;

    int PTRACE_GETREGSET = 0x4204;

    int NT_PRSTATUS	= 1;		/* Contains copy of prstatus struct */

}
