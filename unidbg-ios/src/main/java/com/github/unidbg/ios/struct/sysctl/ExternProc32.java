package com.github.unidbg.ios.struct.sysctl;

import com.github.unidbg.pointer.UnidbgStructure;
import com.github.unidbg.unix.struct.ITimerVal32;
import com.github.unidbg.unix.struct.TimeVal32;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

/**
 * extern_proc
 */
public class ExternProc32 extends UnidbgStructure {

    private static final int MAXCOMLEN = 16; /* max command name remembered */

    public ExternProc32(Pointer p) {
        super(p);
    }

    public Pointer __p_forw;
    public Pointer __p_back;

    public Pointer p_vmspace; /* Address space. */
    public Pointer p_sigacts; /* Signal actions, state (PROC ONLY). */

    public int p_flag; /* P_* flags. */
    public byte p_stat; /* S* process status. */

    public int p_pid; /* Process identifier. */
    public int p_oppid; /* Save parent pid during ptrace. XXX */

    public int p_dupfd; /* Sideways return value from fdopen. XXX */

    public Pointer user_stack; /* where user stack was allocated */
    public Pointer exit_thread; /* XXX Which thread is exiting? */

    public int p_debugger; /* allow to debug */
    public boolean sigwait; /* indication to suspend */
    public int p_estcpu; /* Time averaged value of p_cpticks. */
    public int p_cpticks; /* Ticks of cpu time. */
    public int p_pctcpu; /* %cpu for this process during p_swtime */

    public Pointer p_wchan; /* Sleep address. */
    public Pointer p_wmesg; /* Reason for sleep. */

    public int p_swtime; /* Time swapped in or out. */
    public int p_slptime; /* Time since last blocked. */

    public ITimerVal32 p_realtimer; /* Alarm timer. */
    public TimeVal32 p_rtime; /* Real time. */

    public long p_uticks; /* Statclock hits in user mode. */
    public long p_sticks; /* Statclock hits in system mode. */
    public long p_iticks; /* Statclock hits processing intr. */

    public int p_traceflag; /* Kernel trace points. */
    public Pointer p_tracep; /* Trace to vnode. */
    public int p_siglist;
    public Pointer p_textvp; /* Vnode of executable. */
    public int p_holdcnt; /* If non-zero, don't swap. */

    public int p_sigmask;
    public int p_sigignore; /* Signals being ignored. */
    public int p_sigcatch; /* Signals being caught by user. */

    public byte p_priority; /* Process priority. */
    public byte p_usrpri; /* User-priority based on p_cpu and p_nice. */
    public byte p_nice; /* Process "nice" value. */
    public byte[] p_comm = new byte[MAXCOMLEN + 1];

    public Pointer p_pgrp; /* Pointer to process group. */
    public Pointer p_addr; /* Kernel virtual addr of u-area (PROC ONLY). */
    public short p_xstat; /* Exit status for wait; also stop signal. */
    public short p_acflag; /* Accounting flags. */
    public Pointer p_ru; /* Exit information. XXX */

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("__p_forw", "__p_back", "p_vmspace", "p_sigacts", "p_flag", "p_stat",
                "p_pid", "p_oppid", "p_dupfd", "user_stack", "exit_thread", "p_debugger",
                "sigwait", "p_estcpu", "p_cpticks", "p_pctcpu", "p_wchan", "p_wmesg",
                "p_swtime", "p_slptime", "p_realtimer", "p_rtime", "p_uticks", "p_sticks", "p_iticks",
                "p_traceflag", "p_tracep", "p_siglist", "p_textvp", "p_holdcnt", "p_sigmask", "p_sigignore", "p_sigcatch",
                "p_priority", "p_usrpri", "p_nice", "p_comm", "p_pgrp", "p_addr", "p_xstat", "p_acflag", "p_ru");
    }
}
