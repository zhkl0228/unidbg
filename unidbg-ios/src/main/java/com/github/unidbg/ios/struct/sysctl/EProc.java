package com.github.unidbg.ios.struct.sysctl;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

/**
 * eproc
 */
public class EProc extends UnidbgStructure {

    private static final int WMESGLEN = 7;
    private static final int COMAPT_MAXLOGNAME = 12;

    public EProc(Pointer p) {
        super(p);
    }

    public Pointer e_paddr; /* address of proc */
    public Pointer e_sess; /* session pointer */
    public Pcred e_pcred; /* process credentials */
    public Ucred e_ucred; /* current credentials */
    public VmSpace e_vm; /* address space */
    public int e_ppid; /* parent process id */
    public int e_pgid; /* process group id */
    public short e_jobc; /* job control counter */
    public int e_tdev; /* controlling tty dev */
    public int e_tpgid; /* tty process group id */
    public Pointer e_tsess; /* tty session pointer */
    public byte[] e_wmesg = new byte[WMESGLEN + 1]; /* wchan message */
    public int e_xsize; /* text size */
    public short e_xrssize; /* text rss */
    public short e_xccount; /* text references */
    public short e_xswrss;
    public int e_flag;
    public byte[] e_login = new byte[COMAPT_MAXLOGNAME]; /* short setlogin() name */
    public int[] e_spare = new int[4];

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("e_paddr", "e_sess", "e_pcred", "e_ucred", "e_vm", "e_ppid", "e_pgid", "e_jobc",
                "e_tdev", "e_tpgid", "e_tsess", "e_wmesg", "e_xsize", "e_xrssize", "e_xccount", "e_xswrss",
                "e_flag", "e_login", "e_spare");
    }

}
