package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.ios.DarwinSyscall;
import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class ProcBsdShortInfo extends UnidbgStructure implements DarwinSyscall {

    public static final int SRUN = 2; /* Currently runnable. */
    public static final int P_SUGID = 0x00000100; /* Has set privileges since last exec */

    public ProcBsdShortInfo(Pointer p) {
        super(p);
    }

    public int pbsi_pid; /* process id */
    public int pbsi_ppid; /* process parent id */
    public int pbsi_pgid; /* process perp id */
    public int pbsi_status; /* p_stat value, SZOMB, SRUN, etc */
    public byte[] pbsi_comm = new byte[MAXCOMLEN]; /* upto 16 characters of process name */
    public int pbsi_flags; /* 64bit; emulated etc */
    public int pbsi_uid; /* current uid on process */
    public int pbsi_gid; /* current gid on process */
    public int pbsi_ruid; /* current ruid on process */
    public int pbsi_rgid; /* current tgid on process */
    public int pbsi_svuid; /* current svuid on process */
    public int pbsi_svgid; /* current svgid on process */
    public int pbsi_rfu; /* reserved for future use*/

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("pbsi_pid", "pbsi_ppid", "pbsi_pgid", "pbsi_status", "pbsi_comm", "pbsi_flags",
                "pbsi_uid", "pbsi_gid", "pbsi_ruid", "pbsi_rgid", "pbsi_svuid", "pbsi_svgid", "pbsi_rfu");
    }
}
