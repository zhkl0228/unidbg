package com.github.unidbg.arm;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.NewFileIO;

/**
 * arm emulator
 * Created by zhkl0228 on 2017/5/2.
 */

public interface ARMEmulator<T extends NewFileIO> extends Emulator<T> {

    // From http://infocenter.arm.com/help/topic/com.arm.doc.ihi0044f/IHI0044F_aaelf.pdf

    /**
     * 用户模式
     */
    int USR_MODE = 0b10000;

    /**
     * 管理模式
     */
    int SVC_MODE = 0b10011;

    int R_ARM_ABS32 = 2;
    int R_ARM_REL32 = 3;
    int R_ARM_COPY = 20;
    int R_ARM_GLOB_DAT = 21;
    int R_ARM_JUMP_SLOT = 22;
    int R_ARM_RELATIVE = 23;
    int R_ARM_IRELATIVE = 160;

    int R_AARCH64_ABS64 = 257;
    int R_AARCH64_ABS32 = 258;
    int R_AARCH64_ABS16 = 259;
    int R_AARCH64_PREL64 = 260;
    int R_AARCH64_PREL32 = 261;
    int R_AARCH64_PREL16 = 262;
    int R_AARCH64_COPY = 1024;
    int R_AARCH64_GLOB_DAT = 1025;
    int R_AARCH64_JUMP_SLOT = 1026;
    int R_AARCH64_RELATIVE = 1027;
    int R_AARCH64_TLS_TPREL64 = 1030;
    int R_AARCH64_TLS_DTPREL32 = 1031;
    int R_AARCH64_IRELATIVE = 1032;

    int PAGE_ALIGN = 0x1000; // 4k

    int EXCP_SWI = 2; /* software interrupt */
    int EXCP_BKPT = 7;

}
