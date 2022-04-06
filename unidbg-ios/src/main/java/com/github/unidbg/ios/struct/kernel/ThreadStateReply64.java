package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class ThreadStateReply64 extends UnidbgStructure {

    public static class ThreadState64 extends UnidbgStructure {
        public ThreadState64(Pointer p) {
            super(p);
        }
        public long[] __x = new long[29]; /* General purpose registers x0-x28 */
        public long __fp; /* Frame pointer x29 */
        public long __lr; /* Link register x30 */
        public long __sp; /* Stack pointer x31 */
        public long __pc; /* Program counter */
        public int __cpsr; /* Current program status register */
        public int __pad; /* Same size for 32-bit or 64-bit clients */

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("__x", "__fp", "__lr", "__sp", "__pc", "__cpsr", "__pad");
        }
    }

    public ThreadStateReply64(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public int retCode;
    public int outCnt;
    public ThreadState64 state;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "retCode", "outCnt", "state");
    }
}
