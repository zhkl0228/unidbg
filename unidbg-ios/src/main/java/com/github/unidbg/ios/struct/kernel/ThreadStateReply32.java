package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class ThreadStateReply32 extends UnidbgStructure {

    public static class ThreadState32 extends UnidbgStructure {

        public ThreadState32(Pointer p) {
            super(p);
        }
        public int[] __r = new int[13]; /* General purpose register r0-r12 */
        public int __sp; /* Stack pointer r13 */
        public int __lr; /* Link register r14 */
        public int __pc; /* Program counter r15 */
        public int __cpsr; /* Current program status register */

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("__r", "__sp", "__lr", "__pc", "__cpsr");
        }
    }

    public ThreadStateReply32(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public int retCode;
    public int outCnt;
    public ThreadState32 state;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "retCode", "outCnt", "state");
    }

}
