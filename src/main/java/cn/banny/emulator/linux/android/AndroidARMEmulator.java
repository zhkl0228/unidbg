package cn.banny.emulator.linux.android;

import cn.banny.emulator.arm.AbstractARMEmulator;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.UnicornConst;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * android arm emulator
 * Created by zhkl0228 on 2017/5/2.
 */

public class AndroidARMEmulator extends AbstractARMEmulator {

    private static final Log log = LogFactory.getLog(AndroidARMEmulator.class);

    public AndroidARMEmulator() {
        this(null);
    }

    public AndroidARMEmulator(String processName) {
        super(processName);

        setupTraps();
    }

    /**
     * https://github.com/lunixbochs/usercorn/blob/master/go/arch/arm/linux.go
     */
    private void setupTraps() {
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.Arm)) {
            unicorn.mem_map(LR, 0x10000, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_EXEC);
            KeystoneEncoded encoded = keystone.assemble("mov pc, #0");
            byte[] b0 = encoded.getMachineCode();
            ByteBuffer buffer = ByteBuffer.allocate(0x10000);
            // write "mov pc, #0" to all kernel trap addresses so they will throw exception
            for (int i = 0; i < 0x10000; i += 4) {
                buffer.put(b0);
            }
            unicorn.mem_write(LR, buffer.array());

            encoded = keystone.assemble("bx lr", 0xffff0fa0);
            byte[] __kuser_memory_barrier = encoded.getMachineCode();

            encoded = keystone.assemble(Arrays.asList(
                    "dmb sy",
                    "ldrex r3, [r2]",
                    "subs r3, r3, r0",
                    "strexeq r3, r1, [r2]",
                    "teqeq r3, #1",
                    "beq #0xffff0fc4",
                    "rsbs r0, r3, #0",
                    "b #0xffff0fa0"), 0xffff0fc0);
            byte[] __kuser_cmpxchg = encoded.getMachineCode();
            unicorn.mem_write(0xffff0fa0L, __kuser_memory_barrier);
            unicorn.mem_write(0xffff0fc0L, __kuser_cmpxchg);

            if (log.isDebugEnabled()) {
                log.debug("__kuser_memory_barrier");
                for (int i = 0; i < __kuser_memory_barrier.length; i += 4) {
                    printAssemble(0xffff0fa0L + i, 4);
                }
                log.debug("__kuser_cmpxchg");
                for (int i = 0; i < __kuser_cmpxchg.length; i += 4) {
                    printAssemble(0xffff0fc0L + i, 4);
                }
            }
        }
    }

}
