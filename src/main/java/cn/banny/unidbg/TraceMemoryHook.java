package cn.banny.unidbg;

import cn.banny.unidbg.pointer.UnicornPointer;
import cn.banny.utils.Hex;
import unicorn.ArmConst;
import unicorn.MemHook;
import unicorn.Unicorn;

import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * trace memory read
 * Created by zhkl0228 on 2017/5/2.
 */

class TraceMemoryHook implements MemHook {

    PrintStream redirect;

    @Override
    public void hook(Unicorn u, long address, int size, Object user) {
        byte[] data = u.mem_read(address, size);
        String value;
        if (data.length == 4) {
            value = "0x" + Long.toHexString(ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).getInt() & 0xffffffffL);
        } else {
            value = Hex.encodeHexString(data);
        }
        Emulator emulator = (Emulator) user;
        printMsg("### Memory READ at 0x", emulator, address, size, value);
    }

    private void printMsg(String type, Emulator emulator, long address, int size, String value) {
        UnicornPointer pc = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_PC);
        UnicornPointer lr = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR);
        StringBuilder sb = new StringBuilder();
        sb.append(type).append(Long.toHexString(address)).append(", data size = ").append(size).append(", data value = ").append(value);
        sb.append(" pc=").append(pc);
        sb.append(" lr=").append(lr);
        PrintStream out = System.out;
        if (redirect != null) {
            out = redirect;
        }
        out.println(sb);
    }

    @Override
    public void hook(Unicorn u, long address, int size, long value, Object user) {
        Emulator emulator = (Emulator) user;
        printMsg("### Memory WRITE at 0x", emulator, address, size, "0x" + Long.toHexString(value));
    }

}
