package cn.banny.emulator;

import cn.banny.emulator.linux.Module;
import cn.banny.emulator.pointer.UnicornPointer;
import cn.banny.utils.Hex;
import unicorn.ArmConst;
import unicorn.MemHook;
import unicorn.Unicorn;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * trace memory read
 * Created by zhkl0228 on 2017/5/2.
 */

class TraceMemoryHook implements MemHook {

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
        UnicornPointer pc = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_PC);
        UnicornPointer lr = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR);
        Module pcm = pc == null ? null : emulator.getMemory().findModuleByAddress(pc.peer);
        Module lrm = lr == null ? null : emulator.getMemory().findModuleByAddress(lr.peer);
        StringBuilder sb = new StringBuilder();
        sb.append("### Memory READ at 0x").append(Long.toHexString(address)).append(", data size = ").append(size).append(", data value = ").append(value);
        if (pcm == null) {
            sb.append(" pc=").append(pc);
        } else {
            sb.append(" pc=[").append(pcm.name).append("]0x").append(Long.toHexString(pc.peer - pcm.base));
        }
        if (lrm == null) {
            sb.append(" lr=").append(lr);
        } else {
            sb.append(" lr=[").append(lrm.name).append("]0x").append(Long.toHexString(lr.peer - lrm.base));
        }
        System.out.println(sb);
    }

    @Override
    public void hook(Unicorn u, long address, int size, long value, Object user) {
        Emulator emulator = (Emulator) user;
        UnicornPointer pc = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_PC);
        UnicornPointer lr = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR);
        Module pcm = pc == null ? null : emulator.getMemory().findModuleByAddress(pc.peer);
        Module lrm = lr == null ? null : emulator.getMemory().findModuleByAddress(lr.peer);
        StringBuilder sb = new StringBuilder();
        sb.append("### Memory WRITE at 0x").append(Long.toHexString(address)).append(", data size = ").append(size).append(", data value = 0x").append(Long.toHexString(value));
        if (pcm == null) {
            sb.append(" pc=").append(pc);
        } else {
            sb.append(" pc=[").append(pcm.name).append("]0x").append(Long.toHexString(pc.peer - pcm.base));
        }
        if (lrm == null) {
            sb.append(" lr=").append(lr);
        } else {
            sb.append(" lr=[").append(lrm.name).append("]0x").append(Long.toHexString(lr.peer - lrm.base));
        }
        System.out.println(sb.toString());
    }

}
