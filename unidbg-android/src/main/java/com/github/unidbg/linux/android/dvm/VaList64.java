package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

class VaList64 extends VaList {

    private static final Logger log = LoggerFactory.getLogger(VaList64.class);

    VaList64(Emulator<?> emulator, BaseVM vm, UnidbgPointer va_list, DvmMethod method) {
        super(vm, method);

        long base_p = va_list.getLong(0);
        long base_integer = va_list.getLong(8);
        long base_float = va_list.getLong(16);
        int mask_integer = va_list.getInt(24);
        int mask_float = va_list.getInt(28);

        for (Shorty shorty : shorties) {
            switch (shorty.getType()) {
                case 'B':
                case 'C':
                case 'I':
                case 'S':
                case 'Z': {
                    Pointer pointer;
                    if ((mask_integer & 0x80000000) != 0) {
                        if (mask_integer + 8 <= 0) {
                            pointer = UnidbgPointer.pointer(emulator, base_integer + mask_integer);
                            mask_integer += 8;
                        } else {
                            pointer = UnidbgPointer.pointer(emulator, base_p);
                            mask_integer += 8;
                            base_p = (base_p + 11) & 0xfffffffffffffff8L;
                        }
                    } else {
                        pointer = UnidbgPointer.pointer(emulator, base_p);
                        base_p = (base_p + 11) & 0xfffffffffffffff8L;
                    }
                    assert pointer != null;
                    args.add(pointer.getInt(0));
                    break;
                }
                case 'D': {
                    Pointer pointer;
                    if ((mask_float & 0x80000000) != 0) {
                        if (mask_float + 16 <= 0) {
                            pointer = UnidbgPointer.pointer(emulator, base_float + mask_float);
                            mask_float += 16;
                        } else {
                            pointer = UnidbgPointer.pointer(emulator, base_p);
                            mask_float += 16;
                            base_p = (base_p + 15) & 0xfffffffffffffff8L;
                        }
                    } else {
                        pointer = UnidbgPointer.pointer(emulator, base_p);
                        base_p = (base_p + 15) & 0xfffffffffffffff8L;
                    }
                    assert pointer != null;
                    args.add(pointer.getDouble(0));
                    break;
                }
                case 'F': {
                    Pointer pointer;
                    if ((mask_float & 0x80000000) != 0) {
                        if (mask_float + 16 <= 0) {
                            pointer = UnidbgPointer.pointer(emulator, base_float + mask_float);
                            mask_float += 16;
                        } else {
                            pointer = UnidbgPointer.pointer(emulator, base_p);
                            mask_float += 16;
                            base_p = (base_p + 15) & 0xfffffffffffffff8L;
                        }
                    } else {
                        pointer = UnidbgPointer.pointer(emulator, base_p);
                        base_p = (base_p + 15) & 0xfffffffffffffff8L;
                    }
                    assert pointer != null;
                    args.add((float) pointer.getDouble(0));
                    break;
                }
                case 'J': {
                    Pointer pointer;
                    if ((mask_integer & 0x80000000) != 0) {
                        if (mask_integer + 8 <= 0) {
                            pointer = UnidbgPointer.pointer(emulator, base_integer + mask_integer);
                            mask_integer += 8;
                        } else {
                            pointer = UnidbgPointer.pointer(emulator, base_p);
                            mask_integer += 8;
                            base_p = (base_p + 15) & 0xfffffffffffffff8L;
                        }
                    } else {
                        pointer = UnidbgPointer.pointer(emulator, base_p);
                        base_p = (base_p + 15) & 0xfffffffffffffff8L;
                    }
                    assert pointer != null;
                    args.add(pointer.getLong(0));
                    break;
                }
                case 'L': {
                    Pointer pointer;
                    if ((mask_integer & 0x80000000) != 0) {
                        if (mask_integer + 8 <= 0) {
                            pointer = UnidbgPointer.pointer(emulator, base_integer + mask_integer);
                            mask_integer += 8;
                        } else {
                            pointer = UnidbgPointer.pointer(emulator, base_p);
                            mask_integer += 8;
                            base_p = (base_p + 15) & 0xfffffffffffffff8L;
                        }
                    } else {
                        pointer = UnidbgPointer.pointer(emulator, base_p);
                        base_p = (base_p + 15) & 0xfffffffffffffff8L;
                    }
                    assert pointer != null;
                    args.add(pointer.getInt(0));
                    break;
                }
                default:
                    throw new IllegalStateException("c=" + shorty.getType());
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("VaList64 base_p=0x{}, base_integer=0x{}, base_float=0x{}, mask_integer=0x{}, mask_float=0x{}, args={}, shorty={}", Long.toHexString(base_p), Long.toHexString(base_integer), Long.toHexString(base_float), Long.toHexString(mask_integer & 0xffffffffL), Long.toHexString(mask_float & 0xffffffffL), method.args, Arrays.toString(shorties));
        }
    }
}
