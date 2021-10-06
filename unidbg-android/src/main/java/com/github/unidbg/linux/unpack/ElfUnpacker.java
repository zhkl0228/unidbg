package com.github.unidbg.linux.unpack;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.backend.WriteHook;
import com.github.unidbg.memory.MemRegion;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.InitFunctionListener;
import org.apache.commons.io.FileUtils;
import unicorn.UnicornConst;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Dump 针对 init_array 加密的 so 文件
 * <pre>
 * First before load so:
 *     memory.addModuleListener();
 * Then in onLoaded method:
 *     if ("libxxx.so".equals(module.name)) {
 *         File outFile = new File(FileUtils.getUserDirectory(), "Desktop/libxxx_patched.so");
 *         new ElfUnpacker(libxxxFileData, outFile).register(emulator, module);
 *     }
 * </pre>
 */
public class ElfUnpacker {

    private final byte[] elfFile;
    private final File outFile;

    public ElfUnpacker(byte[] elfFile, File outFile) {
        this.elfFile = elfFile;
        this.outFile = outFile;

        if (outFile.isDirectory()) {
            throw new IllegalStateException("isDirectory");
        }

        this.buffer = ByteBuffer.allocate(8);
        this.buffer.order(ByteOrder.LITTLE_ENDIAN);
    }

    private final ByteBuffer buffer;
    private boolean dirty;

    public void register(final Emulator<?> emulator, final Module module) {
        module.setInitFunctionListener(new InitFunctionListener() {
            @Override
            public void onPreCallInitFunction(Module module, long initFunction, int index) {
                dirty = false;
            }
            @Override
            public void onPostCallInitFunction(Module module, long initFunction, int index) {
                try {
                    if (dirty) {
                        System.out.println("Unpack initFunction=" + UnidbgPointer.pointer(emulator, module.base + initFunction));
                        FileUtils.writeByteArrayToFile(outFile, elfFile);
                    }
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            }
        });

        for (MemRegion region : module.getRegions()) {
            if ((region.perms & UnicornConst.UC_PROT_WRITE) == 0 && (region.perms & UnicornConst.UC_PROT_EXEC) == UnicornConst.UC_PROT_EXEC) { // 只读代码段
                System.out.println("Begin unpack " + module.name + ": 0x" + Long.toHexString(region.begin) + "-0x" + Long.toHexString(region.end));
                emulator.getBackend().hook_add_new(new WriteHook() {
                    private UnHook unHook;
                    @Override
                    public void hook(Backend backend, long address, int size, long value, Object user) {
                        long offset = address - module.base;
                        int fileOffset = module.virtualMemoryAddressToFileOffset(offset);
                        if (size < 1 || size > 8) {
                            throw new IllegalStateException("size=" + size);
                        }
                        if (fileOffset >= 0) {
                            buffer.clear();
                            buffer.putLong(value);
                            System.arraycopy(buffer.array(), 0, elfFile, fileOffset, size);
                            dirty = true;
                        }
                    }
                    @Override
                    public void onAttach(UnHook unHook) {
                        this.unHook = unHook;
                    }
                    @Override
                    public void detach() {
                        this.unHook.unhook();
                    }
                }, region.begin, region.end, emulator);
            }
        }
    }

}
