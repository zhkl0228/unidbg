package com.github.unidbg.ios;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteOrder;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;

// https://github.com/3ign0n/iOS-malloc-stack-log-decoder
public class StackLogDecoder {

    private static final int MALLOC_LOG_TYPE_ALLOCATE = 2; /* malloc, realloc, etc... */
    private static final int MALLOC_LOG_TYPE_DEALLOCATE = 4; /* free, realloc, etc... */
    private static final int stack_logging_type_vm_allocate = 16; /* vm_allocate or mmap */
    private static final int stack_logging_type_vm_deallocate = 32; /* vm_deallocate or munmap */
    private static final int stack_logging_type_mapped_file_or_shared_mem = 128;

    public static void main(String[] args) throws IOException {
        File stackLog = new File("target/stack-logs.78490.2000.unidbg.zcmkle.index");
        FileInputStream inputStream = new FileInputStream(stackLog);
        FileChannel channel = inputStream.getChannel();
        MappedByteBuffer buffer = channel.map(FileChannel.MapMode.READ_ONLY, 0, stackLog.length());
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        int i = 0;
        while (buffer.remaining() >= 16) {
            long size = buffer.getInt() & 0xffffffffL;
            long addr = (buffer.getInt() & 0xffffffffL) ^ 0x00005555;
            long offset_and_flags_l = buffer.getInt() & 0xffffffffL;
            long offset_and_flags_h = buffer.getInt() & 0xffffffffL;
            int flag = (int) ((offset_and_flags_h & 0xff000000) >> 24);
            long stackId = ((offset_and_flags_h & 0x00ffffff) << 32) | offset_and_flags_l;
            String action = "OTHER";
            boolean isFree = false;
            switch (flag) {
                case MALLOC_LOG_TYPE_ALLOCATE:
                    action = "ALLOC";
                    isFree = false;
                    break;
                case MALLOC_LOG_TYPE_DEALLOCATE:
                    action = "FREE ";
                    isFree = true;
                    break;
                case stack_logging_type_vm_allocate:
                    action = "MMAP ";
                    isFree = false;
                    break;
                case stack_logging_type_vm_deallocate:
                    action = "UNMAP";
                    isFree = true;
                    break;
                default:
                    if ((flag & stack_logging_type_mapped_file_or_shared_mem) != 0 && (flag & stack_logging_type_vm_allocate) != 0) {
                        action = "MMAPF";
                        isFree = false;
                        break;
                    }

                    System.err.println(flag);
                    break;
            }
            String msg = String.format("[%08d]: %s, stackId=0x%014x, address=0x%08x, size=0x%x", i++, action, stackId, addr, size);
            if (isFree) {
                System.err.println(msg);
            } else {
                System.out.println(msg);
            }
        }
        channel.close();
        inputStream.close();
    }

}
