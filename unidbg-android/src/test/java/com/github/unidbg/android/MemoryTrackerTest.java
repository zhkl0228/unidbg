package com.github.unidbg.android;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.backend.HypervisorFactory;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.memory.AllocationRecord;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.memory.MemoryTracker;
import junit.framework.TestCase;

import java.util.Arrays;
import java.util.List;

public class MemoryTrackerTest extends TestCase {

    private AndroidEmulator emulator;

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("memory_tracker_test")
                .addBackendFactory(new DynarmicFactory(true))
                .addBackendFactory(new HypervisorFactory(true))
                .addBackendFactory(new Unicorn2Factory(true))
                .build();
        emulator.getMemory().setLibraryResolver(new AndroidResolver(23));
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        emulator.close();
    }

    public void testNoLeak() {
        try (MemoryTracker tracker = emulator.traceMemoryLeaks()) {
            Memory memory = emulator.getMemory();
            MemoryBlock block = memory.malloc(1024, true);
            block.free();
            List<AllocationRecord> leaks = tracker.getLeaks();
            assertEquals("Should have no leaks after free", 0, leaks.size());
        }
    }

    public void testDetectLeak() {
        try (MemoryTracker tracker = emulator.traceMemoryLeaks()) {
            Memory memory = emulator.getMemory();
            memory.malloc(2048, true);
            List<AllocationRecord> leaks = tracker.getLeaks();
            assertEquals("Should detect one leaked block", 1, leaks.size());
            assertTrue("Leaked size should be >= 2048", tracker.getTotalLeakedSize() >= 2048);
        }
    }

    public void testMultipleAllocations() {
        try (MemoryTracker tracker = emulator.traceMemoryLeaks()) {
            Memory memory = emulator.getMemory();
            MemoryBlock block1 = memory.malloc(1024, true);
            memory.malloc(2048, true);
            memory.malloc(4096, true);
            block1.free();
            List<AllocationRecord> leaks = tracker.getLeaks();
            assertEquals("Should detect 2 leaked blocks", 2, leaks.size());
            assertEquals("Total allocations should be 3", 3, tracker.getTotalAllocations());
            assertEquals("Total deallocations should be 1", 1, tracker.getTotalDeallocations());
        }
    }

}
