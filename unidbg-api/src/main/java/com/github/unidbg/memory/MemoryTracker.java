package com.github.unidbg.memory;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.unwind.Frame;
import com.github.unidbg.unwind.Unwinder;
import com.github.zhkl0228.demumble.DemanglerFactory;
import com.github.zhkl0228.demumble.GccDemangler;

import java.io.Closeable;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class MemoryTracker implements MMapListener, Closeable {

    private final Emulator<?> emulator;
    private final MMapListener previousListener;
    private final Map<Long, AllocationRecord> allocations = new LinkedHashMap<>();
    private final long startTime;
    private int totalAllocations;
    private int totalDeallocations;

    public MemoryTracker(Emulator<?> emulator) {
        this.emulator = emulator;
        Memory memory = emulator.getMemory();
        this.previousListener = memory.getMMapListener();
        memory.setMMapListener(this);
        this.startTime = System.nanoTime();
    }

    @Override
    public void onMap(long address, long size, int perms) {
        String[] guestBt = captureGuestBacktrace();
        StackTraceElement[] hostBt = new Throwable().getStackTrace();
        allocations.put(address, new AllocationRecord(address, size, perms, guestBt, hostBt));
        totalAllocations++;
        if (previousListener != null) {
            previousListener.onMap(address, size, perms);
        }
    }

    @Override
    public int onProtect(long address, long size, int perms) {
        if (previousListener != null) {
            return previousListener.onProtect(address, size, perms);
        }
        return perms;
    }

    @Override
    public void onUnmap(long address, long size) {
        removeOverlapping(address, size);
        totalDeallocations++;
        if (previousListener != null) {
            previousListener.onUnmap(address, size);
        }
    }

    private void removeOverlapping(long unmapAddr, long unmapSize) {
        long unmapEnd = unmapAddr + unmapSize;
        Iterator<Map.Entry<Long, AllocationRecord>> it = allocations.entrySet().iterator();
        while (it.hasNext()) {
            AllocationRecord rec = it.next().getValue();
            long recEnd = rec.address + rec.size;
            if (rec.address < unmapEnd && recEnd > unmapAddr) {
                it.remove();
            }
        }
    }

    private String[] captureGuestBacktrace() {
        try {
            Unwinder unwinder = emulator.getUnwinder();
            List<Frame> frames = unwinder.getFrames(20);
            String[] result = new String[frames.size()];
            Memory memory = emulator.getMemory();
            for (int i = 0; i < frames.size(); i++) {
                long pc = frames.get(i).ip.peer;
                result[i] = formatFrame(i, pc, memory);
            }
            return result;
        } catch (Exception e) {
            return new String[]{"<backtrace unavailable: " + e.getMessage() + ">"};
        }
    }

    private String formatFrame(int index, long pc, Memory memory) {
        StringBuilder sb = new StringBuilder();
        sb.append("#").append(index).append(" 0x").append(Long.toHexString(pc));

        Module module = memory.findModuleByAddress(pc);
        if (module != null) {
            long offset = pc - module.base;
            sb.append(" ").append(module.name).append("+0x").append(Long.toHexString(offset));

            Symbol symbol = module.findClosestSymbolByAddress(pc, false);
            if (symbol != null && pc - symbol.getAddress() <= Unwinder.SYMBOL_SIZE) {
                GccDemangler demangler = DemanglerFactory.createDemangler();
                sb.append(" (").append(demangler.demangle(symbol.getName()))
                        .append("+0x").append(Long.toHexString(pc - (symbol.getAddress() & ~1)))
                        .append(")");
            }
        }
        return sb.toString();
    }

    public List<AllocationRecord> getLeaks() {
        return new ArrayList<>(allocations.values());
    }

    public int getTotalAllocations() {
        return totalAllocations;
    }

    public int getTotalDeallocations() {
        return totalDeallocations;
    }

    public long getTotalLeakedSize() {
        long total = 0;
        for (AllocationRecord rec : allocations.values()) {
            total += rec.size;
        }
        return total;
    }

    public void printReport() {
        printReport(System.out);
    }

    public void printReport(PrintStream out) {
        long durationMs = (System.nanoTime() - startTime) / 1_000_000;
        List<AllocationRecord> leaks = getLeaks();
        long leakedSize = getTotalLeakedSize();

        out.println("=== Memory Leak Report ===");
        out.println("Backend: " + emulator.getBackend().getClass().getSimpleName());
        out.println("Tracking duration: " + durationMs + "ms");
        out.println("Total allocations: " + totalAllocations);
        out.println("Total deallocations: " + totalDeallocations);
        out.println("Leaked blocks: " + leaks.size());
        out.println("Total leaked size: " + leakedSize + " bytes (" + formatSize(leakedSize) + ")");

        for (int i = 0; i < leaks.size(); i++) {
            AllocationRecord rec = leaks.get(i);
            out.println();
            out.println("--- Leak #" + (i + 1) + " ---");
            out.println("Address: 0x" + Long.toHexString(rec.address) +
                    ", Size: " + rec.size + " (" + formatSize(rec.size) +
                    "), Perms: " + formatPerms(rec.perms));

            if (rec.guestBacktrace.length > 0) {
                out.println("Guest Backtrace:");
                for (String frame : rec.guestBacktrace) {
                    out.println("  " + frame);
                }
            }

            if (rec.hostStackTrace.length > 0) {
                out.println("Host Stack Trace:");
                for (StackTraceElement element : rec.hostStackTrace) {
                    String className = element.getClassName();
                    if (className.startsWith("com.github.unidbg.")) {
                        out.println("  " + element);
                    }
                }
            }
        }

        if (leaks.isEmpty()) {
            out.println();
            out.println("No memory leaks detected.");
        }
    }

    private static String formatSize(long bytes) {
        if (bytes >= 1024 * 1024) {
            return String.format("%.1f MB", bytes / (1024.0 * 1024.0));
        } else if (bytes >= 1024) {
            return String.format("%.1f KB", bytes / 1024.0);
        }
        return bytes + " B";
    }

    private static String formatPerms(int perms) {
        return (((perms & 1) != 0) ? "r" : "-") +
                (((perms & 2) != 0) ? "w" : "-") +
                (((perms & 4) != 0) ? "x" : "-");
    }

    @Override
    public void close() {
        emulator.getMemory().setMMapListener(previousListener);
        printReport();
    }

}
