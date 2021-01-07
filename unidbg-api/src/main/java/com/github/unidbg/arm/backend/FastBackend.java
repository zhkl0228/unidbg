package com.github.unidbg.arm.backend;

import com.github.unidbg.Emulator;
import com.github.unidbg.debugger.BreakPoint;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

abstract class FastBackend extends AbstractBackend {

    protected final Emulator<?> emulator;

    public FastBackend(Emulator<?> emulator) {
        this.emulator = emulator;
    }

    private static class SoftBreakPoint implements BreakPoint {
        final long address;
        final byte[] backup;
        final BreakPointCallback callback;
        final boolean thumb;
        SoftBreakPoint(long address, byte[] backup, BreakPointCallback callback, boolean thumb) {
            this.address = address;
            this.backup = backup;
            this.callback = callback;
            this.thumb = thumb;
        }
        @Override
        public void setTemporary(boolean temporary) {
            throw new UnsupportedOperationException();
        }
        @Override
        public boolean isTemporary() {
            return false;
        }
        @Override
        public BreakPointCallback getCallback() {
            return callback;
        }
        @Override
        public boolean isThumb() {
            return thumb;
        }
    }

    private int svcNumber = 1;
    private final Map<Integer, SoftBreakPoint> softBreakpointMap = new HashMap<>();

    @Override
    public final BreakPoint addBreakPoint(long address, BreakPointCallback callback, boolean thumb) {
        int svcNumber = ++this.svcNumber; // begin with 2
        byte[] code = addSoftBreakPoint(address, svcNumber, thumb);

        Pointer pointer = UnidbgPointer.pointer(emulator, address);
        assert pointer != null;
        byte[] backup = pointer.getByteArray(0, code.length);
        pointer.write(0, code, 0, code.length);
        SoftBreakPoint breakPoint = new SoftBreakPoint(address, backup, callback, thumb);
        softBreakpointMap.put(svcNumber, breakPoint);
        return breakPoint;
    }

    protected abstract byte[] addSoftBreakPoint(long address, int svcNumber, boolean thumb);

    @Override
    public final boolean removeBreakPoint(long address) {
        address &= (~1);

        for (Iterator<Map.Entry<Integer, SoftBreakPoint>> iterator = softBreakpointMap.entrySet().iterator(); iterator.hasNext(); ) {
            Map.Entry<Integer, SoftBreakPoint> entry = iterator.next();
            SoftBreakPoint breakPoint = entry.getValue();
            if (address == breakPoint.address) {
                Pointer pointer = UnidbgPointer.pointer(emulator, address);
                assert pointer != null;
                pointer.write(0, breakPoint.backup, 0, breakPoint.backup.length);
                iterator.remove();
                return true;
            }
        }
        return false;
    }

    @Override
    public final void setSingleStep(int singleStep) {
    }

    @Override
    public final void setFastDebug(boolean fastDebug) {
    }

}
