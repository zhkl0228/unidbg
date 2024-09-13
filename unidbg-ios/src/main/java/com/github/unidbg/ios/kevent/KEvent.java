package com.github.unidbg.ios.kevent;

import com.github.unidbg.file.ios.BaseDarwinFileIO;
import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class KEvent extends BaseDarwinFileIO {

    private static final Logger log = LoggerFactory.getLogger(KEvent.class);

    private static final short EVFILT_SIGNAL = (-6); /* attached to struct proc */
    private static final short EVFILT_MACHPORT = (-8); /* Mach portsets */
    private static final short EVFILT_USER = (-10); /* User events */
    private static final short EVFILT_VM = (-12); /* Virtual memory events */

    private final Map<Integer, KEvent64> registerMap = new HashMap<>();
    final List<KEvent64> pendingEventList = new ArrayList<>();

    public KEvent(int oflags) {
        super(oflags);
    }

    private static final int EV_ADD = 0x0001; /* add event to kq (implies enable) */
    private static final int EV_DELETE = 0x0002; /* delete event from kq */
    public static final int EV_ENABLE = 0x0004; /* enable event */
    public static final int EV_DISABLE = 0x0008; /* disable event (not reported) */
    private static final int EV_RECEIPT = 0x0040; /* force EV_ERROR on success, data == 0 */

    /*
     * On input, NOTE_TRIGGER causes the event to be triggered for output.
     */
    private static final int NOTE_TRIGGER = 0x01000000;

    private void processKev(KEvent64 kev) {
        switch (kev.filter) {
            case EVFILT_USER: {
                if ((kev.fflags & NOTE_TRIGGER) != 0) {
                    KEvent64 reg = registerMap.get(kev.hashCode());
                    if (reg == null) {
                        throw new IllegalStateException();
                    } else {
                        pendingEventList.add(reg);
                    }
                } else {
                    if ((kev.flags & EV_ADD) != 0) {
                        registerMap.put(kev.hashCode(), kev);
                    }
                    if ((kev.flags & EV_DELETE) != 0) {
                        throw new UnsupportedOperationException();
                    }
                    if ((kev.flags & EV_ENABLE) != 0) {
                        throw new UnsupportedOperationException();
                    }
                    if ((kev.flags & EV_DISABLE) != 0) {
                        throw new UnsupportedOperationException();
                    }
                    if ((kev.flags & EV_RECEIPT) != 0) {
                        throw new UnsupportedOperationException();
                    }
                }
                break;
            }
            case EVFILT_VM:
            case EVFILT_MACHPORT: {
                if ((kev.flags & EV_ADD) != 0) {
                    registerMap.put(kev.hashCode(), kev);
                }
                if ((kev.flags & EV_DELETE) != 0) {
                    throw new UnsupportedOperationException();
                }
                if (kev.isEnabled() && kev.isDisabled()) {
                    throw new UnsupportedOperationException();
                }
                break;
            }
            case EVFILT_SIGNAL:
            default:
                throw new UnsupportedOperationException("filter=" + kev.filter);
        }
    }

    public void processChangeList(Pointer changelist, int nchanges) {
        int size = UnidbgStructure.calculateSize(KEvent64.class);
        Pointer ptr = changelist;
        for (int i = 0; i < nchanges; i++, ptr = ptr.share(size)) {
            KEvent64 kev = new KEvent64(ptr);
            kev.unpack();
            if (log.isDebugEnabled()) {
                log.debug("processChangeList i={}, kev={}", i, kev);
            }
            processKev(kev);
        }
    }

    @Override
    public void close() {
        registerMap.clear();
        pendingEventList.clear();
    }

}
