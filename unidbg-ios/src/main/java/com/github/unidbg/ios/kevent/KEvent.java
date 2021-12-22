package com.github.unidbg.ios.kevent;

import com.github.unidbg.file.ios.BaseDarwinFileIO;
import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class KEvent extends BaseDarwinFileIO {

    private static final Log log = LogFactory.getLog(KEvent.class);

    private static final short EVFILT_SIGNAL = (-6); /* attached to struct proc */
    private static final short EVFILT_USER = (-10); /* User events */

    private final Map<Integer, KEvent64> registerMap = new HashMap<>();
    final List<KEvent64> pendingEventList = new ArrayList<>();

    public KEvent(int oflags) {
        super(oflags);
    }

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
                    registerMap.put(kev.hashCode(), kev);
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
                log.debug("processChangeList i=" + i + ", kev=" + kev);
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
