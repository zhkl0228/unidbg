package cn.banny.unidbg.debugger.ida;

import cn.banny.auxiliary.Inspector;
import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.debugger.AbstractDebugServer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.nio.ByteBuffer;

public class AndroidServer extends AbstractDebugServer {

    private static final Log log = LogFactory.getLog(AndroidServer.class);

    public AndroidServer(Emulator emulator) {
        super(emulator);
    }

    @Override
    protected void processInput(ByteBuffer input) {
        input.flip();

        if (input.hasRemaining()) {
            byte[] buffer = new byte[input.remaining()];
            input.get(buffer);

            if (log.isDebugEnabled()) {
                log.debug(Inspector.inspectString(buffer, "processInput"));
            }
        }

        input.clear();
    }

    @Override
    protected void onHitBreakPoint(Emulator emulator, long address) {
    }

    @Override
    protected void onDebuggerExit() {
    }

    @Override
    protected void onDebuggerConnected() {
    }

}
