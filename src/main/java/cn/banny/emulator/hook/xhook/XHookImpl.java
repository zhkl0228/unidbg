package cn.banny.emulator.hook.xhook;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.Symbol;
import cn.banny.emulator.hook.BaseHook;
import cn.banny.emulator.hook.ReplaceCallback;
import cn.banny.emulator.linux.LinuxModule;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;

public class XHookImpl extends BaseHook implements IxHook {

    private static final Log log = LogFactory.getLog(XHookImpl.class);

    private static IxHook instance;

    public static IxHook getInstance(Emulator emulator) {
        if (instance == null) {
            try {
                instance = new XHookImpl(emulator);
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
        return instance;
    }

    private final Symbol xhook_register;
    private final Symbol xhook_refresh;

    private XHookImpl(Emulator emulator) throws IOException {
        super(emulator);

        LinuxModule module = (LinuxModule) emulator.getMemory().load(resolveLibrary(emulator, "libxhook.so"));
        xhook_register = module.findSymbolByName("xhook_register");
        xhook_refresh = module.findSymbolByName("xhook_refresh");
        log.debug("xhook_register=" + xhook_register + ", xhook_refresh=" + xhook_refresh);

        if (xhook_register == null) {
            throw new IllegalStateException("xhook_register is null");
        }
        if (xhook_refresh == null) {
            throw new IllegalStateException("xhook_refresh is null");
        }

        Symbol xhook_enable_sigsegv_protection = module.findSymbolByName("xhook_enable_sigsegv_protection");
        if (xhook_enable_sigsegv_protection == null) {
            throw new IllegalStateException("xhook_enable_sigsegv_protection is null");
        } else {
            xhook_enable_sigsegv_protection.call(emulator, 0);
        }

        Symbol xhook_enable_debug = module.findSymbolByName("xhook_enable_debug");
        if (xhook_enable_debug == null) {
            throw new IllegalStateException("xhook_enable_debug is null");
        } else {
            xhook_enable_debug.call(emulator, log.isDebugEnabled() ? 1 : 0);
        }
    }

    @Override
    public void register(String pathname_regex_str, String symbol, final ReplaceCallback callback) {
        final Pointer old_func = emulator.getMemory().malloc(emulator.getPointerSize(), false).getPointer();
        Pointer new_func = createReplacePointer(callback, old_func);
        int ret = xhook_register.call(emulator, pathname_regex_str, symbol, new_func, old_func)[0].intValue();
        if (ret != RET_SUCCESS) {
            throw new IllegalStateException("ret=" + ret);
        }
    }

    @Override
    public void refresh() {
        int ret = xhook_refresh.call(emulator, 0)[0].intValue();
        if (ret != RET_SUCCESS) {
            throw new IllegalStateException("ret=" + ret);
        }
    }
}
