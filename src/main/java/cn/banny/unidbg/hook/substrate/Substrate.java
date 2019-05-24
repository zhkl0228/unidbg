package cn.banny.unidbg.hook.substrate;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.Module;
import cn.banny.unidbg.Symbol;
import cn.banny.unidbg.hook.BaseHook;
import cn.banny.unidbg.ios.MachOModule;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;

public class Substrate extends BaseHook implements ISubstrate {

    private static final Log log = LogFactory.getLog(Substrate.class);

    public static ISubstrate getInstance(Emulator emulator) {
        Substrate substrate = emulator.get(Substrate.class.getName());
        if (substrate == null) {
            try {
                substrate = new Substrate(emulator);
                emulator.set(Substrate.class.getName(), substrate);
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
        return substrate;
    }

    private final Symbol _MSGetImageByName;
    private final Symbol _MSFindSymbol;

    private Substrate(Emulator emulator) throws IOException {
        super(emulator, "libsubstrate");

        _MSGetImageByName = module.findSymbolByName("_MSGetImageByName", false);
        _MSFindSymbol = module.findSymbolByName("_MSFindSymbol", false);
        log.debug("_MSGetImageByName=" + _MSGetImageByName + ", _MSFindSymbol=" + _MSFindSymbol);

        if (_MSGetImageByName == null) {
            throw new IllegalStateException("_MSGetImageByName is null");
        }
        if (_MSFindSymbol == null) {
            throw new IllegalStateException("_MSFindSymbol is null");
        }
    }

    @Override
    public Module getImageByName(String file) {
        Number[] numbers = _MSGetImageByName.call(emulator, file);
        long ret = numbers[0].intValue() & 0xffffffffL;
        if (ret == 0) {
            return null;
        } else {
            for (Module module : emulator.getMemory().getLoadedModules()) {
                MachOModule mm = (MachOModule) module;
                if (mm.machHeader == ret) {
                    return module;
                }
            }
            throw new IllegalStateException("ret=0x" + Long.toHexString(ret));
        }
    }

    @Override
    public Symbol findSymbol(Module image, String name) {
        MachOModule mm = (MachOModule) image;
        Number[] numbers = _MSFindSymbol.call(emulator, (mm == null ? 0 : (int) mm.machHeader), name);
        long ret = numbers[0].intValue() & 0xffffffffL;
        if (ret == 0) {
            return null;
        } else {
            return new SubstrateSymbol(name, ret);
        }
    }

}
