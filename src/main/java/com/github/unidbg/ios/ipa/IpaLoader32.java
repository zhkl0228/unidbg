package com.github.unidbg.ios.ipa;

import java.io.File;
import java.io.IOException;

@SuppressWarnings("unused")
public class IpaLoader32 extends IpaLoader {

    public IpaLoader32(File ipa, File rootDir) {
        super(ipa, rootDir);
    }

    @Override
    public LoadedIpa load(EmulatorConfigurator configurator, String... loads) {
        try {
            return load32(configurator, loads);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

}
