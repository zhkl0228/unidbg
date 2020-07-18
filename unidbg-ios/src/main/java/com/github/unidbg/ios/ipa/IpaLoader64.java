package com.github.unidbg.ios.ipa;

import java.io.File;
import java.io.IOException;

public class IpaLoader64 extends IpaLoader {

    public IpaLoader64(File ipa, File rootDir) {
        super(ipa, rootDir);
    }

    @Override
    public LoadedIpa load(EmulatorConfigurator configurator, String... loads) {
        try {
            return load64(configurator, loads);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

}
