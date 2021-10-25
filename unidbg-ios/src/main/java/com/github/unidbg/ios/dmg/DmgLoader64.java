package com.github.unidbg.ios.dmg;

import com.github.unidbg.ios.ipa.EmulatorConfigurator;

import java.io.File;
import java.io.IOException;

public class DmgLoader64 extends DmgLoader {

    public DmgLoader64(File dmgDir, File rootDir) {
        super(dmgDir, rootDir);
    }

    @Override
    public LoadedDmg load(EmulatorConfigurator configurator, String... loads) {
        try {
            return load64(configurator, loads);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

}
