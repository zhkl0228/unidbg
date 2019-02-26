package cn.banny.emulator;

import cn.banny.emulator.linux.Module;
import cn.banny.emulator.linux.ModuleListener;

import java.io.File;
import java.io.IOException;

public class SSHDebug implements ModuleListener {

    public static void main(String[] args) throws IOException {
        RunExecutable.run(new File("src/test/resources/example_binaries/ssh"), new SSHDebug(), "-p", "4446", "root@p.gzmtx.cn");
    }

    @Override
    public void onLoaded(Emulator emulator, Module module) {
    }

}
