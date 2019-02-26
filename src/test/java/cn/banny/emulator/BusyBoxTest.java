package cn.banny.emulator;

import java.io.File;
import java.io.IOException;

public class BusyBoxTest {

    public static void main(String[] args) throws IOException {
        RunExecutable.run(new File("src/test/resources/example_binaries/busybox"), null, "wget", "http://pv.sohu.com/cityjson?ie=utf-8", "-O", "-");
    }

}
