package cn.banny.emulator;

import java.io.File;
import java.io.IOException;

public class AppProcessTest {

    public static void main(String[] args) throws IOException {
        RunExecutable.run(new File("src/test/resources/example_binaries/app_process"), null);
    }

}
