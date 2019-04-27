package cn.banny.emulator.ios;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public class Utils {

    static BigInteger readULEB128(ByteBuffer buffer) {
        BigInteger result = BigInteger.ZERO;
        int shift = 0;
        while (true) {
            byte b = buffer.get();
            result = result.or(BigInteger.valueOf(b & 127).shiftLeft(shift));
            if ((b & 128) == 0) {
                break;
            }
            shift += 7;
        }
        return result;
    }

}
