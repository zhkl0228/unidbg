package king.trace;

public class OtherTools {
    public static String byteToString(byte[] b) {
        char[] _16 = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
        StringBuilder sb = new StringBuilder();
        for(int i = 0 ; i<b.length;i++) {
            sb.append(_16[b[i]>>4&0xf])
                    .append(_16[b[i]&0xf]);
        }
        return sb.toString();
    }

    public static int toUnsignedInt(int data){
        return data&0xffffffff;
    }
    public static long toUnsignedLong(long data){
        return data&0xffffffffffffffffl;
    }
}
