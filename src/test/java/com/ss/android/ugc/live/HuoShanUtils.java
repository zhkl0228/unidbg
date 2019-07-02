package com.ss.android.ugc.live;


import java.security.MessageDigest;

public class HuoShanUtils {


    public static final String TAG = "libcms-test-kit";

    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    // com.ss.sys.ces.gg.tt
    public static class tt{
        public static String format_session_id(String arg6) {
            String v0_1;
            String[] v1 = arg6.replace(" ", "").split(",");
            int v2 = v1.length;
            int v0 = 0;
            while(true) {
                if(v0 < v2) {
                    String v3 = v1[v0];
                    int v4 = v3.indexOf("sessionid=");
                    if(v4 != -1) {
                        v0_1 = v3.substring("sessionid=".length() + v4);
                    }
                    else {
                        ++v0;
                        continue;
                    }
                }
                else {
                    return null;
                }
                return v0_1;
            }
        }

        public static boolean filter_url(String arg3) {
            boolean v0 = false;
            //if(arg3.contains(c.a() + "/v2/r")) {
            if(arg3.contains("/v2/r")) {
                v0 = true;
            }

            return v0;
        }

        public static String format_url(String arg4) {
            String v0 = null;
            int v3 = -1;
            int v1 = arg4.indexOf("?");
            int v2 = arg4.indexOf("#");
            if(v1 != v3) {
                if(v2 == v3) {
                    v0 = arg4.substring(v1 + 1);
                }
                else if(v2 >= v1) {
                    v0 = arg4.substring(v1 + 1, v2);
                }
            }

            return v0;
        }
    }

    public static class e{
        static final char[] a = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        public static String a(String arg3) {
            String v0 = null;
            if(arg3 != null) {
                try {
                    if(arg3.length() == 0) {
                        return v0;
                    }

                    MessageDigest v1_1 = MessageDigest.getInstance("MD5");
                    v1_1.update(arg3.getBytes("UTF-8"));
                    v0 = e.a(v1_1.digest());
                }
                catch(Exception v1) {
                }
            }

            return v0;
        }
        public static String a(byte[] arg2) {
            if(arg2 == null) {
                throw new NullPointerException("bytes is null");
            }

            return e.a(arg2, 0, arg2.length);
        }
        public static String a(byte[] arg8, int arg9, int arg10) {
            if(arg8 == null) {
                throw new NullPointerException("bytes is null");
            }

            if(arg9 >= 0 && arg9 + arg10 <= arg8.length) {
                char[] v3 = new char[arg10 * 2];
                int v0 = 0;
                int v2 = 0;
                while(v0 < arg10) {
                    int v4 = arg8[v0 + arg9] & 0xFF;
                    int v5 = v2 + 1;
                    v3[v2] = e.a[v4 >> 4];
                    v2 = v5 + 1;
                    v3[v5] = e.a[v4 & 15];
                    ++v0;
                }

                return new String(v3, 0, arg10 * 2);
            }

            throw new IndexOutOfBoundsException();
        }
    }




}
