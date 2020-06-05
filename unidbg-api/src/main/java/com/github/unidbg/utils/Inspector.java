/*
 * Filename: Inspector.java
 * Create date: 2009-7-5
 */
package com.github.unidbg.utils;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;


/**
 * 
 * @author unidbg
 * 
 */
@SuppressWarnings("unused")
public class Inspector {

	public static void inspectMapData(String label, byte[] data, int mode) {
		if (data == null)
			return;

		StringBuilder buffer = new StringBuilder();
		buffer.append("\n>-----------------------------------------------------------------------------<\n");

		buffer.append(new SimpleDateFormat("[HH:mm:ss SSS]").format(new Date()));
		
		buffer.append(label);
		
		buffer.append("\nsize: ").append(data.length).append('\n');
		
		int i = 0;
		for(; i < data.length; i++) {
			int di = data[i] & 0xFF;
			if(di != 0) {
				String hex = Integer.toString(di, 16).toUpperCase();
				if(hex.length() < 2) {
					buffer.append('0');
				}
				buffer.append(hex);
			} else {
				buffer.append("  ");
			}
			
			buffer.append(' ');
			
			if((i + 1) % mode == 0) {
				/*buffer.append("   ");
				for(int k = i - 15; k < i+1; k++) {
					buffer.append(toChar(data[k]));
				}*/
				buffer.append('\n');
			}
		}
		
		int redex = mode - i % mode;
		for(byte k = 0; k < redex && redex < mode; k++) {
			buffer.append("  ");
			buffer.append(' ');
		}
		int count = i % mode;
		int start = i - count;
		if(start < i) {
			buffer.append("   ");
		}
		for(int k = start; k < i; k++) {
			buffer.append(toChar(data[k]));
		}
		
		if(redex < mode) {
			buffer.append('\n');
		}
		buffer.append("^-----------------------------------------------------------------------------^");
		
		System.out.println(buffer);
	}
	
	public static void available(InputStream dis) throws IOException {
		if(dis == null) {
			System.out.println("available=null");
			return;
		}

		int size = dis.available();
		byte[] data = new byte[size];
		if (dis.read(data) != size) {
			throw new IOException("Read available failed.");
		}
		Inspector.inspect(data, "Available");
	}
	
	/**
	 * 过滤器
	 * @return 是否接受该数据
	 */
	public boolean accept(byte[] data, String label) {
		return true;
	}
	public boolean acceptObject(Object obj) {
		return true;
	}
	
	public static final int WPE = 16;
	public static final int MNM = 20;
	
	public static void inspectMapData(String label, short[][] data) {
		inspectMapData(label, data, -1);
	}
	
	public static void inspectMapData(String label, short[][] data, int filter) {
		StringBuffer buffer = new StringBuffer();
		buffer.append("\n>-----------------------------------------------------------------------------<\n");

		buffer.append(new SimpleDateFormat("[HH:mm:ss SSS]").format(new Date()));
		
		buffer.append(data.length);
		if(data.length > 0) {
			buffer.append('x').append(data[0].length);
		}
		buffer.append(label).append('\n');

		for (short[] dt : data) {
			for (short ds : dt) {
				int di = ds & 0xFFFF;

				if (di == filter) {
					buffer.append("     ");
					continue;
				}

				String hex = Integer.toString(di, 16).toUpperCase();
				for (int n = 0; n < 4 - hex.length(); n++) {
					buffer.append('0');
				}
				buffer.append(hex);
				buffer.append(' ');
			}
			buffer.append('\n');
		}
		
		buffer.append("^-----------------------------------------------------------------------------^");
		System.out.println(buffer);
	}
	
	public static void inspect(String label, byte[][] data) {
		inspect(label, data, -1);
	}
	
	public static void inspect(String label, short[] data) {
		System.out.println(inspectString(null, label, data, WPE));
	}
	
	public static String inspectString(Date date, String label, short[] data, int mode) {
		StringBuilder buffer = new StringBuilder();
		buffer.append("\n>-----------------------------------------------------------------------------<\n");

		if (date == null) {
			date = new Date();
		}
		buffer.append(new SimpleDateFormat("[HH:mm:ss SSS]").format(date));
		
		buffer.append(label);
		
		buffer.append("\nsize: ");
		if(data != null) {
			buffer.append(data.length);
		} else {
			buffer.append("null");
		}
		buffer.append('\n');
		
		if(data != null) {
			int i = 0;
			for(; i < data.length; i++) {
				int di = data[i] & 0xFFFF;
				
				String hex = Integer.toString(di, 16).toUpperCase();
				for(int n = 0; n < 4 - hex.length(); n++) {
					buffer.append('0');
				}
				buffer.append(hex);
				buffer.append(' ');
				
				if((i + 1) % mode == 0) {
					buffer.append('\n');
				}
			}
			
			if(i % mode != 0) {
				buffer.append('\n');
			}
		}
		
		buffer.append("^-----------------------------------------------------------------------------^");
		
		return buffer.toString();
	}
	
	public static void inspect(String label, byte[][] data, int filter) {
		System.out.println(inspectString(label, data, filter));
	}
	
	public static void inspect(Date date, String label, byte[] data, int mode) {
		System.out.println(inspectInternal(date, label, data, mode));
	}

	private static String inspectInternal(Date date, String label, byte[] data, int mode) {
		StringBuilder buffer = new StringBuilder();
		buffer.append("\n>-----------------------------------------------------------------------------<\n");

		if (date == null) {
			date = new Date();
		}
		buffer.append(new SimpleDateFormat("[HH:mm:ss SSS]").format(date));

		buffer.append(label);
		if(data != null) {
			buffer.append(", md5=").append(Hex.encodeHex(DigestUtils.md5(data)));
			if (data.length < 1024) {
				buffer.append(", hex=").append(Hex.encodeHex(data));
			}
		}
		
		buffer.append("\nsize: ");
		if(data != null) {
			buffer.append(data.length);
		} else {
			buffer.append("null");
		}
		buffer.append('\n');
		
		if(data != null) {
			int i = 0;
			for(; i < data.length; i++) {
				if(i % mode == 0) {
					String hex = Integer.toHexString(i % 0x10000).toUpperCase();
					for(int k = 0, fill = 4 - hex.length(); k < fill; k++) {
						buffer.append('0');
					}
					buffer.append(hex).append(": ");
				}
				
				int di = data[i] & 0xFF;
				String hex = Integer.toString(di, 16).toUpperCase();
				if(hex.length() < 2) {
					buffer.append('0');
				}
				buffer.append(hex);
				buffer.append(' ');
				
				if((i + 1) % mode == 0) {
					buffer.append("   ");
					for(int k = i - 15; k < i+1; k++) {
						buffer.append(toChar(data[k]));
					}
					buffer.append('\n');
				}
			}
			
			int redex = mode - i % mode;
			for(byte k = 0; k < redex && redex < mode; k++) {
				buffer.append("  ");
				buffer.append(' ');
			}
			int count = i % mode;
			int start = i - count;
			if(start < i) {
				buffer.append("   ");
			}
			for(int k = start; k < i; k++) {
				buffer.append(toChar(data[k]));
			}
			
			if(redex < mode) {
				buffer.append('\n');
			}
		}
		
		buffer.append("^-----------------------------------------------------------------------------^");
		
		return buffer.toString();
	}
	
	public static void inspect(String label, byte[] data, int mode) {
		inspect(null, label, data, mode);
	}

	/**
	 * 侦察发送的数据
	 */
	public static void inspect(byte[] data, boolean send) {
		inspect(send ? "发送数据" : "接收数据", data, WPE);
	}

	/**
	 * 侦察发送的数据
	 */
	public static void inspect(int type, byte[] data, boolean send) {
		String ts = Integer.toHexString(type).toUpperCase();
		inspect(send ? "发送数据：0x" + ts : "接收数据：0x" + ts, data, WPE);
	}

	/**
	 * 侦察发送的数据
	 */
	public static void inspect(byte[] data, String label) {
		inspect(label, data, WPE);
	}
	
	private static char toChar(byte in) {
		if(in == ' ')
			return ' ';
		
		if(in > 0x7E || in < 0x21)
			return '.';
		else
			return (char) in;
	}
	
	/**
	 * 测试对象类型
	 */
	public static void objectType(Object in) {
		if(in == null) {
			System.out.println("Object type is null");
			return;
		}
		
		System.out.println("Object type is " + in.getClass() + '[' + in + ']');
	}
	
	/**
	 * 侦测数据类型
	 * @return 返回null则表示没侦测到
	 */
	protected Integer detectedType(byte[] data, boolean send) {
		return null;
	}
	
	/**
	 * 查询int值
	 */
	public static void inspect(String label, int value) {
		System.out.println(label + "0x" + Integer.toHexString(value).toUpperCase());
	}
	
	/**
	 * 引发错误异常
	 */
	public static void throwError() {
		throw new Error("auxiliary error");
	}
	
	/**
	 * 根据值引发错误异常
	 */
	public static void throwError(int errorValue, int testValue) {
		if(testValue != errorValue) {
			return;
		}
		throw new Error("auxiliary error");
	}
	
	public static void where() {
		Thread.dumpStack();
	}
	
	public static void where(int testValue, int printValue) {
		if(testValue != printValue) {
			return;
		}

		where();
	}
	
	protected static void close(InputStream is) {
		if(is == null) {
			return;
		}
		
		try {
			is.close();
		} catch(Exception ignored) {}
	}
	protected static void close(OutputStream os) {
		if(os == null) {
			return;
		}
		
		try {
			os.close();
		} catch(Exception ignored) {}
	}
	
	public static String inspectString(String label, byte[][] data) {
		return inspectString(label, data, -1);
	}
	
	public static String inspectString(String label, short[] data) {
		return inspectString(new Date(), label, data);
	}
	
	public static String inspectString(Date date, String label, short[] data) {
		return inspectString(date, label, data, WPE);
	}
	
	public static String inspectString(String label, byte[][] data, int filter) {
		StringBuilder buffer = new StringBuilder();
		buffer.append("\n>-----------------------------------------------------------------------------<\n");

		buffer.append(new SimpleDateFormat("[HH:mm:ss SSS]").format(new Date()));
		
		if(data.length > 0) {
			buffer.append(data[0].length).append('x');
		}
		buffer.append(data.length);
		buffer.append(label).append('\n');

		for (byte[] dt : data) {
			for (byte db : dt) {
				int di = db & 0xFF;

				if (di == filter) {
					buffer.append("   ");
					continue;
				}

				String hex = Integer.toString(di, 16).toUpperCase();
				if (hex.length() < 2) {
					buffer.append('0');
				}
				buffer.append(hex);
				buffer.append(' ');
			}
			buffer.append('\n');
		}
		
		buffer.append("^-----------------------------------------------------------------------------^");
		return buffer.toString();
	}
	
	public static String inspectString(String label, byte[] data, int mode) {
		return inspectString(null, label, data, mode);
	}
	
	public static String inspectString(Date date, String label, byte[] data, int mode) {
		return inspectInternal(date, label, data, mode);
	}

	/**
	 * 侦察发送的数据
	 */
	public static String inspectString(byte[] data, boolean send) {
		return inspectString(send ? "Sent" : "Received", data, WPE);
	}

	/**
	 * 侦察发送的数据
	 */
	public static String inspectString(int type, byte[] data, boolean send) {
		String ts = Integer.toHexString(type).toUpperCase();
		return inspectString(send ? "发送数据: 0x" + ts : "接收数据: 0x" + ts, data, WPE);
	}

	/**
	 * 侦察发送的数据
	 */
	public static String inspectString(byte[] data, String label) {
		return inspectString(label, data, WPE);
	}

}
