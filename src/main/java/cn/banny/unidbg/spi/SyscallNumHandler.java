package cn.banny.unidbg.spi;

import cn.banny.unidbg.Emulator;
import unicorn.Unicorn;

public interface SyscallNumHandler {

	void handle(Unicorn u, Emulator emulator);
	
}
