/*

Java bindings for the Unicorn Emulator Engine

Copyright(c) 2015 Chris Eagle

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
version 2 as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

*/

/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh, 2015 */

/* Sample code to demonstrate how to emulate ARM64 code */
package samples;

import com.github.unidbg.arm.backend.unicorn.BlockHook;
import com.github.unidbg.arm.backend.unicorn.CodeHook;
import com.github.unidbg.arm.backend.unicorn.Unicorn;
import junit.framework.TestCase;
import unicorn.Arm64Const;
import unicorn.UnicornConst;

import java.io.IOException;

public class SampleArm64Test extends TestCase {

    static {
        try {
            org.scijava.nativelib.NativeLoader.loadLibrary("unicorn");
        } catch (IOException ignored) {
        }
    }

   // code to be emulated
   public static final byte[] ARM_CODE = {-85,1,15,-117}; // add x11, x13, x15
   
   // memory address where emulation starts
   public static final int ADDRESS = 0x10000;
   
   // callback for tracing basic blocks
   private static class MyBlockHook implements BlockHook {
      public void hook(Unicorn u, long address, int size, Object user_data) {
         System.out.printf(">>> Tracing basic block at 0x%x, block size = 0x%x\n", address, size);
      }
   }
      
   // callback for tracing instruction
   private static class MyCodeHook implements CodeHook {
      public void hook(Unicorn u, long address, int size, Object user_data) {
         System.out.printf(">>> Tracing instruction at 0x%x, instruction size = 0x%x\n", address, size);
      }
   }
   
   private static void _test_arm64()
   {
   
       long x11 = 0x1234L;     // X11 register
       long x13 = 0x6789L;     // X13 register
       long x15 = 0x3333L;     // X15 register
   
       System.out.print("Emulate ARM64 code\n");
   
       // Initialize emulator in ARM mode
       Unicorn u = new Unicorn(UnicornConst.UC_ARCH_ARM64, UnicornConst.UC_MODE_ARM);
   
       // map 2MB memory for this emulation
       u.mem_map(ADDRESS, 2 * 1024 * 1024, UnicornConst.UC_PROT_ALL);
   
       // write machine code to be emulated to memory
       u.mem_write(ADDRESS, ARM_CODE);
   
       // initialize machine registers
       u.reg_write(Arm64Const.UC_ARM64_REG_X11, x11);
       u.reg_write(Arm64Const.UC_ARM64_REG_X13, x13);
       u.reg_write(Arm64Const.UC_ARM64_REG_X15, x15);
   
       // tracing all basic blocks with customized callback
       u.hook_add_new(new MyBlockHook(), 1, 0, null);
   
       // tracing one instruction at ADDRESS with customized callback
       u.hook_add_new(new MyCodeHook(), ADDRESS, ADDRESS, null);
   
       // emulate machine code in infinite time (last param = 0), or when
       // finishing all the code.
       u.emu_start(ADDRESS, ADDRESS + ARM_CODE.length, 0, 0);
   
       // now print out some registers
       System.out.print(">>> Emulation done. Below is the CPU context\n");
   
       x11 = u.reg_read(Arm64Const.UC_ARM64_REG_X11);
       System.out.printf(">>> X11 = 0x%x\n", x11);
   
       u.closeAll();
   }

    public void testNative() {
        Unicorn.testSampleArm64();
    }

   public void test() {
       main(null);
   }
   
   public static void main(String[] args)
   {
       _test_arm64();
   }
}
