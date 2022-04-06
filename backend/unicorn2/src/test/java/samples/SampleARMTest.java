/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh, 2015 */

/* Sample code to demonstrate how to emulate ARM code */
package samples;

import com.github.unidbg.arm.backend.unicorn.BlockHook;
import com.github.unidbg.arm.backend.unicorn.CodeHook;
import com.github.unidbg.arm.backend.unicorn.Unicorn;
import junit.framework.TestCase;
import unicorn.ArmConst;
import unicorn.UnicornConst;

import java.io.IOException;

public class SampleARMTest extends TestCase {

    static {
        try {
            org.scijava.nativelib.NativeLoader.loadLibrary("unicorn");
        } catch (IOException ignored) {
        }
    }

   // code to be emulated
   public static final byte[] ARM_CODE = {55,0,(byte)0xa0,(byte)0xe3,3,16,66,(byte)0xe0}; // mov r0, #0x37; sub r1, r2, r3
   public static final byte[] THUMB_CODE = {(byte)0x83, (byte)0xb0}; // sub    sp, #0xc
   
   // memory address where emulation starts
   public static final int ADDRESS = 0x10000;

   private static class MyBlockHook implements BlockHook {
      public void hook(Unicorn u, long address, int size, Object user_data)
      {
          System.out.printf(">>> Tracing basic block at 0x%x, block size = 0x%x\n", address, size);
      }
   }
      
   // callback for tracing instruction
   private static class MyCodeHook implements CodeHook {
      public void hook(Unicorn u, long address, int size, Object user_data) {
       System.out.printf(">>> Tracing instruction at 0x%x, instruction size = 0x%x\n", address, size);
      }
   }
   
   private static void _test_arm()
   {
   
       long r0 = 0x1234L; // R0 register
       long r2 = 0x6789L; // R1 register
       long r3 = 0x3333L; // R2 register
       long r1;     // R1 register
   
       System.out.print("Emulate ARM code\n");
   
       // Initialize emulator in ARM mode
       Unicorn u = new Unicorn(UnicornConst.UC_ARCH_ARM, UnicornConst.UC_MODE_ARM);
   
       // map 2MB memory for this emulation
       u.mem_map(ADDRESS, 2 * 1024 * 1024, UnicornConst.UC_PROT_ALL);
   
       // write machine code to be emulated to memory
       u.mem_write(ADDRESS, ARM_CODE);
   
       // initialize machine registers
       u.reg_write(ArmConst.UC_ARM_REG_R0, r0);
       u.reg_write(ArmConst.UC_ARM_REG_R2, r2);
       u.reg_write(ArmConst.UC_ARM_REG_R3, r3);
   
       // tracing all basic blocks with customized callback
       u.hook_add_new(new MyBlockHook(), 1, 0, null);
   
       // tracing one instruction at ADDRESS with customized callback
       u.hook_add_new(new MyCodeHook(), ADDRESS, ADDRESS, null);
   
       // emulate machine code in infinite time (last param = 0), or when
       // finishing all the code.
       u.emu_start(ADDRESS, ADDRESS + ARM_CODE.length, 0, 0);
   
       // now print out some registers
       System.out.print(">>> Emulation done. Below is the CPU context\n");
   
       r0 = u.reg_read(ArmConst.UC_ARM_REG_R0);
       r1 = u.reg_read(ArmConst.UC_ARM_REG_R1);
       System.out.printf(">>> R0 = 0x%x\n", (int) r0);
       System.out.printf(">>> R1 = 0x%x\n", (int) r1);
   
       u.closeAll();
   }
   
   private static void _test_thumb()
   {
   
       long sp = 0x1234L; // R0 register
   
       System.out.print("Emulate THUMB code\n");
   
       // Initialize emulator in ARM mode
       Unicorn u = new Unicorn(UnicornConst.UC_ARCH_ARM, UnicornConst.UC_MODE_THUMB);
   
       // map 2MB memory for this emulation
       u.mem_map(ADDRESS, 2 * 1024 * 1024, UnicornConst.UC_PROT_ALL);
   
       // write machine code to be emulated to memory
       u.mem_write(ADDRESS, THUMB_CODE);
   
       // initialize machine registers
       u.reg_write(ArmConst.UC_ARM_REG_SP, sp);
   
       // tracing all basic blocks with customized callback
       u.hook_add_new(new MyBlockHook(), 1, 0, null);
   
       // tracing one instruction at ADDRESS with customized callback
       u.hook_add_new(new MyCodeHook(), ADDRESS, ADDRESS, null);
   
       // emulate machine code in infinite time (last param = 0), or when
       // finishing all the code.
       u.emu_start(ADDRESS | 1, ADDRESS + THUMB_CODE.length, 0, 0);
   
       // now print out some registers
       System.out.print(">>> Emulation done. Below is the CPU context\n");
   
       sp = u.reg_read(ArmConst.UC_ARM_REG_SP);
       System.out.printf(">>> SP = 0x%x\n", (int) sp);
   
       u.closeAll();
   }

   public void testNative() {
       Unicorn.testSampleArm();
   }

   public void test() {
       main(null);
   }
   
   public static void main(String[] args)
   {
       _test_thumb();
       System.out.print("==========================\n");
       _test_arm();
   }

}
