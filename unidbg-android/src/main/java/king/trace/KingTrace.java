package king.trace;

import capstone.Capstone;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.memory.Memory;
import unicorn.CodeHook;
import unicorn.Unicorn;
import unicorn.UnicornException;

import java.io.*;
import java.util.Arrays;

class KingTrace implements CodeHook {
    private AndroidEmulator emulator;
    private Unicorn unicorn;
    private StringBuilder outLogSb=new StringBuilder();
    private AssemblyCalc armCalc;
    private int logType;
    private boolean isDump;
    private String savePath="./myCodeDumper.log";

    //isDump 是否dump寄存器中的指针, logType 日志输出方式 0 控制台输出 1 日志文件输出
    public KingTrace(AndroidEmulator emulator, boolean isDump, int logType) {
        this(emulator,isDump,logType,"");
    }
    public KingTrace(AndroidEmulator emulator, boolean isDump, int logType, String savePath) {
        super();
        this.emulator = emulator;
        this.logType=logType;
        this.isDump=isDump;
        unicorn=this.emulator.getUnicorn();
        if(emulator.is32Bit()){
            this.armCalc=new Arm32Calc(unicorn);
        }else{
            this.armCalc= new Arm64Calc(unicorn);
        }
        this.savePath=savePath;
    }

    public String KingCalc(String opt,String opcode){
        String result="";
        //过滤掉
        if(opt.contains("bfi")){
            return "";
        }
        try{
            armCalc.Init(opt,opcode);
            result=armCalc.GetResult(isDump);
        }catch (Exception ex){
            result="    //计算异常2";
        }
        return result;
    }

    @Override
    public void hook(Unicorn u, long address, int size, Object user) {
        try {
            Memory memory = this.emulator.getMemory();
            Module module = memory.findModuleByAddress(address);
            if(module.name.equals("libhookzz.so")||module.name.equals("libc.so")){
                return;
            }
            PrintStream out = System.out;
            Capstone.CsInsn[] insns = this.emulator.disassemble(address, size,0);
            if (insns == null || insns.length != 1) {
                throw new IllegalStateException("insns=" + Arrays.toString(insns));
            }
            Capstone.CsInsn ins=insns[0];
            String opcode= ins.opStr;
            String result=KingCalc(ins.mnemonic,opcode);
            printMsg(this.emulator, address, size, result);
        } catch (UnicornException | FileNotFoundException e) {
            throw new IllegalStateException(e);
        }
    }

    private void printMsg(Emulator<?> emulator, long address, int size, String appstr) throws FileNotFoundException {
        Capstone.CsInsn[] insns = emulator.disassemble(address, size, 0);
        StringBuilder sb = new StringBuilder();
        for (Capstone.CsInsn ins : insns) {
//            sb.append("### Trace king Instruction ");
            sb.append(ARM.assembleDetail(emulator, ins, address, false));
            sb.append(appstr);
            sb.append('\n');
            address += ins.size;
        }
        if(this.logType==0){
            PrintStream out = System.out;
            out.print(sb.toString());
        }else if(this.logType==1){
            outLogSb.append(sb.toString());
            if(outLogSb.length()>1000000){
                File outfile=new File(this.savePath);
                FileOutputStream os=new FileOutputStream(outfile,true);
                try{
                    os.write(outLogSb.toString().getBytes());
                    outLogSb.delete( 0, outLogSb.length() );
                    os.close();
                }catch(IOException e){
                    e.printStackTrace();
                }
            }
        }

    }
}