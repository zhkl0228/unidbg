package king.trace;

import com.github.unidbg.utils.Inspector;
import unicorn.Unicorn;

import java.util.Hashtable;

enum CalcType{
    LSL,LSR,BIC,ORR,EOR,ADD,SUB,MVN,AND,MOV,MOVT,MOVW,LDR,ORN,UXTB
}

public abstract class AssemblyCalc {
    public abstract String LSL() ;
    public abstract String LSR();
    public abstract String BIC();
    public abstract String ORR();
    public abstract String EOR();
    public abstract String ADD();
    public abstract String SUB();
    public abstract String MVN();
    public abstract String AND();
    public abstract String MOV();
    public abstract String MOVT();
    public abstract String MOVW();
    public abstract String LDR();
    public abstract String ORN();
    public abstract String UXTB();
    public abstract String GetResult(boolean isDump);
    public String Ops ="";
    public String Opcode ="";
    public String Arg1Name ="";
    public String Arg2Name ="";
    public String Arg3Name= "";
    private int Arg1Value=-1;
    private int Arg2Value=-1;
    private int Arg3Value=-1;
    public void setArg1(int arg){
        this.Arg1Value=arg;
    }
    public void setArg2(int arg){
        this.Arg2Value=arg;
    }
    public void setArg3(int arg){
        this.Arg3Value=arg;
    }
    public long getArg1(){
        return (long)this.Arg1Value &0xffffffffL;
    }
    public long getArg2(){
        return (long)this.Arg2Value &0xffffffffL;
    }
    public long getArg3(){
        return (long)this.Arg3Value &0xffffffffL;
    }

    public int DumpSize=0x40;
    public Hashtable<String, Integer> RegDic;
    public CalcType OpType;
    //在最后面的常量数值
    public int OpValue=0;
    public Unicorn unicorn;
    public abstract void Init(String ops,String opcode);
    public String ExecCalc(){
        if(this.Ops.startsWith("lsr")) {
            this.OpType= CalcType.LSR;
            return LSR();
        }else if(this.Ops.startsWith("lsl")){
            this.OpType= CalcType.LSL;
            return LSL();
        }else if(this.Ops.startsWith("bic")){
            this.OpType= CalcType.BIC;
            return BIC();
        }else if(this.Ops.startsWith("orr")){
            this.OpType= CalcType.ORR;
            return ORR();
        }else if (this.Ops.startsWith("add")){
            this.OpType= CalcType.ADD;
            return ADD();
        }else if (this.Ops.startsWith("eor")){
            this.OpType= CalcType.EOR;
            return EOR();
        }else if (this.Ops.startsWith("and")){
            this.OpType= CalcType.AND;
            return AND();
        }else if (this.Ops.startsWith("mvn")){
            this.OpType= CalcType.MVN;
            return MVN();
        }else if (this.Ops.startsWith("sub")) {
            this.OpType = CalcType.SUB;
            return SUB();
        }else if (this.Ops.startsWith("orn")){
                this.OpType= CalcType.ORN;
                return ORN();
        }else if (this.Ops.startsWith("uxtb")){
            this.OpType= CalcType.UXTB;
            return UXTB();
        }else if(this.Ops.equals("mov")){
            this.OpType= CalcType.MOV;
            return MOV();
        }else if(this.Ops.equals("movw")){
            this.OpType= CalcType.MOVW;
            return MOVW();
        }else if(this.Ops.equals("movt")){
            this.OpType= CalcType.MOVT;
            return MOVT();
        }else if (this.Ops.startsWith("ldr")){
            this.OpType= CalcType.LDR;
            return LDR();
        }
        return "";
    }
    public long GetLeftOpValue(){

        long ret=0;
        if(!this.Arg3Name.equals("")){
            ret= (long)this.Arg3Value&0xffffffffL;
        }else if(!this.Arg2Name.equals("")){
            ret= (long)this.Arg2Value&0xffffffffL;
        }else {
            ret= (long)this.Arg1Value&0xffffffffL;
        }
        return ret;
    }
    public int GetSharpValue(String opcode){
        if(!opcode.contains("#")){
            return 0;
        }
        String[] opdata= opcode.split("#");
        String lsdata=opdata[1].replace("]","");
        int inttp=10;
        if(lsdata.contains("0x")){
            inttp=16;
        }
        lsdata=lsdata.replace("0x","");
        lsdata=lsdata.replace("lsl","");
        lsdata=lsdata.replace("lsr","");
        return Integer.valueOf(lsdata,inttp);
    }

    public void DumpHex(long hex){
        if(hex>0xffff){
            try{
                byte[] data = unicorn.mem_read(hex, this.DumpSize);
                if(data.length>0){
                    Inspector.inspect(data,String.format("0x%x 当前数据",hex));
                }
            }catch (Exception ex){
            }
        }
    }
}

