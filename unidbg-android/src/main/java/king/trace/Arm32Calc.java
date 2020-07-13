package king.trace;

import unicorn.ArmConst;
import unicorn.Unicorn;

import java.util.Hashtable;

public class Arm32Calc extends AssemblyCalc {
    @Override
    public String LSL() {
        int ret=0;
        if(this.OpValue>0){
            long leftValue=this.GetLeftOpValue();
            ret=(int)(leftValue<<this.OpValue);
        }
        else if(!this.Arg3Name.equals("")){
            ret=(int)(this.getArg2()<<this.getArg3());
        }else{
            ret=(int)this.getArg1()<<this.getArg2();
        }
        return String.format("%s=0x%x",this.Arg1Name,ret);
    }

    @Override
    public String LSR() {
        int ret=0;
        if(this.OpValue>0){
            long leftValue=this.GetLeftOpValue();
            ret=(int)(leftValue>>this.OpValue);
        }else if(!this.Arg3Name.equals("")){
            ret=(int)this.getArg2()>>this.getArg3();
        }else{
            ret=(int)this.getArg1()>>this.getArg2();
        }
        return String.format("%s=0x%x",this.Arg1Name,ret);
    }

    @Override
    public String BIC() {
        int ret=0;
        if(this.OpValue>0){
            if (this.Opcode.contains("lsl")){
                ret=(int)(this.getArg2()&~(this.getArg3()<<this.OpValue));
            }else if (this.Opcode.contains("lsr")){
                ret=(int)(this.getArg2()&~(this.getArg3()>>this.OpValue));
            }else{
                long leftValue=this.GetLeftOpValue();
                ret=(int)(leftValue&~this.OpValue);
            }
        }
        else if(!this.Arg3Name.equals("")){
            ret=(int)(this.getArg2()&~this.getArg3());
        }else{
            ret=(int)(this.getArg1()&~this.getArg2());
        }
        return String.format("%s=0x%x",this.Arg1Name,ret);
    }

    @Override
    public String ORR() {
        int ret=0;
        if(this.OpValue>0){
            if (this.Opcode.contains("lsl")){
                ret=(int)(this.getArg2()|(this.getArg3()<<this.OpValue));
            }else if (this.Opcode.contains("lsr")){
                ret=(int)(this.getArg2()|(this.getArg3()>>this.OpValue));
            }else{
                long leftValue=this.GetLeftOpValue();
                ret=(int)(leftValue|this.OpValue);
            }
        }
        else if(!this.Arg3Name.equals("")){
            ret=(int)(this.getArg2()|this.getArg3());
        }else{
            ret=(int)(this.getArg1()|this.getArg2());
        }
        return String.format("%s=0x%x",this.Arg1Name,ret);
    }

    @Override
    public String EOR() {
        int ret=0;
        if(this.OpValue>0){
            if (this.Opcode.contains("lsl")){
                ret=(int)(this.getArg2()^(this.getArg3()<<this.OpValue));
            }else if (this.Opcode.contains("lsr")){
                ret=(int)(this.getArg2()^(this.getArg3()>>this.OpValue));
            }else{
                long leftValue=this.GetLeftOpValue();
                ret=(int)(leftValue^this.OpValue);
            }
        }
        else if(!this.Arg3Name.equals("")){
            ret=(int)(this.getArg2()^this.getArg3());
        }else{
            ret=(int)(this.getArg1()^this.getArg2());
        }
        return String.format("%s=0x%x",this.Arg1Name,ret);
    }

    @Override
    public String ADD() {
        int ret=0;
        if(this.OpValue>0){
            if (this.Opcode.contains("lsl")){
                ret=(int)(this.getArg2()+(this.getArg3()<<this.OpValue));
            }else if (this.Opcode.contains("lsr")){
                ret=(int)(this.getArg2()+(this.getArg3()>>this.OpValue));
            }else{
                long leftValue=this.GetLeftOpValue();
                ret=(int)(leftValue+this.OpValue);
            }
        }
        else if(!this.Arg3Name.equals("")){
            ret=(int)(this.getArg2()+this.getArg3());
        }else{
            ret=(int)(this.getArg1()+this.getArg2());
        }
        return String.format("%s=0x%x",this.Arg1Name,ret);
    }

    @Override
    public String SUB() {
        int ret=0;
        if(this.OpValue>0){
            if (this.Opcode.contains("lsl")){
                ret=(int)(this.getArg2()-(this.getArg3()<<this.OpValue));
            }else if (this.Opcode.contains("lsr")){
                ret=(int)(this.getArg2()-(this.getArg3()>>this.OpValue));
            }else{
                long leftValue=this.GetLeftOpValue();
                ret=(int)(leftValue-this.OpValue);
            }
        }
        else if(!this.Arg3Name.equals("")){
            ret=(int)(this.getArg2()-this.getArg3());
        }else{
            ret=(int)(this.getArg1()-this.getArg2());
        }
        return String.format("%s=0x%x",this.Arg1Name,ret);
    }

    @Override
    public String MVN() {
        int ret=0;
        if(this.OpValue>0){
            ret=(int)~this.OpValue;
        }else if(!this.Arg3Name.equals("")){
            ret=(int)~this.getArg3();
        }else{
            ret=(int)~this.getArg2();
        }
        return String.format("%s=0x%x",this.Arg1Name,ret);
    }

    @Override
    public String AND() {
        if(this.OpValue>0){
            if (this.Opcode.contains("lsl")){
                return String.format("%s=0x%x",this.Arg1Name,this.getArg2()&(this.getArg3()<<this.OpValue));
            }else if (this.Opcode.contains("lsr")){
                return String.format("%s=0x%x",this.Arg1Name,this.getArg2()&(this.getArg3()>>this.OpValue));
            }
            long leftValue=this.GetLeftOpValue();
            return String.format("%s=0x%x",this.Arg1Name,(int)(leftValue&this.OpValue));
        }
        if(!this.Arg3Name.equals("")){
            return String.format("%s=0x%x",this.Arg1Name,this.getArg2()&this.getArg3());
        }
        return String.format("%s=0x%x",this.Arg1Name,this.getArg1()&this.getArg2());
    }

    @Override
    public String ORN() {
        int ret=0;
        if(this.OpValue>0){
            if (this.Opcode.contains("lsl")){
                ret=(int)(this.getArg2()|(~(this.getArg3()<<this.OpValue)));
            }else if (this.Opcode.contains("lsr")){
                ret=(int)(this.getArg2()&(~(this.getArg3()>>this.OpValue)));
            }else{
                long leftValue=this.GetLeftOpValue();
                ret=(int)(leftValue|(~this.OpValue));
            }
        }
        else if(!this.Arg3Name.equals("")){
            ret=(int)(this.getArg2()|(~this.getArg3()));
        }else{
            ret=(int)(this.getArg1()|(~this.getArg2()));
        }
        return String.format("%s=0x%x",this.Arg1Name,ret);
    }

    @Override
    public String UXTB() {
        return String.format("%s=0x%x",this.Arg1Name,this.getArg2()&0xff);
    }

    @Override
    public String MOV() {
        return String.format("%s=0x%x",this.Arg1Name,this.getArg2());
    }

    @Override
    public String MOVT() {
        long startdata=this.getArg1()&0x0000ffff;
        long ndata=startdata|(this.OpValue<<16);

        return String.format("%s=0x%x",this.Arg1Name,(int)ndata);
    }

    @Override
    public String MOVW() {
        long startdata=this.getArg1()&0xffff0000;
        long ndata=startdata|this.OpValue;
        return String.format("%s=0x%x",this.Arg1Name,ndata);
    }

    @Override
    public String LDR() {
        String[] opcodeSplit=this.Opcode.split("#");
        if (this.Opcode.contains("lsl")){
            long retPointer=this.getArg2()+(this.getArg3()<<this.OpValue);
            byte[] data = unicorn.mem_read(retPointer, 0x4);
            int ret=  java.nio.ByteBuffer.wrap(data).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
            return String.format("%s=0x%x",this.Arg1Name,ret);
        }
        else if(this.Opcode.contains("lsr")){
            long retPointer=this.getArg2()+(this.getArg3()>>this.OpValue);
            byte[] data = unicorn.mem_read(retPointer, 0x4);
            int ret=  java.nio.ByteBuffer.wrap(data).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
            return String.format("%s=0x%x",this.Arg1Name,ret);
        }
        else if(opcodeSplit[opcodeSplit.length-1].contains("]")){
            try{
                if(this.Arg2Name.equals("pc")){
                    this.OpValue+=0x4;
                }
                byte[] data = unicorn.mem_read(this.getArg2()+this.OpValue, 0x4);
                int ret=  java.nio.ByteBuffer.wrap(data).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
                return String.format("%s=0x%x",this.Arg1Name,ret);
            }catch(Exception ex){
                return String.format("内存读取异常");
            }
        }else{
            try{
                byte[] data = unicorn.mem_read(this.getArg2(), 0x4);
                int ret=  java.nio.ByteBuffer.wrap(data).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
                return String.format("%s=0x%x %s=0x%x",this.Arg1Name,ret,this.Arg2Name,this.getArg2()+this.OpValue);
            }catch(Exception ex){
                return String.format("内存读取异常");
            }
        }
    }

    @Override
    public String GetResult(boolean isDump) {
        StringBuilder sb=new StringBuilder();
        sb.append("   -------");
        try{
            if(!this.Arg1Name.equals("")){
                sb.append(String.format("   %s=0x%x",this.Arg1Name,this.getArg1()));
            }
            if(!this.Arg2Name.equals("")){
                sb.append(String.format("   %s=0x%x",this.Arg2Name,this.getArg2()));
            }
            if(!this.Arg3Name.equals("")){
                sb.append(String.format("   %s=0x%x",this.Arg3Name,this.getArg3()));
            }
            String calcRet= this.ExecCalc();
            if(calcRet.equals("")){
                return sb.toString();
            }
            sb.append("  //");
            sb.append(calcRet);
            if(isDump){
                this.DumpHex(this.getArg1());
                this.DumpHex(this.getArg2());
                this.DumpHex(this.getArg3());
                this.DumpHex(this.OpValue);
            }
        }catch (Exception ex){
            sb.append("  //计算结果异常");
        }
        return sb.toString();
    }

    public Arm32Calc(Unicorn unicorn){
        RegDic=new Hashtable<String, Integer>();
        RegDic.put("r0", ArmConst.UC_ARM_REG_R0);
        RegDic.put("r1", ArmConst.UC_ARM_REG_R1);
        RegDic.put("r2", ArmConst.UC_ARM_REG_R2);
        RegDic.put("r3",ArmConst.UC_ARM_REG_R3);
        RegDic.put("r4",ArmConst.UC_ARM_REG_R4);
        RegDic.put("r5",ArmConst.UC_ARM_REG_R5);
        RegDic.put("r6",ArmConst.UC_ARM_REG_R6);
        RegDic.put("r7",ArmConst.UC_ARM_REG_R7);
        RegDic.put("r8",ArmConst.UC_ARM_REG_R8);
        RegDic.put("sb",ArmConst.UC_ARM_REG_R9);
        RegDic.put("sl",ArmConst.UC_ARM_REG_R10);
        RegDic.put("ip",ArmConst.UC_ARM_REG_IP);
        RegDic.put("sp",ArmConst.UC_ARM_REG_SP);
        RegDic.put("fp",ArmConst.UC_ARM_REG_FP);
        RegDic.put("lr",ArmConst.UC_ARM_REG_LR);
        RegDic.put("pc",ArmConst.UC_ARM_REG_PC);
        this.unicorn=unicorn;
    }

    @Override
    public void Init(String ops, String opcode) {
        this.Ops=ops;
        this.Opcode=opcode;
        String[] opcodeSplit=opcode.split(",");
        int reg1=-1;
        String reg1name="";
        int reg2=-1;
        String reg2name="";
        int reg3=-1;
        String reg3name="";
        for(int i=0;i<opcodeSplit.length;i++){
            String tmp=opcodeSplit[i].replace("[","");
            tmp=tmp.replace("]","");
            tmp=tmp.replace(" ","");
            if(RegDic.containsKey(tmp)){
                if(i==0){
                    reg1=RegDic.get(tmp);
                    reg1name=tmp;
                }else if(i==1){
                    reg2=RegDic.get(tmp);
                    reg2name=tmp;
                }else if(i==2){
                    reg3=RegDic.get(tmp);
                    reg3name=tmp;
                }
            }
        }
        int reg1data=((Number) unicorn.reg_read(reg1)).intValue();
        int reg2data=((Number) unicorn.reg_read(reg2)).intValue();
        int reg3data=((Number) unicorn.reg_read(reg3)).intValue();
        this.Arg1Name=reg1name;
        this.Arg2Name=reg2name;
        this.Arg3Name=reg3name;
        if(!reg1name.equals("")){
            this.setArg1(reg1data);
        }
        if(!reg2name.equals("")){
            this.setArg2(reg2data);
        }
        if(!reg3name.equals("")){
            this.setArg3(reg3data);
        }
        this.OpValue=GetSharpValue(opcode);
    }
}
