package king.trace;

import unicorn.Arm64Const;
import unicorn.Unicorn;

import java.util.Hashtable;

public class Arm64Calc extends AssemblyCalc {
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

    public Arm64Calc(Unicorn unicorn){
        RegDic=new Hashtable<String, Integer>();
        RegDic.put("x0", Arm64Const.UC_ARM64_REG_X0);
        RegDic.put("x1",Arm64Const.UC_ARM64_REG_X1);
        RegDic.put("x2",Arm64Const.UC_ARM64_REG_X2);
        RegDic.put("x3",Arm64Const.UC_ARM64_REG_X3);
        RegDic.put("x4",Arm64Const.UC_ARM64_REG_X4);
        RegDic.put("x5",Arm64Const.UC_ARM64_REG_X5);
        RegDic.put("x6",Arm64Const.UC_ARM64_REG_X6);
        RegDic.put("x7",Arm64Const.UC_ARM64_REG_X7);
        RegDic.put("x8",Arm64Const.UC_ARM64_REG_X8);
        RegDic.put("x9",Arm64Const.UC_ARM64_REG_X9);
        RegDic.put("x10",Arm64Const.UC_ARM64_REG_X10);
        RegDic.put("x11",Arm64Const.UC_ARM64_REG_X11);
        RegDic.put("x12",Arm64Const.UC_ARM64_REG_X12);
        RegDic.put("x13",Arm64Const.UC_ARM64_REG_X13);
        RegDic.put("x14",Arm64Const.UC_ARM64_REG_X14);
        RegDic.put("x15",Arm64Const.UC_ARM64_REG_X15);
        RegDic.put("x16",Arm64Const.UC_ARM64_REG_X16);
        RegDic.put("x17",Arm64Const.UC_ARM64_REG_X17);
        RegDic.put("x18",Arm64Const.UC_ARM64_REG_X18);
        RegDic.put("x19",Arm64Const.UC_ARM64_REG_X19);
        RegDic.put("x20",Arm64Const.UC_ARM64_REG_X20);
        RegDic.put("x21",Arm64Const.UC_ARM64_REG_X21);
        RegDic.put("x22",Arm64Const.UC_ARM64_REG_X22);
        RegDic.put("x23",Arm64Const.UC_ARM64_REG_X23);
        RegDic.put("x24",Arm64Const.UC_ARM64_REG_X24);
        RegDic.put("x25",Arm64Const.UC_ARM64_REG_X25);
        RegDic.put("x26",Arm64Const.UC_ARM64_REG_X26);
        RegDic.put("x27",Arm64Const.UC_ARM64_REG_X27);
        RegDic.put("x28",Arm64Const.UC_ARM64_REG_X28);
        RegDic.put("x29",Arm64Const.UC_ARM64_REG_W29);
        RegDic.put("x30",Arm64Const.UC_ARM64_REG_W30);
        RegDic.put("w0",Arm64Const.UC_ARM64_REG_X0);
        RegDic.put("w1",Arm64Const.UC_ARM64_REG_X1);
        RegDic.put("w2",Arm64Const.UC_ARM64_REG_X2);
        RegDic.put("w3",Arm64Const.UC_ARM64_REG_X3);
        RegDic.put("w4",Arm64Const.UC_ARM64_REG_X4);
        RegDic.put("w5",Arm64Const.UC_ARM64_REG_X5);
        RegDic.put("w6",Arm64Const.UC_ARM64_REG_X6);
        RegDic.put("w7",Arm64Const.UC_ARM64_REG_X7);
        RegDic.put("w8",Arm64Const.UC_ARM64_REG_X8);
        RegDic.put("w9",Arm64Const.UC_ARM64_REG_X9);
        RegDic.put("w10",Arm64Const.UC_ARM64_REG_X10);
        RegDic.put("w11",Arm64Const.UC_ARM64_REG_X11);
        RegDic.put("w12",Arm64Const.UC_ARM64_REG_X12);
        RegDic.put("w13",Arm64Const.UC_ARM64_REG_X13);
        RegDic.put("w14",Arm64Const.UC_ARM64_REG_X14);
        RegDic.put("w15",Arm64Const.UC_ARM64_REG_X15);
        RegDic.put("w16",Arm64Const.UC_ARM64_REG_X16);
        RegDic.put("w17",Arm64Const.UC_ARM64_REG_X17);
        RegDic.put("w18",Arm64Const.UC_ARM64_REG_X18);
        RegDic.put("w19",Arm64Const.UC_ARM64_REG_X19);
        RegDic.put("w20",Arm64Const.UC_ARM64_REG_X20);
        RegDic.put("w21",Arm64Const.UC_ARM64_REG_X21);
        RegDic.put("w22",Arm64Const.UC_ARM64_REG_X22);
        RegDic.put("w23",Arm64Const.UC_ARM64_REG_X23);
        RegDic.put("w24",Arm64Const.UC_ARM64_REG_X24);
        RegDic.put("w25",Arm64Const.UC_ARM64_REG_X25);
        RegDic.put("w26",Arm64Const.UC_ARM64_REG_X26);
        RegDic.put("w27",Arm64Const.UC_ARM64_REG_X27);
        RegDic.put("w28",Arm64Const.UC_ARM64_REG_X28);
        RegDic.put("w29",Arm64Const.UC_ARM64_REG_W29);
        RegDic.put("w30",Arm64Const.UC_ARM64_REG_W30);
        RegDic.put("fp",Arm64Const.UC_ARM64_REG_FP);
        RegDic.put("lr",Arm64Const.UC_ARM64_REG_LR);
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
