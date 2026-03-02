package com.github.unidbg.arm.backend.hypervisor.arm64;

import capstone.api.Instruction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SimpleMemorySizeDetector implements MemorySizeDetector {

    private static final Logger log = LoggerFactory.getLogger(SimpleMemorySizeDetector.class);

    @Override
    public int detectReadSize(Instruction insn) {
        switch (insn.getMnemonic()) {
            case "ldrb":
            case "ldursb":
            case "ldarb":
            case "ldaprb":
                return 1;
            case "ldursh":
            case "ldrh":
            case "ldarh":
            case "ldaprh":
                return 2;
            case "ldr":
            case "ldxr":
            case "ldaxr":
            case "ldur":
            case "ldar":
            case "ldapr":
            case "ldadd":
            case "ldadda":
            case "ldaddal":
            case "ldaddl":
            case "ldclr":
            case "ldclra":
            case "ldclral":
            case "ldclrl":
            case "ldeor":
            case "ldeora":
            case "ldeoral":
            case "ldeorl":
            case "ldset":
            case "ldseta":
            case "ldsetal":
            case "ldsetl":
            case "swp":
            case "swpa":
            case "swpal":
            case "swpl":
            case "cas":
            case "casa":
            case "casal":
            case "casl":
                if (insn.getOpStr().startsWith("w")) {
                    return 4;
                }
                if (insn.getOpStr().startsWith("x")) {
                    return 8;
                }
                break;
            case "ldp":
            case "ldxp":
            case "ldaxp":
                if (insn.getOpStr().startsWith("w")) {
                    return 8;
                }
                if (insn.getOpStr().startsWith("x")) {
                    return 16;
                }
                break;
            default:
                log.info("detectReadSize: insn={}", insn);
                break;
        }
        return 0;
    }

    @Override
    public int detectWriteSize(Instruction insn) {
        String opStr = insn.getOpStr();
        switch (insn.getMnemonic()) {
            case "strb":
            case "sturb":
            case "stlrb":
                return 1;
            case "strh":
            case "sturh":
            case "stlrh":
                return 2;
            case "str":
            case "stur":
            case "stlr":
            case "ldadd":
            case "ldadda":
            case "ldaddal":
            case "ldaddl":
            case "ldclr":
            case "ldclra":
            case "ldclral":
            case "ldclrl":
            case "ldeor":
            case "ldeora":
            case "ldeoral":
            case "ldeorl":
            case "ldset":
            case "ldseta":
            case "ldsetal":
            case "ldsetl":
            case "swp":
            case "swpa":
            case "swpal":
            case "swpl":
            case "cas":
            case "casa":
            case "casal":
            case "casl":
                if (opStr.startsWith("w")) {
                    return 4;
                }
                if (opStr.startsWith("x")) {
                    return 8;
                }
                break;
            case "stxr":
            case "stlxr": {
                String valueReg = extractAfterFirstComma(opStr);
                if (valueReg.startsWith("w")) {
                    return 4;
                }
                if (valueReg.startsWith("x")) {
                    return 8;
                }
                break;
            }
            case "stp":
                if (opStr.startsWith("w")) {
                    return 8;
                }
                if (opStr.startsWith("x")) {
                    return 16;
                }
                break;
            case "stxp":
            case "stlxp": {
                String valueReg = extractAfterFirstComma(opStr);
                if (valueReg.startsWith("w")) {
                    return 8;
                }
                if (valueReg.startsWith("x")) {
                    return 16;
                }
                break;
            }
            default:
                log.info("detectWriteSize: insn={}", insn);
                break;
        }
        return 0;
    }

    private static String extractAfterFirstComma(String opStr) {
        int commaIdx = opStr.indexOf(',');
        return commaIdx >= 0 ? opStr.substring(commaIdx + 1).trim() : opStr;
    }

}
