package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class CtorVtableSpecialName extends BaseNode {
    private final BaseNode firstType;
    private final BaseNode secondType;

    public CtorVtableSpecialName(BaseNode firstType, BaseNode secondType) {
        super(NodeType.CtorVtableSpecialName);
        this.firstType = firstType;
        this.secondType = secondType;
    }

    @Override
    public void printLeft(StringWriter writer) {
        writer.write("construction vtable for ");
        firstType.print(writer);
        writer.write("-in-");
        secondType.print(writer);
    }
}