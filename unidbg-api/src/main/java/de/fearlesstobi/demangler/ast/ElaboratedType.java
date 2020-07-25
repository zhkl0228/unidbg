package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class ElaboratedType extends ParentNode {
    private final String elaborated;

    public ElaboratedType(String elaborated, BaseNode type) {
        super(NodeType.ElaboratedType, type);
        this.elaborated = elaborated;
    }

    @Override
    public void printLeft(StringWriter writer) {
        writer.write(elaborated);
        writer.write(" ");
        child.print(writer);
    }
}