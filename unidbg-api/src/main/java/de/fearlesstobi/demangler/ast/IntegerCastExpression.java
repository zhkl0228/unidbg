package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class IntegerCastExpression extends ParentNode {
    private final String number;

    public IntegerCastExpression(BaseNode type, String number) {
        super(NodeType.IntegerCastExpression, type);
        this.number = number;
    }

    @Override
    public void printLeft(StringWriter writer) {
        writer.write("(");
        child.print(writer);
        writer.write(")");
        writer.write(number);
    }
}