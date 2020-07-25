package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class BinaryExpression extends BaseNode {
    private final BaseNode leftPart;
    private final String name;
    private final BaseNode rightPart;

    public BinaryExpression(BaseNode leftPart, String name, BaseNode rightPart) {
        super(NodeType.BinaryExpression);
        this.leftPart = leftPart;
        this.name = name;
        this.rightPart = rightPart;
    }

    @Override
    public void printLeft(StringWriter writer) {
        if (name.equals(">")) {
            writer.write("(");
        }

        writer.write("(");
        leftPart.print(writer);
        writer.write(") ");

        writer.write(name);

        writer.write(" (");
        rightPart.print(writer);
        writer.write(")");

        if (name.equals(">")) {
            writer.write(")");
        }
    }
}