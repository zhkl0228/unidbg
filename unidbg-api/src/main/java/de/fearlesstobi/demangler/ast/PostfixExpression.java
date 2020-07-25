package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class PostfixExpression extends ParentNode {
    private final String operator;

    public PostfixExpression(BaseNode type, String operator) {
        super(NodeType.PostfixExpression, type);
        this.operator = operator;
    }

    @Override
    public void printLeft(StringWriter writer) {
        writer.write("(");
        child.print(writer);
        writer.write(")");
        writer.write(operator);
    }
}