package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class ThrowExpression extends BaseNode {
    private final BaseNode expression;

    public ThrowExpression(BaseNode expression) {
        super(NodeType.ThrowExpression);
        this.expression = expression;
    }

    @Override
    public void printLeft(StringWriter writer) {
        writer.write("throw ");
        expression.print(writer);
    }
}