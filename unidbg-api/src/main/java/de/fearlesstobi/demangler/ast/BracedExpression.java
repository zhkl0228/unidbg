package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class BracedExpression extends BaseNode {
    private final BaseNode element;
    private final BaseNode expression;
    private final boolean isArrayExpression;

    public BracedExpression(BaseNode element, BaseNode expression, boolean isArrayExpression) {
        super(NodeType.BracedExpression);
        this.element = element;
        this.expression = expression;
        this.isArrayExpression = isArrayExpression;
    }

    @Override
    public void printLeft(StringWriter writer) {
        if (isArrayExpression) {
            writer.write("[");
            element.print(writer);
            writer.write("]");
        } else {
            writer.write(".");
            element.print(writer);
        }

        writer.write(" = ");

        expression.print(writer);
    }
}

