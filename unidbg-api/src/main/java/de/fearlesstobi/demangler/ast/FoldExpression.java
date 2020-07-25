package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class FoldExpression extends BaseNode {
    private final boolean isLeftFold;
    private final String operatorName;
    private final BaseNode expression;
    private final BaseNode initializer;

    public FoldExpression(boolean isLeftFold, String operatorName, BaseNode expression, BaseNode initializer) {
        super(NodeType.FunctionParameter);
        this.isLeftFold = isLeftFold;
        this.operatorName = operatorName;
        this.expression = expression;
        this.initializer = initializer;
    }

    @Override
    public void printLeft(StringWriter writer) {
        writer.write("(");

        if (isLeftFold && initializer != null) {
            initializer.print(writer);
            writer.write(" ");
            writer.write(operatorName);
            writer.write(" ");
        }

        writer.write(isLeftFold ? "... " : " ");
        writer.write(operatorName);
        writer.write(!isLeftFold ? " ..." : " ");
        expression.print(writer);

        if (!isLeftFold && initializer != null) {
            initializer.print(writer);
            writer.write(" ");
            writer.write(operatorName);
            writer.write(" ");
        }

        writer.write(")");
    }
}