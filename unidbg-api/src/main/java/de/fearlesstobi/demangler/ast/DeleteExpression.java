package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class DeleteExpression extends ParentNode {
    private final boolean isGlobal;
    private final boolean isArrayExpression;

    public DeleteExpression(BaseNode child, boolean isGlobal, boolean isArrayExpression) {
        super(NodeType.DeleteExpression, child);
        this.isGlobal = isGlobal;
        this.isArrayExpression = isArrayExpression;
    }

    @Override
    public void printLeft(StringWriter writer) {
        if (isGlobal) {
            writer.write("::");
        }

        writer.write("delete");

        if (isArrayExpression) {
            writer.write("[] ");
        }

        child.print(writer);
    }
}