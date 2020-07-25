package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class ConditionalExpression extends BaseNode {
    private final BaseNode thenNode;
    private final BaseNode elseNode;
    private final BaseNode conditionNode;

    public ConditionalExpression(BaseNode conditionNode, BaseNode thenNode, BaseNode elseNode) {
        super(NodeType.ConditionalExpression);
        this.thenNode = thenNode;
        this.conditionNode = conditionNode;
        this.elseNode = elseNode;
    }

    @Override
    public void printLeft(StringWriter writer) {
        writer.write("(");
        conditionNode.print(writer);
        writer.write(") ? (");
        thenNode.print(writer);
        writer.write(") : (");
        elseNode.print(writer);
        writer.write(")");
    }
}