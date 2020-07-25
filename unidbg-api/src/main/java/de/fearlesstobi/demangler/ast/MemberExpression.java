package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class MemberExpression extends BaseNode {
    private final BaseNode leftNode;
    private final String kind;
    private final BaseNode rightNode;

    public MemberExpression(BaseNode leftNode, String kind, BaseNode rightNode) {
        super(NodeType.MemberExpression);
        this.leftNode = leftNode;
        this.kind = kind;
        this.rightNode = rightNode;
    }

    @Override
    public void printLeft(StringWriter writer) {
        leftNode.print(writer);
        writer.write(kind);
        rightNode.print(writer);
    }
}