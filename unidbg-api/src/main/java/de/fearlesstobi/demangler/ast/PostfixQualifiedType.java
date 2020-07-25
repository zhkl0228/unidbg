package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class PostfixQualifiedType extends ParentNode {
    private final String postfixQualifier;

    public PostfixQualifiedType(String postfixQualifier, BaseNode type) {
        super(NodeType.PostfixQualifiedType, type);
        this.postfixQualifier = postfixQualifier;
    }

    @Override
    public void printLeft(StringWriter writer) {
        child.print(writer);
        writer.write(postfixQualifier);
    }
}