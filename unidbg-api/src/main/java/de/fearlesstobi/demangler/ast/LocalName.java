package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class LocalName extends BaseNode {
    private final BaseNode encoding;
    private final BaseNode entity;

    public LocalName(BaseNode encoding, BaseNode entity) {
        super(NodeType.LocalName);
        this.encoding = encoding;
        this.entity = entity;
    }

    @Override
    public void printLeft(StringWriter writer) {
        encoding.print(writer);
        writer.write("::");
        entity.print(writer);
    }
}