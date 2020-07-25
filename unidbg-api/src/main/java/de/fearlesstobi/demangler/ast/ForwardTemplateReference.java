package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class ForwardTemplateReference extends BaseNode {
    // TODO: Compute inside the de.fearlesstobi.demangler.Demangler
    private BaseNode reference;

    public ForwardTemplateReference() {
        super(NodeType.ForwardTemplateReference);
    }

    @Override
    public String getName() {
        return reference.getName();
    }

    @Override
    public void printLeft(StringWriter writer) {
        reference.printLeft(writer);
    }

    @Override
    public void printRight(StringWriter writer) {
        reference.printRight(writer);
    }

    @Override
    public boolean hasRightPart() {
        return reference.hasRightPart();
    }
}
