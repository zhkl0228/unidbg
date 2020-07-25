package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class PackedTemplateParameterExpansion extends ParentNode {
    public PackedTemplateParameterExpansion(BaseNode child) {
        super(NodeType.PackedTemplateParameterExpansion, child);
    }

    @Override
    public void printLeft(StringWriter writer) {
        if (child instanceof PackedTemplateParameter) {
            if (!((PackedTemplateParameter) child).nodes.isEmpty()) {
                child.print(writer);
            }
        } else {
            writer.write("...");
        }
    }
}