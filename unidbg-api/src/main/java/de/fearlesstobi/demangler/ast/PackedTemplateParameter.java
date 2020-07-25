package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;
import java.util.List;

public class PackedTemplateParameter extends NodeArray {
    public PackedTemplateParameter(List<BaseNode> nodes) {
        super(nodes, NodeType.PackedTemplateParameter);
    }

    @Override
    public void printLeft(StringWriter writer) {
        for (BaseNode node : nodes) {
            node.printLeft(writer);
        }
    }

    @Override
    public void printRight(StringWriter writer) {
        for (BaseNode node : nodes) {
            node.printLeft(writer);
        }
    }

    @Override
    public boolean hasRightPart() {
        for (BaseNode node : nodes) {
            if (node.hasRightPart()) {
                return true;
            }
        }

        return false;
    }
}