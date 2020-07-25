package de.fearlesstobi.demangler.ast;

abstract class ParentNode extends BaseNode {
    final BaseNode child;

    ParentNode(NodeType type, BaseNode child) {
        super(type);
        this.child = child;
    }

    @Override
    public String getName() {
        return child.getName();
    }
}