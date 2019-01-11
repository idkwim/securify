package ch.securify.dslpatterns.instructions;

import ch.securify.analysis.DSLAnalysis;
import ch.securify.decompiler.Variable;
import ch.securify.dslpatterns.util.DSLLabel;
import ch.securify.dslpatterns.util.VariableDC;

import java.util.List;
import java.util.Set;

/**
 * The dsl placeholder for the instruction sstore
 */
public class DSLSstore extends AbstractDSLInstruction {

    private Variable offset;
    private Variable var;

    /**
     * @param label the label at which the instrucion is placed
     * @param offset the offset in the stack
     * @param var the variable to store
     */
    public DSLSstore(DSLLabel label, Variable offset, Variable var) {
        super(label);
        this.offset = offset;
        this.var = var;
    }

    @Override
    public DSLSstore getCopy() {
        return new DSLSstore(getLabel(), offset, var);
    }

    /**
     * @return a list of all the variables contained in the instruction
     */
    @Override
    public Set<Variable> getVariables() {
        Set<Variable> varsList = super.getVariables();

        if(VariableDC.isValidVariable(offset))
            varsList.add(offset);
        if(VariableDC.isValidVariable(var))
            varsList.add(var);

        return varsList;
    }

    @Override
    public String getStringRepresentation() {
        StringBuilder sb = new StringBuilder();
        sb.append("sstoreInstr(");
        sb.append(label.getName());
        sb.append(" , ");
        sb.append(offset.getName());
        sb.append(" , ");
        sb.append(var.getName());
        sb.append(")");

        return sb.toString();
    }

    @Override
    public String getDatalogStringRepDC(DSLAnalysis analyzer) {
        StringBuilder sb = new StringBuilder();
        sb.append("sstoreInstr(");
        sb.append(label.getName());
        sb.append(" , _ , _ )");
        return sb.toString();
    }
}

