package analysis.dep.tf;

import java.util.*;

import analysis.LatticeElement;
import analysis.TransferFunction;
import analysis.dep.DepLatticeElement;
import conversion.TacPlace;
import conversion.Variable;
import conversion.nodes.CfgNode;

// transfer function for unary assignment nodes
public class DepTfAssignUnary
extends TransferFunction {

    private Variable left;
    private TacPlace right;
    private int op;
    private Set mustAliases;
    private Set mayAliases;
    private CfgNode cfgNode;
    
// *********************************************************************************    
// CONSTRUCTORS ********************************************************************
// *********************************************************************************     

    // mustAliases, mayAliases: of setMe
    public DepTfAssignUnary(TacPlace left, TacPlace right, int op, 
            Set mustAliases, Set mayAliases, CfgNode cfgNode) {
        
        this.left = (Variable) left;  // must be a variable
        this.right = right;
        this.op = op;
        this.mustAliases = mustAliases;
        this.mayAliases = mayAliases;
        this.cfgNode = cfgNode;
    }

// *********************************************************************************    
// OTHER ***************************************************************************
// *********************************************************************************  

    public LatticeElement transfer(LatticeElement inX) {

        DepLatticeElement in = (DepLatticeElement) inX;
        DepLatticeElement out = new DepLatticeElement(in);

        // let the lattice element handle the details
        out.assign(left, mustAliases, mayAliases, cfgNode);
        
        return out;
    }
}
