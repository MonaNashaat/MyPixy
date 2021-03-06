package analysis.alias;

import java.util.*;

import conversion.Variable;
import conversion.nodes.CfgNode;

public class DummyAliasAnalysis 
extends AliasAnalysis {
    
    public DummyAliasAnalysis () {
        super();
    }

//  ********************************************************************************
//  GET ****************************************************************************
//  ********************************************************************************

    // returns the set of must-aliases (Variable's) for the given variable 
    // at the given node (folded over all contexts)
    public Set<Variable> getMustAliases(Variable var, CfgNode cfgNode) {
        Set<Variable> retMe = new HashSet<Variable>();
        retMe.add(var);
        return retMe;
    }

    // returns the set of may-aliases (Variable's) for the given variable 
    // at the given node (folded over all contexts)
    @SuppressWarnings({ "rawtypes" })
	public Set getMayAliases(Variable var, CfgNode cfgNode) {
        return Collections.EMPTY_SET;
    }
    
    // returns an arbitrary global must-alias of the given variable at
    // the given node (folded over all contexts); null if there is none
    public Variable getGlobalMustAlias(Variable var, CfgNode cfgNode) {
        return null;
    }
    
    // returns a set of local must-aliases of the given variable at
    // the given node (folded over all contexts); empty set if there
    // are none
    @SuppressWarnings({ "unchecked", "rawtypes" })
	public Set getLocalMustAliases(Variable var, CfgNode cfgNode) {
        return Collections.EMPTY_SET;
    }
    
    // returns a set of global may-aliases of the given variable at
    // the given node (folded over all contexts); empty set if there
    // are none
    @SuppressWarnings({ "unchecked", "rawtypes" })
	public Set getGlobalMayAliases(Variable var, CfgNode cfgNode) {
        return Collections.EMPTY_SET;
    }
    
    // returns a set of local may-aliases of the given variable at
    // the given node (folded over all contexts); empty set if there
    // are none
    @SuppressWarnings({ "unchecked", "rawtypes" })
	public Set getLocalMayAliases(Variable var, CfgNode cfgNode) {
        return Collections.EMPTY_SET;
    }
    
}
