package analysis.exercise2;

import java.util.HashSet;
import java.util.Set;
import analysis.FileState;
import analysis.FileStateFact;
import analysis.ForwardAnalysis;
import analysis.VulnerabilityReporter;
import soot.Body;
import soot.Unit;
import soot.Value;
import soot.jimple.*;
import soot.jimple.internal.*;
import soot.Local;

public class TypeStateAnalysis extends ForwardAnalysis<Set<FileStateFact>> {

	public TypeStateAnalysis(Body body, VulnerabilityReporter reporter) {
		super(body, reporter);
	}

	@Override
	protected void flowThrough(Set<FileStateFact> in, Unit unit, Set<FileStateFact> out) {
		copy(in, out);
		// TODO: Implement your flow function here

		//Checks if each unit is an AssignStmt
		if(unit instanceof AssignStmt){
			// Checks if the rightOp of AssignStmt unit is a NewExpr.
			// This is to keep track of the init state of File Object
			if(((AssignStmt) unit).getRightOp() instanceof NewExpr){
				Set<Value> values = new HashSet<>();
				values.add(((AssignStmt) unit).getLeftOp());
				//Initialize a new FileStateFact object and add file state to out
				out.add(new FileStateFact(values, FileState.Init));

			//If the assignStmt rightOp is an instance of a static field reference,
			// following code add alias to the file object.
			}
			else if(((AssignStmt) unit).getRightOp() instanceof StaticFieldRef || ((AssignStmt) unit).getRightOp() instanceof Local) {
				Value rightOp = ((AssignStmt) unit).getRightOp();
				for(FileStateFact fileStateFact : out) {
					if (fileStateFact.containsAlias(rightOp)) {
						//add alias for file object
						fileStateFact.addAlias(((AssignStmt) unit).getLeftOp());
					}
				}
			}
		}
		//Checks if unit is an instance of an invoke statement, if yes, check for the invoke expression.
		if(unit instanceof InvokeStmt) {

			if (((InvokeStmt) unit).getInvokeExpr() instanceof VirtualInvokeExpr) {
				if (((InvokeStmt) unit).containsInvokeExpr()) {
					//check if the invoke statement is a file open invoke method
					if (((InvokeStmt) unit).getInvokeExpr().getMethod().getName().equals("open")) {
						for (FileStateFact fileStateFact : out) {
							//if the current state of the file object is init or closed,
							// open is a valid sequence, thus we update the state of the file object
							if (!fileStateFact.isOpened()) {
								fileStateFact.updateState(FileState.Open);
							}
						}
					//check if the invoke statment is a file close function
					}else if (((InvokeStmt) unit).getInvokeExpr().getMethod().getName().equals("close")) {
						//to get the file object which is being referenced.
						Value leftOp = ((JVirtualInvokeExpr) ((InvokeStmt) unit).getInvokeExpr()).getBase();
						for (FileStateFact fileStateFact : out) {
							//if  current state of the file object is not closed, update state of file object
							if (fileStateFact.containsAlias(leftOp) && !fileStateFact.getState().equals(FileState.Close)) {
								fileStateFact.updateState(FileState.Close);
							}
						}
					}

				}
			}
		}
		//This is to check the state of file object at return, and report vulnerabilities if any
		if(unit instanceof ReturnVoidStmt){
			for(FileStateFact fileStateFact : out){
				//if any file object is not closed at return,then this is an invalid sequence, thus report a vulnerability
				if(!fileStateFact.getState().equals(FileState.Close)) {
					this.reporter.reportVulnerability(this.method.getSignature(), unit);
				}
			}
		}
		prettyPrint(in, unit, out);
	}

	@Override
	protected Set<FileStateFact> newInitialFlow() {
		// TODO: Implement your initialization here.
		// The following line may be just a place holder, check for yourself if
		// it needs some adjustments.
		return new HashSet<>();
	}

	@Override
	protected void copy(Set<FileStateFact> source, Set<FileStateFact> dest) {
		// TODO: Implement the copy function here.
		//to copy FileStateFact objects from source set to dest set by looping through the source.
		for (FileStateFact fileStateFact : source) {
			dest.add(fileStateFact.copy());
		}
	}

	@Override
	protected void merge(Set<FileStateFact> in1, Set<FileStateFact> in2, Set<FileStateFact> out) {
		// TODO: Implement the merge function here.
	}

}
