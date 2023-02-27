package analysis.exercise1;

import analysis.AbstractAnalysis;
import analysis.VulnerabilityReporter;
import soot.Body;
import soot.Unit;
import soot.jimple.AssignStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.StringConstant;

public class MisuseAnalysis extends AbstractAnalysis{
	public MisuseAnalysis(Body body, VulnerabilityReporter reporter) {
		super(body, reporter);
	}
	
	@Override
	protected void flowThrough(Unit unit) {
		// TODO: Implement your analysis here.
		//Checks whether the statement is an AssignStmt or not
		if(unit instanceof AssignStmt){
			//If true, then take the unit to assignStmt
			AssignStmt assignStmt = (AssignStmt) unit;
			//Checks whether assignStmt is an InvokeExpr or not
			if(assignStmt.containsInvokeExpr()){
				//If true take the rhs of the assignStmt to invokeExpr
				InvokeExpr invokeExpr = (InvokeExpr) assignStmt.getRightOp();
				//Checks whether the declaring class of invokeExpr is Cipher, and
				//Checks whether the method name is getInstance and
				//Checks whether the first argument is AES/GCM/PKCS5Padding.
				//If first 2 condition is true and 3rd is false.
				if(invokeExpr.getMethodRef().getDeclaringClass().getShortName().equals("Cipher") &&
						invokeExpr.getMethod().getName().equals("getInstance") &&
						!invokeExpr.getArgs().get(0).equals(StringConstant.v("AES/GCM/PKCS5Padding"))) {
						//report vulnerability if condition is true
						this.reporter.reportVulnerability(this.method.getSignature(), unit);
				}
			}
		}
	}
}
