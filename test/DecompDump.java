// Print the decompiled C of the named functions (or of functions containing a mnemonic).
// Script args: <outfile> <name|@mnemonic> ...
//@category Testing

import java.io.PrintStream;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class DecompDump extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		PrintStream out = new PrintStream(args[0]);
		DecompInterface di = new DecompInterface();
		di.openProgram(currentProgram);
		for (int k = 1; k < args.length; k++) {
			java.util.List<Function> fs = new java.util.ArrayList<>();
			if (args[k].startsWith("@")) {
				for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
					for (Instruction i : currentProgram.getListing().getInstructions(f.getBody(), true)) {
						if (i.getMnemonicString().replace("_", "").startsWith(args[k].substring(1))) {
							fs.add(f);
							break;
						}
					}
					if (fs.size() >= 3) {
						break;
					}
				}
			}
			else if (args[k].startsWith("+0x")) {   // create a function at this address first
				Function f = createFunction(toAddr(Long.parseLong(args[k].substring(3), 16)), null);
				if (f != null) {
					fs.add(f);
				}
			}
			else if (args[k].startsWith("0x")) {
				Function f = getFunctionContaining(toAddr(Long.parseLong(args[k].substring(2), 16)));
				if (f != null) {
					fs.add(f);
				}
				else {
					out.println("// no function contains " + args[k]);
				}
			}
			else {
				fs.addAll(getGlobalFunctions(args[k]));
			}
			for (Function f : fs) {
				DecompileResults r = di.decompileFunction(f, 60, monitor);
				out.println("// ===== " + f.getName() + " @ " + f.getEntryPoint());
				out.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "FAILED " + r.getErrorMessage());
			}
		}
		out.close();
	}
}
