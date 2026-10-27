// Calling-convention check (upstream issue #2): apply C prototypes to a function and print where the
// compiler spec places each parameter and the return value. The program is any raw Allegrex image; the
// function is created at its first address.
// Script args: <outfile> <prototype> [<prototype> ...]
//@category Testing

import java.io.PrintStream;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;

public class CspecCheck extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		PrintStream out = new PrintStream(args[0]);
		Function f = createFunction(currentProgram.getMinAddress(), "f");
		for (int k = 1; k < args.length; k++) {
			FunctionDefinitionDataType def =
				CParserUtils.parseSignature((ghidra.app.services.DataTypeManagerService) null, currentProgram, args[k], true);
			java.util.List<Parameter> ps = new java.util.ArrayList<>();
			for (var p : def.getArguments()) {
				ps.add(new ParameterImpl(p.getName(), p.getDataType(), currentProgram));
			}
			f.updateFunction(null, new ReturnParameterImpl(def.getReturnType(), currentProgram),
				FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
				ps.toArray(new Parameter[0]));
			StringBuilder sb = new StringBuilder(args[k] + " =>");
			sb.append(" return ").append(f.getReturn().getVariableStorage());
			for (Parameter p : f.getParameters()) {
				sb.append("; ").append(p.getName()).append(' ').append(p.getVariableStorage());
			}
			out.println(sb);
		}
		out.close();
	}
}
