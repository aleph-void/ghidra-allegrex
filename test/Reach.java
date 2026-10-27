// Decode every slot of a raw image and record which SLEIGH constructors (by source line) appear in
// the decoded parse trees: the "every entry is reachable" check.  Output: one file:line per line.
// Script args: <outfile> <slot-size> [CONTEXTVAR=value ...] [@<file>]
// @<file>: the image is decoded once per line of the file, each line a set of CONTEXTVAR=value settings
// (Ghidra-Rare Allegrex: the VFPU prefix lanes are context-dependent constructors).
//@category Testing

import java.io.PrintStream;
import java.lang.reflect.Field;
import java.util.Map;
import java.util.TreeSet;

import ghidra.app.plugin.processors.sleigh.ConstructState;
import ghidra.app.plugin.processors.sleigh.SleighInstructionPrototype;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import java.math.BigInteger;
import ghidra.program.model.lang.ProcessorContext;
import ghidra.program.model.lang.ProgramProcessorContext;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBufferImpl;

public class Reach extends GhidraScript {

	private final TreeSet<String> seen = new TreeSet<>();

	private void walk(ConstructState st) {
		if (st.getConstructor() != null) {
			seen.add(st.getConstructor().getSourceFile() + ":" + st.getConstructor().getLineno());
		}
		for (int i = 0; i < st.getNumSubStates(); i++) {
			ConstructState sub = st.getSubState(i);
			if (sub != null) {
				walk(sub);
			}
		}
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		int slot = Integer.parseInt(args[1]);
		MemoryBlock block = currentProgram.getMemory().getBlocks()[0];
		Address base = block.getStart();
		long n = block.getSize() / slot;
		Language lang = currentProgram.getLanguage();
		java.util.List<String[]> sets = new java.util.ArrayList<>();
		java.util.List<String> fixed = new java.util.ArrayList<>();
		for (int k = 2; k < args.length; k++) {
			if (args[k].startsWith("@")) {
				for (String line : java.nio.file.Files.readAllLines(java.nio.file.Path.of(args[k].substring(1)))) {
					if (!line.isBlank()) {
						sets.add(line.trim().split("\\s+"));
					}
				}
			}
			else {
				fixed.add(args[k]);
			}
		}
		if (sets.isEmpty()) {
			sets.add(new String[0]);
		}
		Field fld = lang.getClass().getDeclaredField("instructProtoMap");
		fld.setAccessible(true);
		Map<?, ?> protoCache = (Map<?, ?>) fld.get(lang);
		for (String[] set : sets) {
			java.util.List<String> all = new java.util.ArrayList<>(fixed);
			all.addAll(java.util.Arrays.asList(set));
			for (String kv0 : all) {
				String[] kv = kv0.split("=");
				Register r = currentProgram.getRegister(kv[0]);
				currentProgram.getProgramContext().setValue(r, block.getStart(), block.getEnd(),
					new BigInteger(kv[1]));
			}
			for (long i = 0; i < n; i++) {
				Address a = base.add(i * slot);
				try {
					ProcessorContext ctx = new ProgramProcessorContext(currentProgram.getProgramContext(), a);
					MemBuffer buf = new MemoryBufferImpl(currentProgram.getMemory(), a);
					InstructionPrototype p = lang.parse(buf, ctx, false);
					walk(((SleighInstructionPrototype) p).getRootState());
				}
				catch (Exception e) {
					// not an instruction
				}
				protoCache.clear();
			}
		}
		PrintStream out = new PrintStream(args[0]);
		for (String l : seen) {
			out.println(l);
		}
		out.close();
	}
}
