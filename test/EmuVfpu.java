// Emulates every case_<n> function of the VFPU differential program (vfpu_diff.py) in Ghidra's p-code
// emulator and prints the 128 VFPU registers and CC each one stores, in the format PPSSPP's run prints.
// The program must be the imported vfpudiff.elf. Script args: <outfile>
// The instruction context (VFPU prefixes) comes from disassembling the program first.
// The transcendental pcodeops (vfpuSin, vfpuCos, vfpuExp2, vfpuLog2, vfpuAsin) are evaluated here in double
// precision, so the instructions around them (VROT's lane layout, VNSIN's sign, prefixes) can be compared.
//@category Testing

import java.io.PrintStream;

import java.util.function.DoubleUnaryOperator;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emulate.EmulateExecutionState;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;

public class EmuVfpu extends GhidraScript {

	@Override
	protected void run() throws Exception {
		PrintStream out = new PrintStream(getScriptArgs()[0]);
		Symbol buf = getSymbols("out", null).get(0);
		Address outAddr = buf.getAddress();
		for (int i = 0;; i++) {
			var syms = getSymbols("case_" + i, null);
			if (syms.isEmpty()) {
				break;
			}
			Address start = syms.get(0).getAddress();
			if (getInstructionAt(start) == null) {
				new DisassembleCommand(start, null, true).applyTo(currentProgram, monitor);
			}
			EmulatorHelper emu = new EmulatorHelper(currentProgram);
			unary(emu, "vfpuSin", x -> Math.sin(x * Math.PI / 2));
			unary(emu, "vfpuCos", x -> Math.cos(x * Math.PI / 2));
			unary(emu, "vfpuExp2", x -> Math.pow(2, x));
			unary(emu, "vfpuLog2", x -> Math.log(x) / Math.log(2));
			unary(emu, "vfpuAsin", x -> Math.asin(x) * 2 / Math.PI);
			try {
				Address stop = toAddr(0x100);
				emu.writeRegister("a0", outAddr.getOffset());
				emu.writeRegister("ra", stop.getOffset());
				emu.writeRegister("sp", 0x09fff000L);
				emu.setBreakpoint(stop);
				emu.run(start, null, monitor);
				StringBuilder sb = new StringBuilder();
				if (emu.getEmulateExecutionState() != EmulateExecutionState.BREAKPOINT) {
					out.println("E " + i + " " + emu.getEmulateExecutionState() + " at " +
						emu.getExecutionAddress() + ": " + emu.getLastError());
					continue;
				}
				byte[] b = emu.readMemory(outAddr, 129 * 4);
				for (int j = 0; j < 129; j++) {
					long v = (b[4 * j] & 0xffL) | ((b[4 * j + 1] & 0xffL) << 8) | ((b[4 * j + 2] & 0xffL) << 16) |
						((b[4 * j + 3] & 0xffL) << 24);
					if (j % 16 == 0) {
						sb.append("C " + i + " " + j);
					}
					sb.append(String.format(" %08x", v));
					if (j % 16 == 15 || j == 128) {
						sb.append("\n");
					}
				}
				out.print(sb);
			}
			finally {
				emu.dispose();
			}
		}
		out.close();
	}

	private static void unary(EmulatorHelper emu, String name, DoubleUnaryOperator f) {
		emu.registerCallOtherCallback(name, new BreakCallBack() {
			@Override
			public boolean pcodeCallback(PcodeOpRaw op) {
				MemoryState st = emulate.getMemoryState();
				float x = Float.intBitsToFloat((int) st.getValue(op.getInput(1)));
				float r = (float) f.applyAsDouble(x);
				st.setValue(op.getOutput(), Float.floatToRawIntBits(r) & 0xffffffffL);
				return true;
			}
		});
	}
}
