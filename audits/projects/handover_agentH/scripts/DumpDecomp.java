import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.HashSet;
import java.util.Set;

public class DumpDecomp extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outDir = args[0];
        new File(outDir).mkdirs();
        String progName = currentProgram.getName();
        File out = new File(outDir, progName + ".decomp.txt");
        PrintWriter w = new PrintWriter(new BufferedWriter(new FileWriter(out), 1 << 20));
        try {
            w.println("##SEGMENTS");
            for (MemoryBlock blk : currentProgram.getMemory().getBlocks()) {
                w.println(blk.getName() + " " + blk.getStart() + " - " + blk.getEnd());
            }
            w.println("##EXTERNALS");
            SymbolTable st = currentProgram.getSymbolTable();
            Set<String> seen = new HashSet<String>();
            for (Symbol sym : st.getAllSymbols(true)) {
                if (sym.isExternal()) {
                    String nm = sym.getName();
                    if (seen.add(nm)) {
                        w.println(nm + " @ " + sym.getAddress());
                    }
                }
            }
            w.println("##FUNCTIONS");
            DecompInterface di = new DecompInterface();
            di.setOptions(new DecompileOptions());
            di.openProgram(currentProgram);
            ConsoleTaskMonitor mon = new ConsoleTaskMonitor();
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            int cnt = 0;
            while (it.hasNext()) {
                Function fn = it.next();
                cnt++;
                try {
                    DecompileResults res = di.decompileFunction(fn, 90, mon);
                    if (res.decompileCompleted() && res.getDecompiledFunction() != null) {
                        w.println("//==== " + fn.getName() + " @ " + fn.getEntryPoint() + " ====");
                        w.println(res.getDecompiledFunction().getC());
                        w.println();
                    } else {
                        w.println("//==== " + fn.getName() + " @ " + fn.getEntryPoint() + " : DECOMP_FAILED ====");
                        w.println();
                    }
                } catch (Exception e) {
                    w.println("//==== " + fn.getName() + " @ " + fn.getEntryPoint() + " : EXC " + e + " ====");
                    w.println();
                }
            }
            w.println("##TOTAL_FUNCTIONS " + cnt);
        } finally {
            w.close();
        }
        println("DECOMP DONE " + progName + " -> " + out);
    }
}
