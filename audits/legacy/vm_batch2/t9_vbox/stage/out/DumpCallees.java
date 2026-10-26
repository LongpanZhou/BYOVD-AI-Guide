import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * T9 DumpCallees: decompile the named functions plus reachable callees to a given depth.
 * Usage (headless -postScript): DumpCallees.java <outDir> <depth> <name or addr>[,<name or addr>...]
 * Env var T9_OUT_DIR also accepted.
 */
public class DumpCallees extends GhidraScript {

    static class Edge {
        Function from;
        Function to;
        String kind;
        Edge(Function f, Function t, String k) { from = f; to = t; kind = k; }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) { println("T9-DUMPCALLEES-FAIL: need <outDir> <depth> <targets>"); return; }
        String outDir = args[0];
        int depth = Integer.parseInt(args[1]);
        List<String> roots = new ArrayList<String>();
        for (int i = 2; i < args.length; i++) {
            for (String s : args[i].split(",")) { if (!s.trim().isEmpty()) roots.add(s.trim()); }
        }
        File out = new File(outDir);
        if (!out.exists()) out.mkdirs();
        Program prog = currentProgram;
        DecompInterface dec = new DecompInterface();
        dec.setOptions(new DecompileOptions());
        dec.openProgram(prog);
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();

        // resolve roots
        Set<Function> rootFns = new LinkedHashSet<Function>();
        for (String s : roots) {
            Function f = resolveFn(s);
            if (f == null) { println("T9 no-function-for: " + s); continue; }
            rootFns.add(f);
        }
        println("T9 roots resolved: " + rootFns.size());

        // BFS callee collection
        Set<Function> all = new LinkedHashSet<Function>(rootFns);
        Set<Function> frontier = new LinkedHashSet<Function>(rootFns);
        List<Edge> edges = new ArrayList<Edge>();
        for (int d = 0; d < depth; d++) {
            Set<Function> next = new LinkedHashSet<Function>();
            for (Function f : frontier) {
                for (Function g : callees(f, mon)) {
                    edges.add(new Edge(f, g, "call"));
                    if (all.add(g)) next.add(g);
                }
            }
            frontier = next;
            println("T9 depth " + d + ": frontier=" + frontier.size() + " total=" + all.size());
            if (all.size() > 4000) { println("T9 cap hit (4000 fns)"); break; }
        }

        // decompile all
        int cnt = 0;
        for (Function f : all) {
            cnt++;
            String c;
            try {
                DecompileResults res = dec.decompileFunction(f, 120, mon);
                c = res.decompileCompleted() && res.getDecompiledFunction() != null
                        ? res.getDecompiledFunction().getC()
                        : ("// DECOMPILE-FAILED " + f.getName(true) + " @ " + f.getEntryPoint() + "\n");
            } catch (Exception e) {
                c = "// DECOMPILE-EXC " + f.getName(true) + " @ " + f.getEntryPoint() + " : " + e + "\n";
            }
            String nm = f.getName(true).replaceAll("[^A-Za-z0-9_.@?-]", "_");
            Writer w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(new File(out, f.getEntryPoint().toString() + "_" + nm + ".c")), StandardCharsets.UTF_8));
            w.write(c);
            w.close();
            if ((cnt % 50) == 0) println("T9 decompiled " + cnt + "/" + all.size());
        }
        println("T9-DUMPCALLEES-COMPLETE total=" + cnt + " edges=" + edges.size());
    }

    private Function resolveFn(String s) {
        Function f = null;
        try {
            Address a = getAddressFactory().getAddress(s);
            f = getFunctionAt(a);
            if (f == null) f = getFunctionContaining(a);
        } catch (Exception e) { f = null; }
        if (f != null) return f;
        ghidra.program.model.symbol.SymbolIterator sit = currentProgram.getSymbolTable().getSymbols(s);
        while (sit.hasNext()) {
            ghidra.program.model.symbol.Symbol sym = sit.next();
            if (sym.isExternal()) continue;
            f = getFunctionAt(sym.getAddress());
            if (f == null) f = getFunctionContaining(sym.getAddress());
            if (f != null) return f;
        }
        return null;
    }

    /** Return callees of f: direct calls (references from within f's body) + basic-block flow targets. */
    private List<Function> callees(Function f, TaskMonitor mon) {
        List<Function> out = new ArrayList<Function>();
        AddressSetView body = f.getBody();
        ReferenceIterator it = currentProgram.getReferenceManager().getReferenceIterator(f.getEntryPoint());
        // iterate references from all addresses in body (cheap way: iterate function body instructions' references)
        ghidra.program.model.listing.InstructionIterator iit = currentProgram.getListing().getInstructions(body, true);
        Set<Address> seen = new HashSet<Address>();
        while (iit.hasNext()) {
            ghidra.program.model.listing.Instruction ins = iit.next();
            Reference[] refs = ins.getReferencesFrom();
            for (Reference r : refs) {
                if (!r.getReferenceType().isCall()) continue;
                Address t = r.getToAddress();
                if (!seen.add(t)) continue;
                if (t.isExternalAddress()) {
                    ghidra.program.model.symbol.Symbol s2 = currentProgram.getSymbolTable().getPrimarySymbol(t);
                    Function ef = currentProgram.getFunctionManager().getFunctionAt(t);
                    if (ef == null) {
                        // skip externals (imported libs)
                    } else { out.add(ef); }
                    continue;
                }
                Function g = getFunctionAt(t);
                if (g == null) g = getFunctionContaining(t);
                if (g != null && !g.isThunk()) out.add(g);
            }
            // thunk targets via flows
        }
        // also follow thunk wrappers used by calls (thunk resolves to real fn)
        // fallthrough/basic-block edges: covered by call refs above for our purpose
        return out;
    }
}
