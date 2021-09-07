package experiment;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import pique.analysis.ITool;
import pique.model.Diagnostic;
import tool.CVEBinToolWrapper;
import tool.CWECheckerToolWrapper;
import tool.YaraRulesToolWrapper;
import utilities.PiqueProperties;

public class ToolRunner {

	public static void main(String[] args) {
		Properties prop = PiqueProperties.getProperties();

        // Initialize objects
        Path benchmarkRepo = Paths.get(prop.getProperty("benchmark.repo"));
        benchmarkRepo = Paths.get(benchmarkRepo.toFile().getParent()+"/benchmark/");

        Path resources = Paths.get(prop.getProperty("blankqm.filepath")).getParent();
        
        ITool yaraRulesWrapper = new YaraRulesToolWrapper(resources);
        Set<ITool> tools = Stream.of(yaraRulesWrapper).collect(Collectors.toSet());

        File[] files = benchmarkRepo.toFile().listFiles();
        Path outputDest = Paths.get(prop.getProperty("results.directory"));
		File outputFile = Paths.get(outputDest.toString() + "/YaraOutput.txt").toFile();
		try {
			outputFile.createNewFile();
		} catch (IOException e) {
			e.printStackTrace();
		}

		for (File x : files) {
			System.out.println(x.getName());
			appendln(outputFile,x.getName() + ",");
			tools.forEach(tool -> {
				Map<String,Diagnostic> out = tool.parseAnalysis(tool.analyze(x.toPath()));
				appendln(outputFile, tool.getName() + " " + findingCount(out) + ",");
			});
        }
	       
	}
	
	private static int findingCount(Map<String, Diagnostic> out) {
		int count = 0;
		for (Diagnostic d : out.values()) {
			count+=d.getNumChildren();
		}
		return count;
	}

	public static void appendln(File f, String str) {
		try (FileWriter fw = new FileWriter(f.getAbsolutePath(),true)){
			fw.write(str + "\n");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
}
