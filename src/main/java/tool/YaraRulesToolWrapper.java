package tool;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONObject;

import pique.analysis.ITool;
import pique.analysis.Tool;
import pique.model.Diagnostic;
import pique.model.Finding;
import utilities.helperFunctions;

/**
 * This class is responsible for that automatic analysis using YARA and an associated set of rules which are packaged into the PIQUE-Bin repository. 
 * This solution is not desirable - perhaps the YARA executable could be automatically downloaded along with the git repository of rules. 
 * One common issue with this tool is the rules themselves being quarantined by anti-virus due to containing the patterns of some common malware.
 * 
 * @author Andrew Johnson
 *
 */
public class YaraRulesToolWrapper extends Tool implements ITool {
	
	private ArrayList<String> ruleCategories;
	private final String ruleCatPrefix = "RULE CATEGORY ";
	
	public YaraRulesToolWrapper(Path toolRoot) {
		super("yara-rules", toolRoot);
		// TODO Auto-generated constructor stub
	}

	@Override
	public Path analyze(Path projectLocation) {
		System.out.println(this.getName() + " Running...");
		
		ruleCategories = new ArrayList<String>();
		Map<String, Diagnostic> diagnostics = helperFunctions.initializeDiagnostics(this.getName());
		for (String diagnosticName :diagnostics.keySet()) {
			String ruleFileName = (diagnosticName.split(" "))[1]; // Diagnostics are "Yara rulename Diagnostic"
			ruleCategories.add(ruleFileName);
		}
		
		File tempResults = new File(System.getProperty("user.dir") + "\\out\\yaraRulesOutput.txt");
		tempResults.delete(); // clear out the last output file. May want to change this to rename rather than delete.
		tempResults.getParentFile().mkdirs();
		try (BufferedWriter writer = Files.newBufferedWriter(tempResults.toPath())) 
		{
		    for (String rule : ruleCategories) {
				String ruleResults = runYaraRules(rule,projectLocation);
				writer.write(ruleCatPrefix+rule+"\n");
				writer.write(ruleResults+"\n");
			}
		} catch (IOException e) {
			System.err.println("error when analyzing with Yara");
			e.printStackTrace();
		}

		return tempResults.toPath();
	}

	@Override
	public Map<String, Diagnostic> parseAnalysis(Path toolResults) {
		System.out.println(this.getName() + " Parsing Analysis...");
		Map<String, Diagnostic> diagnostics = helperFunctions.initializeDiagnostics(this.getName());

		//get contents output file
		String results = "";
		
		try {
			results = helperFunctions.readFileContent(toolResults);

		} catch (IOException e) {
			System.err.println("Error reading results of YaraRulesToolWrapper");
			return diagnostics;
		}
		
		String findingCategory = "";
		int ensureUniqueFinding = 0; //this is used to ensure findings aren't counted as duplicates
		for (String line :  results.split("\\r?\\n")) {
			if (line.contains(ruleCatPrefix)) {
				findingCategory = line.substring(ruleCatPrefix.length());
			}
			else if (line.length()>0) {
				String[] splitLine = line.split(" ");
				String ruleName = splitLine[0];
				Finding finding = new Finding(splitLine[1],ensureUniqueFinding++,0,1); //might need to change. setting arbitrary number for line #
				finding.setName(ruleName);
				Diagnostic relevantDiag = diagnostics.get("Yara "+findingCategory+ " Diagnostic");
				relevantDiag.setChild(finding);
			}
		}
		return diagnostics;
	}

	@Override
	public Path initialize(Path toolRoot) {
		return null;
	}
	
	private String runYaraRules(String ruleName, Path projectLocation) {
		String ruleFileName = this.getToolRoot().toAbsolutePath().toString() + "\\rules\\" + ruleName + "_index.yar";
		// command to call yara on the target file with give rules
		String cmd = String.format("cmd /c %s\\yara64.exe -w %s  %s",
 				this.getToolRoot().toAbsolutePath().toString(), ruleFileName, projectLocation.toAbsolutePath().toString());
		String output = "";
		try {
			output = helperFunctions.getOutputFromProgram(cmd,true);
		} catch (IOException  e) {
			e.printStackTrace();
		}
		return output;
	}
	
}
