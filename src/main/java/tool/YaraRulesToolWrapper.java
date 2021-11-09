package tool;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.SystemUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
	private static final Logger LOGGER = LoggerFactory.getLogger(YaraRulesToolWrapper.class);
	
	private ArrayList<String> ruleCategories;
	private final String ruleCatPrefix = "RULE CATEGORY ";
	
	public YaraRulesToolWrapper(Path toolRoot) {
		super("yara-rules", toolRoot);
	}

	/**
	 * @param path The path to a binary file for the desired solution of project to
	 *             analyze
	 * @return The path to the analysis results file
	 */
	@Override
	public Path analyze(Path projectLocation) {
		System.out.println(this.getName() + " Running...");
		LOGGER.info(this.getName() + "  Analyzing "+ projectLocation.toString());
		
		ruleCategories = new ArrayList<String>();
		Map<String, Diagnostic> diagnostics = helperFunctions.initializeDiagnostics(this.getName());
		for (String diagnosticName :diagnostics.keySet()) {
			String ruleFileName = (diagnosticName.split(" "))[1]; // Diagnostics are "Yara rulename Diagnostic"
			ruleCategories.add(ruleFileName);
		}
		
		File tempResults = new File(System.getProperty("user.dir") + "\\out\\yaraRulesOutput.txt");
		tempResults.delete(); // clear out the last output file. May want to change this to rename rather than delete.

		//check if file to be analyzed exists, only run analysis if it does.
		if (projectLocation.toFile().exists()) {
			tempResults.getParentFile().mkdirs();
			try (BufferedWriter writer = Files.newBufferedWriter(tempResults.toPath())) 
			{
			    for (String rule : ruleCategories) {
					String ruleResults = runYaraRules(rule,projectLocation);
					if (ruleResults.contains("error scanning")) {
						LOGGER.error("Yara failed to scan a file. Yara output: " + ruleResults);
						throw new IOException(ruleResults);
					}
					writer.write(ruleCatPrefix+rule+"\n");
					writer.write(ruleResults+"\n");
				}
			} catch (IOException e) {
				LOGGER.error("error when analyzing with Yara");
				LOGGER.error(e.toString());
			}

		} 
		else LOGGER.error("Error running YARA. " +projectLocation.toString() + " does not exist.");
		
		return tempResults.toPath();
	}

	/**
	 * parses output of tool from analyze().
	 * 
	 * @param toolResults location of the results, output by analyze() 
	 * @return A Map<String,Diagnostic> with findings from the tool attached. Returns null if tool failed to run.
	 */
	@Override
	public Map<String, Diagnostic> parseAnalysis(Path toolResults) {
		System.out.println(this.getName() + " Parsing Analysis...");
		LOGGER.debug(this.getName() + " Parsing Analysis...");
		
		Map<String, Diagnostic> diagnostics = helperFunctions.initializeDiagnostics(this.getName());

		//get contents output file
		String results = "";
		
		try {
			results = helperFunctions.readFileContent(toolResults);

		} catch (IOException e) {
			LOGGER.error("Error reading results of YaraRulesToolWrapper");
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

	/**
	 * In the current state of things, no initialization is needed for this tool, as the executable and rules are 
	 * included in the repository.
	 */
	@Override
	public Path initialize(Path toolRoot) {
		
		//check if docker image has been built already
		final String[] imageCheck = {"docker", "image", "inspect", this.getName()};
		String check = "";
		try {
			check = helperFunctions.getOutputFromProgram(imageCheck, LOGGER);
		}
		catch (IOException e) {
			LOGGER.error("Error initializing yara.");
			LOGGER.error(e.toString());
			e.printStackTrace();
		}
		
		if (check.contains("Error: No such image")) { //we haven't built the image yet, need to build
			final String cmd[] = {"docker", 
					"build",
					"-t", this.getName(),
					toolRoot.toAbsolutePath().toString()};
			try {
				helperFunctions.getOutputFromProgram(cmd, LOGGER);
			}
			catch (IOException e) {
				LOGGER.error("Error building docker image for yara.");
				LOGGER.error(e.toString());
				e.printStackTrace();
			}
		}
		
		return toolRoot;
	}
	
	private String runYaraRules(String ruleName, Path projectLocation) {
		
		String[] cmd = {"docker", "run", "--rm", 
				"-v", projectLocation.toAbsolutePath().toString()+":/input",
				this.getName(), "-w",
				"rules/"+ruleName + "_index.yar",
				"/input"};
		String output = null;
		try {
			output = helperFunctions.getOutputFromProgram(cmd,LOGGER);
		} catch (IOException  e) {
			LOGGER.error("Failed to run Yara rule " + ruleName + ".");
			LOGGER.error(e.toString());
			e.printStackTrace();
		}
		return output;
	}
	
}
