package tool;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import helper.helperFunctions;
import pique.analysis.ITool;
import pique.analysis.Tool;
import pique.model.Diagnostic;
import pique.model.Finding;

/**
 * ITool implementation static analysis tool class.
 */

public class CWECheckerToolWrapper extends Tool implements ITool {

	final String cweList[] = { "CWE190", "CWE215", "CWE243", "CWE332", "CWE367", "CWE415", "CWE416", "CWE426", "CWE467",
			"CWE476", "CWE560", "CWE676", "CWE782" };

	public CWECheckerToolWrapper() {
		super("cwe_checker", null);
	}

	// Methods
	/**
	 * @param path The path to a binary file for the desired solution of project to
	 *             analyze
	 * @return The path to the analysis results file
	 */

	public Path analyze(Path projectLocation) {

		File tempResults = new File(System.getProperty("user.dir") + "/out/CWECheckerOutput.json");
		tempResults.getParentFile().mkdirs();

		String cmd = String.format("cmd /c docker run --rm -v %s:/input fkiecad/cwe_checker:latest --json --quiet /input > %s",
				projectLocation.toAbsolutePath().toString(), tempResults.toPath().toAbsolutePath().toString());

		Process p;
		try {
			p = Runtime.getRuntime().exec(cmd);
			BufferedReader stdInput = new BufferedReader(new InputStreamReader(p.getInputStream()));
			String line;

			while ((line = stdInput.readLine()) != null) {
				System.out.println("cwe_checker: " + line);
			}
			p.waitFor();
		} catch (IOException | InterruptedException e) {
			e.printStackTrace();
		}

		return tempResults.toPath();
	}

	public Map<String, Diagnostic> parseAnalysis(Path toolResults) {
		Map<String, Diagnostic> diagnostics = initializeDiagnostics();


		String results = "";

		try {
			results = Files.readString(toolResults);

		} catch (IOException e) {
			System.err.println("Error when reading tool results.");
			e.printStackTrace();
		}
			
		try {
		
			if (results.length() > 0) {
				JSONArray jsonResults = new JSONArray(results);
				for (int i = 0; i < jsonResults.length(); i++) {
					JSONObject jsonFinding = (JSONObject) jsonResults.get(i);
					String findingName = jsonFinding.get("name").toString();
					Finding finding = new Finding();
					diagnostics.get(findingName).setChild(finding);
				}
			}
			else {
				System.err.println("No findings from cwe_checker");
			}
			

		} catch (JSONException e) {
			e.printStackTrace();
		}

		return diagnostics;
	}

	public Path initialize(Path toolRoot) {
		final String cmd = "cmd /c docker pull fkiecad/cwe_checker:latest\"";
		Process p;
		try {
			p = Runtime.getRuntime().exec(cmd);
			BufferedReader stdInput = new BufferedReader(new InputStreamReader(p.getInputStream()));
			String line;

			while ((line = stdInput.readLine()) != null) {
				System.out.println("cwe_checker install: " + line);
			}
			p.waitFor();
		} catch (IOException | InterruptedException e) {
			e.printStackTrace();
		}

		return toolRoot;
	}

	// Creates and returns a set of CWE diagnostics without findings
	private Map<String, Diagnostic> initializeDiagnostics() {
		Map<String, Diagnostic> diagnostics = new HashMap<>();

		for (String cwe : cweList) {
			String id = "CWE-" + helperFunctions.addDashtoCWEName(cwe);
			String description = "A weakness of type " + id;
			Diagnostic diag = new Diagnostic(id, description, "cwe_checker");
			diagnostics.put(cwe, diag);
		}

		return diagnostics;
	}

}
