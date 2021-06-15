/**
 * MIT License
 * Copyright (c) 2019 Montana State University Software Engineering Labs
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package tool;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import pique.analysis.ITool;
import pique.analysis.Tool;
import pique.model.Diagnostic;
import pique.model.Finding;
import pique.model.ModelNode;
import pique.model.QualityModel;
import pique.model.QualityModelImport;
import utilities.PiqueProperties;
import utilities.helperFunctions;

/**
 * ITool implementation static analysis tool class.
 */

public class CWECheckerToolWrapper extends Tool implements ITool {


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
		tempResults.delete(); // clear out the last output. May want to change this to rename rather than delete.
		tempResults.getParentFile().mkdirs();

		String cmd = String.format("cmd /c docker run --rm -v %s:/input fkiecad/cwe_checker:latest --json --quiet /input > %s",
				projectLocation.toAbsolutePath().toString(), tempResults.toPath().toAbsolutePath().toString());
		try {
			helperFunctions.getOutputFromProgram(cmd);
		} catch (IOException e) {
			e.printStackTrace();
		}

		return tempResults.toPath();
	}

	public Map<String, Diagnostic> parseAnalysis(Path toolResults) {
		Map<String, Diagnostic> diagnostics = helperFunctions.initializeDiagnostics(this.getName());


		String results = "";

		try {
			results = helperFunctions.readFileContent(toolResults);

		} catch (IOException e) {
			System.err.println("Error when reading CWEChecker tool results.");
			e.printStackTrace();
		}
			
		try {
		
			if (results.length() > 0) {
				JSONArray jsonResults = new JSONArray(results);
				for (int i = 0; i < jsonResults.length(); i++) {
					JSONObject jsonFinding = (JSONObject) jsonResults.get(i);
					String findingName = jsonFinding.get("name").toString();
					findingName = helperFunctions.addDashtoCWEName(findingName) + " Weakness Diagnostic";
					Finding finding = new Finding("",i,0,1); //might need to change. Passing 'i' as line number to ensure findings have different names
					Diagnostic relDiag = diagnostics.get(findingName);
					if (relDiag == null) {
						System.err.println("Error finding diagnostic for CWE_Checker finding. Check to ensure all CWEs are in the model. Ignoring this finding.");
					}
					else {
						relDiag.setChild(finding);
					}
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

	

}
