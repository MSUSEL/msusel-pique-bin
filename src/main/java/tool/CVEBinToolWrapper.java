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

import pique.analysis.ITool;
import pique.analysis.Tool;
import pique.model.Diagnostic;
import pique.model.Finding;
import utilities.helperFunctions;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class CVEBinToolWrapper extends Tool implements ITool  {

	//Expected set of CWEs this tool will find instances of. Certainly a better way to do this, but this is fast and 
	//I already had the list written out
	final String[] cweList = {"CWE-22", 
			"CWE-755", 
			"CWE-20", 
			"CWE-119", 
			"CWE-416", 
			"CWE-835", 
			"CWE-273", 
			"CWE-295", 
			"CWE-770", 
			"CWE-772", 
			"CWE-476", 
			"CWE-674", 
			"CWE-Unknown-Other", 
			"CWE-190", 
			"CWE-191", 
			"CWE-59", 
			"CWE-125", 
			"CWE-787", 
			"CWE-502", 
			"CWE-404", 
			"CWE-94", 
			"CWE-120", 
			"CWE-362", 
			"CWE-200", 
			"CWE-617"};
			
	public CVEBinToolWrapper() {
		super("cve-bin-tool", null);
	}

	// Methods
		/**
		 * @param path The path to a binary file for the desired solution of project to
		 *             analyze
		 * @return The path to the analysis results file
		 */
		@Override
		public Path analyze(Path projectLocation) {
			File tempResults = new File(System.getProperty("user.dir") + "/out/cve-bin-tool.json");
			tempResults.delete(); // clear out the last output. May want to change this to rename rather than delete.
			tempResults.getParentFile().mkdirs();

			String cmd = String.format("cmd /c python -m cve_bin_tool.cli -f json %s -o %s",
					projectLocation.toAbsolutePath().toString(), tempResults.toPath().toAbsolutePath().toString());
			
			try {
				System.out.println(helperFunctions.getOutputFromProgram(cmd));

			} catch (IOException  e) {
				e.printStackTrace();
			}

			return tempResults.toPath();
		}

		@Override
		public Map<String, Diagnostic> parseAnalysis(Path toolResults) {
			Map<String, Diagnostic> diagnostics = initializeDiagnostics();

			String results = "";

			try {
				results = Files.readString(toolResults);

			} catch (IOException e) {
				System.err.println("Error when reading tool results, or no results to read.");
				return diagnostics;
			}
			
			ArrayList<String> cveList = new ArrayList<String>();
			ArrayList<Integer> severityList = new ArrayList<Integer>();
			
			try {
				JSONArray jsonResults = new JSONArray(results);
				
				for (int i = 0; i < jsonResults.length(); i++) {
					JSONObject jsonFinding = (JSONObject) jsonResults.get(i); 
					//Need to change this for this tool.
					String findingName = jsonFinding.get("cve_number").toString();
					String findingSeverity = jsonFinding.get("severity").toString();
					severityList.add(this.severityToInt(findingSeverity));
					cveList.add(findingName);
				}
				
				//make a string of all the CWE names to pass to getCWE function
				String findingsString = "";
				for (String x : cveList) {
					findingsString = findingsString +" " + x;
				}
				//get CWE names
				String[] findingNames = helperFunctions.getCWE(findingsString);
				
				for (int i = 0; i < findingNames.length; i++) {
					
					
					Diagnostic diag = diagnostics.get(("CVE-" +findingNames[i]));
					if (diag == null) { 
						//this means that either it is unknown, mapped to a CWE outside of the expected results, or is not assigned a CWE
						//We may want to treat this in another way.
						diag = diagnostics.get("CVE-CWE-Unknown-Other");
					}
					Finding finding = new Finding("",0,0,severityList.get(i));
					finding.setName(cveList.get(i));
					diag.setChild(finding);
				}
				

			} catch (JSONException e) {
				e.printStackTrace();
			}
			
			return diagnostics;
		}

		@Override
		public Path initialize(Path toolRoot) {
			//NOTE: the version of cve-bin-tool that is installed at the time of writing this will error when downloading CVEs
			//However, this will be the command that should be run in the future. If this is failing, get the working
			//version and make this cmd something unimportant. 
			final String cmd = "cmd /c python -m pip install cve-bin-tool"; 
			
			Process p;
			try {
				p = Runtime.getRuntime().exec(cmd);
	            BufferedReader stdInput = new BufferedReader(new InputStreamReader(p.getInputStream()));
				String line;
				
				while ((line = stdInput.readLine()) != null) {
					System.out.println("cve-bin-tool install: " + line);
				}
				stdInput.close();
				p.waitFor();
			} catch (IOException | InterruptedException e) {
				e.printStackTrace();
			}

			return toolRoot;
		}

		// Creates and returns a set of CWE diagnostics without findings
		private Map<String, Diagnostic> initializeDiagnostics() {
			Map<String, Diagnostic> diagnostics = new HashMap<>();

			for (String cwe : cweList) { // TODO: add descriptions for CWEs
				String id = "CVE-" + helperFunctions.addDashtoCWEName(cwe);
				String description = "CVE findings of " + cwe;
				Diagnostic diag = new Diagnostic(id, description, "cve-bin-tool");
				diagnostics.put(id, diag);
			}

			return diagnostics;
		}	
		
		//maps low-critical to numeric values based on the highest value for each range.
		private Integer severityToInt(String severity) {
			Integer severityInt = 1;
			switch(severity.toLowerCase()) {
				case "low": {
					severityInt = 4;
					break;
				}
				case "medium": {
					severityInt = 7;
					break;
				}
				case "high": {
					severityInt = 9;
					break;
				}
				case "critical": {
					severityInt = 10;
					break;
				}
			}
			
			return severityInt;
		}
    @Override
    public String getName() {
        return null;
    }
}
