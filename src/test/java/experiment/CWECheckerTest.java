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
package experiment;

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

public class CWECheckerTest  {
	
	public Path p;

	public boolean analyze(Path projectLocation) {
		p = projectLocation;
		File tempResults = new File(System.getProperty("user.dir") + "/out/CWECheckerOutput.json");
		tempResults.delete(); // clear out the last output. May want to change this to rename rather than delete.
		tempResults.getParentFile().mkdirs();
		String out = "";
		String cmd = String.format("cmd /c docker run --rm -v %s:/input fkiecad/cwe_checker:latest --json --quiet /input",
				projectLocation.toAbsolutePath().toString());
		try {
			out = helperFunctions.getOutputFromProgram(cmd,false);
			System.out.println("cwe_checker on " + projectLocation.toString() + ": "+ out);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return !(out.toLowerCase().contains("error") || out.toLowerCase().contains("report"));

	}

	public String getName() {
		return p.getFileName().toString();
	}
	


	

}
