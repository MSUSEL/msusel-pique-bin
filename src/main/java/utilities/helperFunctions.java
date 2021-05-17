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
package utilities;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Collectors;
import java.util.stream.Stream;


public class helperFunctions {
	public static String addDashtoCWEName(String cwe) {
		String dashed = cwe;
		if (!cwe.contains("-")) {
			String cweName = cwe.substring(0, 3);
			String cweNum = cwe.substring(3);
			dashed = cweName + "-" + cweNum;
		}
			return dashed;
	}
	
	public static String[] getCWE(String cve) {
		String cwe = "";
		String temp = (new File("")).toPath().toAbsolutePath().toString();
		String cmd = "python " +temp + "\\src\\main\\java\\utilities\\CVEtoCWE.py " + cve;
		System.out.println(cmd);
		try {
			cwe = getOutputFromProgram(cmd);
		} catch (IOException e) {
			System.err.println("Error running CVEtoCWE.py");
			e.printStackTrace();
		}
		String[] cwes = cwe.split("\n \n");
		return cwes;
	}
	
	 /**
	  * Taken directly from https://stackoverflow.com/questions/13008526/runtime-getruntime-execcmd-hanging
	  * 
	  * @param program - A string as would be passed to Runtime.getRuntime().exec(program)
	  * @return the text output of the command. Includes input and error.
	  * @throws IOException
	  */
	public static String getOutputFromProgram(String program) throws IOException {
	    Process proc = Runtime.getRuntime().exec(program);
	    return Stream.of(proc.getErrorStream(), proc.getInputStream()).parallel().map((InputStream isForOutput) -> {
	        StringBuilder output = new StringBuilder();
	        try (BufferedReader br = new BufferedReader(new InputStreamReader(isForOutput))) {
	            String line;
	            while ((line = br.readLine()) != null) {
	                output.append(line);
	                output.append("\n");
	            }
	        } catch (IOException e) {
	            throw new RuntimeException(e);
	        }
	        return output;
	    }).collect(Collectors.joining());
	}
	
	 /**
	  * 
	  * 
	  * @param filePath - Path of file to be read
	  * @return the text output of the file content.
	  * @throws IOException
	  */
	public static String readFileContent(Path filePath) throws IOException
    {
        StringBuilder contentBuilder = new StringBuilder();
 
        try (Stream<String> stream = Files.lines( filePath, StandardCharsets.UTF_8)) 
        {
            stream.forEach(s -> contentBuilder.append(s).append("\n"));
        }
        catch (IOException e) 
        {
            throw e;
        }
 
        return contentBuilder.toString();
    }

}
