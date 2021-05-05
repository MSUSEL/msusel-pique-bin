package utilities;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
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

}
