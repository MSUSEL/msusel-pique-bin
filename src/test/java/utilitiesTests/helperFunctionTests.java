package utilitiesTests;

import static org.junit.Assert.fail;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Properties;

import org.junit.Test;

import pique.model.Diagnostic;
import utilities.PiqueTestProperties;
import utilities.helperFunctions;

public class helperFunctionTests {


	@Test
	public void testCVEtoCWE() {
		String cve = "CVE-2018-1010";
		String cwe = helperFunctions.getCWE(cve)[0];
		assert(cwe.equals("CWE-20")); //based off https://nvd.nist.gov/vuln/detail/CVE-2018-1010
	}
	
	@Test
	public void testNonsenseCVEtoCWE() {
		String cve = "notacve";
		String cwe = helperFunctions.getCWE(cve)[0];
		System.out.print(cwe);
		assert(cwe.contains("CVE not found"));
	}
	
	@Test
	public void testCMDLineOutputAndDependencies() {
			String[] cmd1 = {"python", "--version"};
			String out = "";
			try {
				out = helperFunctions.getOutputFromProgram(cmd1,null);
			} catch (IOException e) {
				fail();
			} 
			
			//This is not a clean way of doing this, but it should work. 
			//Verify python version 3.6+
			assert(out.contains("3."));
			assert(!out.contains("1."));
			assert(!out.contains("2."));
			assert(!out.contains("3.1"));
			assert(!out.contains("3.2"));
			assert(!out.contains("3.3"));
			assert(!out.contains("3.4"));
			assert(!out.contains("3.5"));
			
			String[] cmd2 = {"docker", "--version"};
			String out2 = "";
			try {
				out2 = helperFunctions.getOutputFromProgram(cmd2,null);
			} catch (IOException e) {
				fail();
			} 
			assert(out2.contains("Docker"));
	}
	
	@Test
	public void testFileReadingDoesNotError() {
		Properties prop = PiqueTestProperties.getProperties();
		Path p = Paths.get(prop.getProperty("blankqm.filepath"));
		try {
			assert(helperFunctions.readFileContent(p).length()>0);
		} catch (IOException e) {
			fail();
		}
	}
	
	@Test
	public void testFileFormatting() {
		String exampleFile = "/usr/Andrew Johnson/example";
		exampleFile = helperFunctions.formatFileWithSpaces(exampleFile);
		assert(exampleFile.equals("/usr/'Andrew Johnson'/example"));
		
		exampleFile = "\\usr\\Andrew Johnson\\example";
		exampleFile = helperFunctions.formatFileWithSpaces(exampleFile);
		assert(exampleFile.equals("\\usr\\'Andrew Johnson'\\example"));
	}
	
	@Test
	public void testInitializeDiagnostics() {
		//this is hard-coded to look at the main/resources files, so we will use a real tool in this case.
		Map<String,Diagnostic> map = helperFunctions.initializeDiagnostics("not a tool");
		assert(map.values().size()==0);
		
		map = helperFunctions.initializeDiagnostics("yara-rules");
		assert(map.values().size()==9);
		
		
	}
	
}
