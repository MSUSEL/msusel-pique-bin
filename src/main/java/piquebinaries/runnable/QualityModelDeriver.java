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
package piquebinaries.runnable;

import java.math.BigDecimal;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pique.analysis.ITool;
import pique.model.QualityModel;
import pique.model.QualityModelExport;
import pique.model.QualityModelImport;
import pique.runnable.AQualityModelDeriver;
import pique.utility.PiqueProperties;
import tool.CVEBinToolWrapper;
import tool.CWECheckerToolWrapper;
import tool.YaraRulesToolWrapper;

/**
 * Utility driver class responsible for running the calibration module's procedure.
 * This uses a benchmark repository, quality model description, directory of comparison matrices, and
 * instances of language-specific analysis tools as input to perform a 3 step process of
 * (1) Derive thresholds
 * (2) Elicitate weights
 * (3) Apply these results to the quality model to generate a fully derived quality model
 */
public class QualityModelDeriver extends AQualityModelDeriver {
	private static final Logger LOGGER = LoggerFactory.getLogger(QualityModelDeriver.class);

    public static void main(String[] args){
        new QualityModelDeriver();
    }

    public QualityModelDeriver(){
        init();
    }

    private void init(){
    	LOGGER.info("Beginning deriver");
    	
        Properties prop = PiqueProperties.getProperties();

        Path blankqmFilePath = Paths.get(prop.getProperty("blankqm.filepath"));
        Path derivedModelFilePath = Paths.get(prop.getProperty("results.directory"));

        // Initialize objects
        String projectRootFlag = "";
        Path benchmarkRepo = Paths.get(prop.getProperty("benchmark.repo"));

        Path resources = Paths.get(prop.getProperty("blankqm.filepath")).getParent();
        
        ITool cvebinToolWrapper = new CVEBinToolWrapper();
        ITool cweCheckerWrapper = new CWECheckerToolWrapper();
        ITool yaraRulesWrapper = new YaraRulesToolWrapper(resources);
        Set<ITool> tools = Stream.of(cvebinToolWrapper,cweCheckerWrapper, yaraRulesWrapper).collect(Collectors.toSet());
        QualityModelImport qmImport = new QualityModelImport(blankqmFilePath);
        QualityModel qmDescription = qmImport.importQualityModel();
        qmDescription = pique.utility.TreeTrimmingUtility.trimQualityModelTree(qmDescription);
        

        QualityModel derivedQualityModel = deriveModel(qmDescription, tools, benchmarkRepo, projectRootFlag);

        Path jsonOutput = new QualityModelExport(derivedQualityModel)
        		.exportToJson(derivedQualityModel
        				.getName(), derivedModelFilePath);
  
        LOGGER.info("Quality Model derivation finished. You can find the file at " + jsonOutput.toAbsolutePath().toString());
    }


    
}
