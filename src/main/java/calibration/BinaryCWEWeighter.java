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
package calibration;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.lang3.ArrayUtils;

import pique.calibration.IWeighter;
import pique.calibration.WeightResult;
import pique.model.ModelNode;
import pique.model.QualityModel;

/** 
 * @author Andrew Johnson
 *
 * This class should weight based off of pairwise comparisons for the quality aspect level but utilize manual weights for 
 * product factors to the quality aspect level. This allows stakeholder
 * interest to be represented but reduces the extreme amount of comparisons.
 */
public class BinaryCWEWeighter implements IWeighter{
	private String[] qaNames;
	private String[] pfNames;
	private double[][] manWeights;
	private double[][] comparisonMat;
	private int numQA;
	private int numPF;
	

	@Override
	public Set<WeightResult> elicitateWeights(QualityModel qualityModel, Path... externalInput) {
		numQA = qualityModel.getQualityAspects().size();
		numPF = qualityModel.getProductFactors().size();
		qaNames = new String[numQA];
		pfNames = new String[numPF];
		manWeights = new double[numPF][numQA];
		comparisonMat = new double[numQA][numQA];
		
		List<String> modelQANames = new ArrayList<String>();
		List<String> modelPFNames = new ArrayList<String>();
		qualityModel.getQualityAspects().values().stream().forEach(s -> modelQANames.add(s.getName()));
		qualityModel.getProductFactors().values().stream().forEach(s -> modelPFNames.add(s.getName()));
		
		
		
		
		String pathToCsv = "src/main/resources/comparisons.csv";
		String pfPrefix = "Category ";
		BufferedReader csvReader;
		int lineCount = 0;
		try {
			csvReader = new BufferedReader(new FileReader(pathToCsv));
		
			String row;
			while (( row = csvReader.readLine()) != null) {
				String[] data = row.split(",");
				if (lineCount == 0) {
					for (int i = 1; i < data.length; i++) {
						qaNames[i-1] = data[i];
					}
					lineCount++;
				}
				else if (modelQANames.contains(data[0]) || modelPFNames.contains(getCategoryName(data[0],pfPrefix))) {
					if (lineCount < numQA+1) { //tqi weights, fill values for ahpMat
						for (int i = 1; i < data.length; i++) {
							comparisonMat[lineCount-1][i-1] = Double.parseDouble(data[i].trim());
						}
					}
					else { //QA weights, fill values for manWeights
						//parse out the integer for the CWE number and add appropriate prefix, unless it is not numbered
						pfNames[lineCount-numQA-1] = getCategoryName(data[0],pfPrefix);
						for (int i = 1; i < data.length; i++) {							
							manWeights[lineCount-numQA-1][i-1] = Double.parseDouble(data[i].trim());
						}
					}
				    lineCount++;
				}
			}
			csvReader.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		Set<WeightResult> weights = new HashSet<>();

		//there is certainly a better way to implement this next part
		
		//set the weights as a simple 1/number of children for each edge
		averageWeights(qualityModel.getMeasures().values(),weights);
		averageWeights(qualityModel.getDiagnostics().values(),weights);
		averageWeights(qualityModel.getProductFactors().values(),weights);


		//set the weights for edges going into quality aspects based on manual weighting
		manualWeights(qualityModel.getQualityAspects().values(),weights);
		
		//set the weights for edges going into tqi based on ahp
		ahpWeights(qualityModel.getTqi(), weights);
		
        return weights;
	}
	
	




	@Override
	public String getName() {
        return this.getClass().getCanonicalName();
	}

	private String getCategoryName(String name, String pfPrefix) {
		if (name.replaceAll("[\\D]", "").length() == 0) {
			//no numbers in the name
			return pfPrefix +name;
		}
		else {
			return pfPrefix + "CWE-" + Integer.toString(Integer.parseInt(name.replaceAll("[\\D]", "")));							
		}
	}
	
	private void averageWeights(Collection<ModelNode> values, Set<WeightResult> weights) {
		values.forEach(node -> {
			WeightResult weightResult = new WeightResult(node.getName());
			node.getChildren().values().forEach(child -> weightResult.setWeight(child.getName(), averageWeight(node)));
			weights.add(weightResult);
		});
	}

	private double averageWeight(ModelNode currentNode) {
        return 1.0 / (double)currentNode.getChildren().size();
    }
	
	//weight based on AHP
	private void ahpWeights(ModelNode tqi, Set<WeightResult> weights) {
		double[] ahpVec = new double[numQA];
		//normalize by column sums
		double[][] norm = normalizeByColSum(comparisonMat);
		//get the row means
		for (int i= 0; i < numQA; i++) {
			ahpVec[i] = rowMean(norm,i);
		}
		WeightResult weightResult = new WeightResult(tqi.getName());	
		tqi.getChildren().values().forEach(child -> 
			weightResult.setWeight(child.getName(), ahpVec[ArrayUtils.indexOf(qaNames, child.getName())]));
        weights.add(weightResult);
	}
	
	private double[][] normalizeByColSum(double[][] mat) {
		double[][] norm = new double[mat.length][mat[0].length];
		for (int i= 0; i < mat.length; i++) {
			for (int j= 0; j < mat[0].length; j++) {
				norm[i][j] = (mat[i][j]/colSum(mat,j));
			}	
		}
		return norm;
	}
	
	private double[][] normalizeByRowSum(double[][] mat) {
		double[][] norm = new double[mat.length][mat[0].length];
		for (int i= 0; i < mat.length; i++) {
			for (int j= 0; j < mat[0].length; j++) {
				norm[i][j] = (mat[i][j]/rowSum(mat,i));
			}	
		}
		return norm;
	}

	private double rowMean(double[][] mat, int row) {
		int cols = mat[0].length;  
		return (rowSum(mat,row))/((double)cols);
	}
	
	private double rowSum(double[][] mat, int row) {
		int cols = mat[0].length;  
		 double sumRow = 0;  
        for(int j = 0; j < cols; j++){  
          sumRow = sumRow + mat[row][j];  
        }
        return sumRow;
	}
	
	private double colSum(double[][] mat, int col) {
		 int rows = mat.length;  
		 double sumCol = 0;  
         for(int j = 0; j < rows; j++){  
           sumCol = sumCol + mat[j][col];  
         } 
		return (sumCol);
	}
	
	//weights based on manual entry
	private void manualWeights(Collection<ModelNode> nodes, Set<WeightResult> weights) {
		double[][] normMat = normalizeByColSum(manWeights);
		

		for (ModelNode node : nodes) {
			WeightResult weightResult = new WeightResult(node.getName());	
			node.getChildren().values().forEach(child -> 
				weightResult.setWeight(child.getName(), normMat[ArrayUtils.indexOf(pfNames, child.getName())][ArrayUtils.indexOf(qaNames, node.getName())]));
	        weights.add(weightResult);
		}
	}
	
}
