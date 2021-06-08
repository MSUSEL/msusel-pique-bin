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
package evaluator;

import pique.evaluation.Evaluator;
import pique.model.ModelNode;

public class WeightedAverageOfValuedNodesEvaluator extends Evaluator {

    @Override
    public double evaluate(ModelNode modelNode) {
    	double weightedSum = 0.0;    	
    	int numberNonZeroNodes = 0;    	
    	Double zeroValue = 0.5; //value of node with no findings 0 thresholds
    	
    	// Apply weighted sums
        for (ModelNode child : modelNode.getChildren().values()) {
        	Double[] th = child.getThresholds();
        	if (th!=null) {
	        	if (isZero(th[0],0.005) && isZero(th[1],0.005) && isZero(child.getValue()-zeroValue,0.005)) {
	        		// node has no findings and no thresholds, ignore it
	        	}
	        	else {
	        		numberNonZeroNodes+=1;
	            	weightedSum += child.getValue() * modelNode.getWeight(child.getName());
	
	        	}
        	}
        	else { //we're in the benchmark stage still
        		weightedSum += child.getValue() * modelNode.getWeight(child.getName());
        		numberNonZeroNodes+=1;
        	}
        }
        
        if (numberNonZeroNodes==0) {
        	weightedSum = 0.5;
        }
        else {        	
        	weightedSum = weightedSum*((double)modelNode.getNumChildren()/(double)numberNonZeroNodes); // account for nodes that we ignore
        }
        
        return weightedSum;
    }
    
    public boolean isZero(Double value, Double threshold){
        return value >= -threshold && value <= threshold;
    }
}
