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

import pique.evaluation.IUtilityFunction;

public class BinaryUtility implements IUtilityFunction {


    @Override
    public double utilityFunction(double v, Double[] doubles, boolean pos) {
    	if (doubles == null) return 0.0;
    	
    	//if upper and lower threshold are equal, return the value or 0.5 if no findings 
    	//(0.5 implies it is equivalent to other projects in the benchmark repository)
    	if (doubles[1]-doubles[0]==0.0) {
    		if (v==0.0) {
    			return 0.5;
    		}
    		if(pos) return v;
    		return -v;
    	}
    	return linearInterpolationTwoPoints(v,doubles, pos);

    	
    }

    private double linearInterpolationTwoPoints(double inValue, Double[] thresholds, boolean pos) {
    	//reverse the slope if measure is negative
    	int upper = 1;
    	int lower = 0;
    	if (!pos) {
    		upper = 0;
    		lower = 1;
    	}
    	
        return (inValue - thresholds[lower]) * (1.0 / (thresholds[upper] - thresholds[lower]));
    }

}
