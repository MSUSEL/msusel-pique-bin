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

import java.math.BigDecimal;

import pique.evaluation.IUtilityFunction;
import pique.utility.BigDecimalWithContext;

public class BinaryUtility implements IUtilityFunction {


    @Override
    public BigDecimal utilityFunction(BigDecimal v, BigDecimal[] bigDecimals, boolean pos) {
    	if (bigDecimals == null) return new BigDecimalWithContext(0.0);
    	
    	//if upper and lower threshold are equal, return the value or 0.5 if no findings 
    	//(0.5 implies it is equivalent to other projects in the benchmark repository)
    	if (bigDecimals[1].subtract(bigDecimals[0]).compareTo(new BigDecimalWithContext(0.0))==0) {
    		if (v.compareTo(new BigDecimalWithContext(0.0))==0) {
    			return new BigDecimalWithContext(0.5);
    		}
    		if(pos) return v;
    		return v.negate();
    	}
    	return linearInterpolationTwoPoints(v,bigDecimals, pos);

    	
    }

    private BigDecimal linearInterpolationTwoPoints(BigDecimal inValue, BigDecimal[] thresholds, boolean pos) {
    	//reverse the slope if measure is negative
    	int upper = 1;
    	int lower = 0;
    	if (!pos) {
    		upper = 0;
    		lower = 1;
    	}
    	
        return (inValue.subtract(thresholds[lower])).divide((thresholds[upper].subtract(thresholds[lower])),BigDecimalWithContext.getMC());
    }

}
