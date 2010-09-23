package it.unisa.dia.jzks.gui.utils;

import it.unisa.dia.jzks.merkleTree.InvalidQParameterException;

import java.io.Serializable;

import javax.swing.SpinnerNumberModel;


public class SpinnerNumberModelPow2 extends SpinnerNumberModel implements Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private Integer value;
	private Integer minimum;
	private Integer maximum;
	
	
	public SpinnerNumberModelPow2(){
		value=0;
		minimum=2;
		maximum=Integer.valueOf((int)Math.pow(2.0, 30.0));
	}
	
	public Integer 	getMaximum(){
		return maximum;
	}
    
	public Integer 	getMinimum(){
		return minimum;
	}
	           
	public Integer 	getNextValue(){
		this.value=value*2;
		return value;
	}
	           
           
	public Integer 	getPreviousValue(){
		try{
			double i=Math.log(value)/Math.log(2);
			i--;
			if (i==0)
				i=1;
			value=Integer.valueOf((int)Math.pow(2.0, i));
		}catch (Exception e) {
			e.printStackTrace();
		}
		return value;
	}
	           
       
	public Integer 	getValue(){
		return value;
	}          
          
	public void setValue(Integer newValue) throws InvalidQParameterException{
		double i=Math.log(newValue)/Math.log(2);
		if (i%(int)i==0.0)
			this.value=newValue;
		else
			throw new InvalidQParameterException("The parameter q must be > 1 and power of 2");
	}	
}