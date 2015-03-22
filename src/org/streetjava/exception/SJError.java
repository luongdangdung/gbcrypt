package org.streetjava.exception;

/**
 * SJError describes getValue method, it return String contain the code which
 will be translated by system
 *
 * @author dungld
 */
public interface SJError {
    
    /**
     *
     * @return the code for defining language
     */
    String getCode();
    
    /**
     * @return the value of code predefined
     */
    String getValue();
}
