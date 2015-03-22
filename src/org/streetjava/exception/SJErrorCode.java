package org.streetjava.exception;

/**
 *
 * @author dungld
 */
public enum SJErrorCode implements SJError{
    TECHNICAL,
    SHA1_CHECKSUM_NOT_EQUAL,
    HEADER_SIGN_INCORRECT
    ;

    @Override
    public String getValue() {
        return "ERROR_"+this.toString();
    }

    @Override
    public String getCode() {
        return this.toString();
    }
    
}
