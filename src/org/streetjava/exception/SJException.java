package org.streetjava.exception;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;

/**
 * This is custom exception, it can be used for all unchecked exception with
 * predefined error code.
 *
 * @author dungld
 */
public class SJException extends RuntimeException implements SJThrowable {

    SJError errorCode;
    
    public SJException(String message){
        super(message);
    }
    
    public SJException(String message, SJError _errorCode){
        super(message + " ,errorCode:"+_errorCode.getValue());
        errorCode = _errorCode;
    }
    
    public SJException(SJError errorCode) {
        super(errorCode.getValue());
    }

    public SJException(Throwable t, SJError _errorCode) {
        super(_errorCode.getValue(), t);
        errorCode = _errorCode;
    }
    
    public SJException(Throwable t, SJError _errorCode, String message){
        super(message + " ,errorCode:"+_errorCode.getValue(), t);
        errorCode = _errorCode;
    }

    public SJException(Throwable t) {
        super(t);
    }

    

    @Override
    public SJError getErrorCode() {
        return errorCode;
    }
    
    @Override
    public String getErrorMessage() {
        return super.getMessage();
    }

    @Override
    public String getErrorStackTrace() {
        Writer result = new StringWriter();
        this.printStackTrace(new PrintWriter(result));
        return result.toString();
    }
 
    
}
