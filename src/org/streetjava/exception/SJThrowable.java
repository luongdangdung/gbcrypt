package org.streetjava.exception;

/**
 *
 * @author dungld
 */
public interface SJThrowable {
    String getErrorStackTrace();
    String getErrorMessage();
    SJError getErrorCode();
}
