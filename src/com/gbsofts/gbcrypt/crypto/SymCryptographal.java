package com.gbsofts.gbcrypt.crypto;

import javax.crypto.SecretKey;
import org.streetjava.exception.SJException;

/**
 *
 * @author dungld
 */
public interface SymCryptographal extends Cryptographal{
   
    byte[] getIV();
    
    void setIV(byte[] iv);
}
