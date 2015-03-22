package com.gbsofts.gbcrypt.crypto;

import org.streetjava.exception.SJException;

/**
 *
 * @author Luong Dang Dung
 */
public interface Cryptographal {
    byte[] encrypt(byte[] input) throws SJException;
    byte[] decrypt(byte[] input) throws SJException;
}
