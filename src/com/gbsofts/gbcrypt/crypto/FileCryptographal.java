package com.gbsofts.gbcrypt.crypto;

import org.streetjava.exception.SJException;

/**
 *
 * @author Luong Dang Dung
 */
public interface FileCryptographal {
    void encryptFile(String inputFile,  String outputFile) throws SJException;
    void decryptFile(String inputFile,  String outputFile) throws SJException;
}
