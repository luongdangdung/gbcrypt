package com.gbsofts.gbcrypt.crypto;

import org.streetjava.exception.SJException;

/**
 *
 * @author dungld
 */
public interface DirectoryCryptographal {
    void encryptDir(String inputDir, String outputDir) throws SJException;
    void decryptDir(String inputDir, String outputDir) throws SJException;
}
