package com.gbsofts.gbcrypt.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;
import org.streetjava.exception.SJException;

/**
 *  This interface describes template actions of Asymmetric Crypto
 * 
 * @author Luong Dang Dung
 */
public interface AsymCryptographal extends Cryptographal{
    
    /**
     * Fist element of result is Public Key
     * Second element of result is Private Key
     * 
     * @return list of keys
     * @throws SJException
     */
    Object[] generateKeyPair() throws SJException;
    
    /**
     * get public key from byte array, use for loading public key from file
     * @param input
     * @return
     * @throws SJException
     */
    PublicKey getPublicKey(byte[] input) throws SJException;
    
    /**
     * get private key from byte arrya, use for loading private key from file
     * @param input
     * @return
     * @throws SJException
     */
    PrivateKey getPrivateKey(byte[] input) throws SJException;
    
    /**
     * Save generated keys to specified paths
     * 
     * @param publicKeyPath
     * @param privateKeyPath
     * @throws SJException
     */
    void saveKeys(String publicKeyPath, String privateKeyPath) throws SJException;
    
}
