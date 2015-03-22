package com.gbsofts.gbcrypt.crypto;

/**
 * This file produces appropriate implementation of DirectoryCryptographal
 * 
 * @author Luong Dang Dung
 */
public class DirectoryCryptographalFactory {
    
    private final static DirectoryCryptographalFactory instance = new DirectoryCryptographalFactory();
            
    public static DirectoryCryptographalFactory getInstance(){
        return instance;
    }        
            
    public DirectoryCryptographal create(int length, String publicKey, String privateKey, boolean isReplace){
        return new DirectoryCryptography(FileCryptographalFactory.getInstace().create(length,publicKey,privateKey,isReplace));
    }
}
