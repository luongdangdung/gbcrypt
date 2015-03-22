package com.gbsofts.gbcrypt.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.streetjava.exception.SJException;

/**
 * This file implements Blowsfish encryption
 * 
 * @author Luong Dang Dung
 */
public class BlowfishCryptography implements SymCryptographal {
    
    private final byte[] secretKeyBytes;
    
    byte[] iv;
    
    public BlowfishCryptography(byte[] _secretKeyBytes){
        secretKeyBytes = _secretKeyBytes;
    }

    @Override
    public byte[] encrypt(byte[] input) throws SJException {
        byte[] result = null;
        
        try {    
            SecretKeySpec spec = new SecretKeySpec(secretKeyBytes, "Blowfish");
            
            Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");

            cipher.init(Cipher.ENCRYPT_MODE, spec);
            
            iv = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
            
            result = cipher.doFinal(input);
            
        } catch (Exception e) {
            throw new SJException(e);
        }

        return result;
    }

    @Override
    public byte[] decrypt(byte[] input) throws SJException {
        byte[] result = null;
        
        try{
            SecretKeySpec spec = new SecretKeySpec(secretKeyBytes, "Blowfish");
            
            Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
            
            cipher.init(Cipher.DECRYPT_MODE, spec, new IvParameterSpec(iv));
            
            result = cipher.doFinal(input);
        }catch(Exception e){
            throw new SJException(e);
        }
        
        return result;
        
    }

    @Override
    public byte[] getIV() {
        return iv;
    }

    @Override
    public void setIV(byte[] _iv) {
        iv = _iv;
    }

}
