package com.gbsofts.gbcrypt.crypto;

import java.security.spec.KeySpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.streetjava.exception.SJException;

/**
 * This file implements AES 256 bit encryption with PKCS5Padding
 * 
 * @author Luong Dang Dung
 */
public class AESCryptography implements SymCryptographal {

    private final byte[] salt;
    private final char[] key;
    private final int count = 65536;
    private final int length = 256;

    byte[] iv = new byte[16];

    public AESCryptography(char[] _key, byte[] _salt) {
        salt = _salt;
        key = _key;
    }

    @Override
    public byte[] encrypt(byte[] input) throws SJException {
        byte[] result = null;

        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            KeySpec spec = new PBEKeySpec(key, salt, count, length);
            SecretKey secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
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

        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            KeySpec spec = new PBEKeySpec(key, salt, count, length);
            SecretKey secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

            result = cipher.doFinal(input);
        } catch (Exception e) {
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
