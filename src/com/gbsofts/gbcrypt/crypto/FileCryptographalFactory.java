package com.gbsofts.gbcrypt.crypto;

/**
 *
 * @author Luong Dang Dung
 */
public class FileCryptographalFactory {

    private final static FileCryptographalFactory instance = new FileCryptographalFactory();

    public static FileCryptographalFactory getInstace() {
        return instance;
    }

    public FileCryptographal create(int length, String publicKey, String privateKey, boolean isReplace) {
        return new FileCryptography(new MixedCryptography(new RSACryptography(length, publicKey, privateKey)), isReplace);
    }

}
