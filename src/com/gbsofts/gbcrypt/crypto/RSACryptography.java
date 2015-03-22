package com.gbsofts.gbcrypt.crypto;

import com.gbsofts.gbcrypt.util.FileUtil;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.streetjava.exception.SJErrorCode;
import org.streetjava.exception.SJException;

/**
 * This class implements RSA crypto
 * 
 * @author Luong Dang Dung
 */
public class RSACryptography implements AsymCryptographal {

    private String form = "RSA";
    private int length = 4096;
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public RSACryptography(int _length) {
        length = _length;
    }

    public RSACryptography(int _length, String publicKeyFile, String privateKeyFile) {
        try {
            length = _length;
            publicKey = getPublicKey(FileUtil.getByteArray(publicKeyFile));
            privateKey = getPrivateKey(FileUtil.getByteArray(privateKeyFile));
        } catch (Exception e) {
            throw new SJException(e, SJErrorCode.TECHNICAL);
        }
    }

    @Override
    public Object[] generateKeyPair() throws SJException {
        Object[] result = new Object[2];

        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance(form);
        } catch (NoSuchAlgorithmException ex) {
            throw new SJException(ex, SJErrorCode.TECHNICAL);
        }

        kpg.initialize(length);

        KeyPair kp = kpg.generateKeyPair();
        result[0] = kp.getPublic();
        result[1] = kp.getPrivate();

        return result;
    }

    @Override
    public PublicKey getPublicKey(byte[] input) throws SJException {
        PublicKey pubKey = null;
        try {
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(input);

            KeyFactory keyFactory = KeyFactory.getInstance(form);
            pubKey = keyFactory.generatePublic(pubKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new SJException(e, SJErrorCode.TECHNICAL);
        }
        return pubKey;
    }

    @Override
    public PrivateKey getPrivateKey(byte[] input) throws SJException {
        PrivateKey prvKey = null;
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(input);
            KeyFactory kf = KeyFactory.getInstance(form);

            prvKey = kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new SJException(e, SJErrorCode.TECHNICAL);
        }
        return prvKey;
    }

    @Override
    public byte[] encrypt(byte[] input) throws SJException {
        byte[] result = null;

        try {
            Cipher cipher = Cipher.getInstance(form);

            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            result = cipher.doFinal(input);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            throw new SJException(ex, SJErrorCode.TECHNICAL);
        }

        return result;
    }

    @Override
    public byte[] decrypt(byte[] input) throws SJException {
        byte[] result = null;
        try {
            Cipher cipher = Cipher.getInstance(form);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            result = cipher.doFinal(input);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            throw new SJException(ex, SJErrorCode.TECHNICAL);
        }
        return result;
    }

    @Override
    public void saveKeys(String publicKeyPath, String privateKeyPath) throws SJException {
        try {
            Object[] keys = generateKeyPair();

            PublicKey pubKey = (PublicKey) keys[0];
            PrivateKey prvKey = (PrivateKey) keys[1];

            FileUtil.writeFile(pubKey.getEncoded(), publicKeyPath);
            FileUtil.writeFile(prvKey.getEncoded(), privateKeyPath);
        } catch (SJException | IOException e) {
            throw new SJException(e, SJErrorCode.TECHNICAL);
        }
    }

}
