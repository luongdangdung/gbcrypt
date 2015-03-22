package com.gbsofts.gbcrypt.crypto;

import com.gbsofts.gbcrypt.util.FileUtil;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;
import java.util.UUID;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.streetjava.exception.SJErrorCode;
import org.streetjava.exception.SJException;

/**
 * This class describes the sequence of crypto operators which have combined.
 * 
 * @author Luong Dang Dung
 */
public class MixedCryptography implements Cryptographal {

    private final AsymCryptographal crypto;

    public MixedCryptography(AsymCryptographal _crypto) {
        crypto = _crypto;
    }

    /**
     * EncryptFile process <br/>
     * 0.1 Generate SHA1 checksum bytes of Input <br/>
     * 1. Generate params of Blowfish <br/>
     * 2. Encrypte params of Blowfish --> params1 <br/>
     * 3. Generate params of AES <br/>
     * 4. Encrypt params of AES --> params2 <br/>
     * 5. Encrypt content using Blowfish --> content1 <br/>
     * 6. Get Blowfish IV bytes <br/>
     * 7. Encrypt Bloswfish IV bytes <br/>
     * 8. Encrypt content1 using AES --> content2 <br/>
     * 9. Get AES IV bytes <br/>
     * 10. Encrypt AES IV bytes <br/>
     * 10.1 Write SHA1 checksum length to outputfile <br/>
     * 10.2 Write SHA1 checksym bytes to output file <br/>
     * 11. Write params1(s) length to outputfile <br/>
     * 12. Write params2(s) length to outputfile <br/>
     * 13. Write params1(s) to outputfile <br/>
     * 14. Write params2(s) to outputfile <br/>
     * 15. Write content2 to outputfile <br/>
     * 16. Flush and close outfile <br/>
     *
     *
     * @param inputFile
     * @param outputFile
     * @throws SJException
     */
    public byte[] encrypt(byte[] inputBytes) throws SJException {
        try {
            //0.1 Generate SHA1 checksum bytes of Input
            byte[] sha1checksum = FileUtil.CHECKSUM_BYTE_SHA1(inputBytes);

            //1. Generate params of Blowfish
            KeyGenerator keygenerator = KeyGenerator.getInstance("Blowfish");
            SecretKey secretkey = keygenerator.generateKey();

            //2. Encrypte params of Blowfish --> params1
            byte[] blowfishKeyBytes = secretkey.getEncoded();
            byte[] blowfishKeyEncryptedBytes = crypto.encrypt(blowfishKeyBytes);

            //3. Generate params of AES
            String randomAESPass = UUID.randomUUID().toString();
            byte[] randomAESSalt = new byte[16];
            new Random().nextBytes(randomAESSalt);

            //4. Encrypt params of AES --> params2
            byte[] aesPassBytes = randomAESPass.getBytes();
            byte[] aesPassEncryptedBytes = crypto.encrypt(aesPassBytes);

            byte[] randomAESSaltEncyptedBytes = crypto.encrypt(randomAESSalt);

            //5. Encrypt content using Blowfish --> content1
            SymCryptographal blowfishCrypto = new BlowfishCryptography(blowfishKeyBytes);
            byte[] content1 = blowfishCrypto.encrypt(inputBytes);

            //6. Get Blowfish IV bytes
            byte[] blowfishIVBytes = blowfishCrypto.getIV();
            //7. Encrypt Bloswfish IV bytes
            byte[] blowfishIVEncryptedBytes = crypto.encrypt(blowfishIVBytes);

            //8. Encrypt content1 using AES --> content2
            SymCryptographal aesCrypto = new AESCryptography(randomAESPass.toCharArray(), randomAESSalt);
            byte[] content2 = aesCrypto.encrypt(content1);

            //9. Get AES IV bytes
            byte[] aesIVBytes = aesCrypto.getIV();

            //10. Encrypt AES IV bytes
            byte[] aesIVEncryptedBytes = crypto.encrypt(aesIVBytes);

            //10.1 Write SHA1 checksum length to outputfile
            byte[] outputBytes = FileUtil.concat(new byte[0], FileUtil.INT_TO_BYTE_ARRAY(sha1checksum.length));

            //10.2 Write SHA1 checksym bytes to output file
            outputBytes = FileUtil.concat(outputBytes, sha1checksum);

            //11. Write params1(s) length to outputfile
            int blowfishKeyEncryptedBytesSize = blowfishKeyEncryptedBytes.length;
            int blowfishIVEncryptedBytesSize = blowfishIVEncryptedBytes.length;

            outputBytes = FileUtil.concat(outputBytes, FileUtil.INT_TO_BYTE_ARRAY(blowfishKeyEncryptedBytesSize));
            outputBytes = FileUtil.concat(outputBytes, FileUtil.INT_TO_BYTE_ARRAY(blowfishIVEncryptedBytesSize));

            //12. Write params2(s) length to outputfile
            int aesPassEncryptedBytesSize = aesPassEncryptedBytes.length;
            int randomAESSaltEncyptedBytesSize = randomAESSaltEncyptedBytes.length;
            int aesIVEncryptedBytesSize = aesIVEncryptedBytes.length;

            outputBytes = FileUtil.concat(outputBytes, FileUtil.INT_TO_BYTE_ARRAY(aesPassEncryptedBytesSize));
            outputBytes = FileUtil.concat(outputBytes, FileUtil.INT_TO_BYTE_ARRAY(randomAESSaltEncyptedBytesSize));
            outputBytes = FileUtil.concat(outputBytes, FileUtil.INT_TO_BYTE_ARRAY(aesIVEncryptedBytesSize));

            //13. Write params1(s) to outputfile
            outputBytes = FileUtil.concat(outputBytes, blowfishKeyEncryptedBytes);
            outputBytes = FileUtil.concat(outputBytes, blowfishIVEncryptedBytes);

            //14. Write params2(s) to outputfile
            outputBytes = FileUtil.concat(outputBytes, aesPassEncryptedBytes);
            outputBytes = FileUtil.concat(outputBytes, randomAESSaltEncyptedBytes);
            outputBytes = FileUtil.concat(outputBytes, aesIVEncryptedBytes);

            //15. Write content2 to outputfile
            outputBytes = FileUtil.concat(outputBytes, content2);

            return outputBytes;
        } catch (Exception e) {
            throw new SJException(e, SJErrorCode.TECHNICAL);
        }
    }

    /**
     * Decrypt File process <br/>
     * 0.1 Read SHA1 checksum size, recalculate headerFixedSize <br/>
     * 0.2 Read SHA1 checksum byte, recalculate headerFixedSize <br/>
     * 1. Read blowfishKeyEncryptedBytesSize at headerFixedSize to
     * (headerFixedSize+4) byte, recalculate headerFixedSize <br/>
     * 2. Read blowfishIVEncryptedBytesSize at 4 - 8 byte --> num2 <br/>
     * 3. Read aesPassEncryptedBytesSize at 8 - 12 byte --> num3 <br/>
     * 4. Read randomAESSaltEncyptedBytesSize at 12 - 16 byte --> num4 <br/>
     * 5. Read aesIVEncryptedBytes at 16 -20 byte --> num5 <br/>
     * 6. Read bytes from 20 to num1 to get blowfishKeyEncryptedBytes and
     * decrypt it using RSA <br/>
     * 7. Read bytes from (20+num1) to num2 to get blowfishIVEncryptedBytesSize
     * and decrypt it using RSA <br/>
     * 8. Read bytes from (20+num1+num2) to num3 to get
     * aesPassEncryptedBytesSize and decrypt it using RSA7 <br />
     * 9. Read bytes from (20+num1+num2+num3) to num4 to get
     * randomAESSaltEncyptedBytesSize and decrypt it using RSA <br/>
     * 10. Read bytes from (20+num1+num2+num3+num4) to num5 to get
     * aesIVEncryptedBytes and decrypt it using RSA <br/>
     * 11. Get main content at (20 + num1 + num2 + num3 + num4 + num5) to file
     * length --> content1 <br/>
     * 12. Decrypt content1 using AES with params of (8), (9), (10) --> content2
     * <br/>
     * 13. Decrypt content2 using Blowfish with params of (6), (7) --> content3
     * <br/>
     * 14. Write content3 to outputfile <br/>
     * 15. Compare outputfile checksum with SHA1 checksum <br/>
     *
     * @param inputFile
     * @param outputFile
     * @throws SJException
     */
    public byte[] decrypt(byte[] fileContent) throws SJException {
        try {
            int headerFixedSize = 0;

            //0.1 Read SHA1 checksum size at 0 - 4 byte
            ByteBuffer wrapped = ByteBuffer.wrap(Arrays.copyOfRange(fileContent, headerFixedSize, headerFixedSize + 4));
            int checkSumSize = wrapped.getInt();
            headerFixedSize += 4;

            //0.2 Read SHA1 checksum byte, recalculate headerFixedSize
            byte[] checkSumBytes = Arrays.copyOfRange(fileContent, headerFixedSize, headerFixedSize + checkSumSize);
            headerFixedSize += checkSumSize;

            //1. Read blowfishKeyEncryptedBytesSize at 0 - 4 byte --> num1
            wrapped = ByteBuffer.wrap(Arrays.copyOfRange(fileContent, headerFixedSize, headerFixedSize + 4));
            int blowfishKeyEncryptedBytesSize = wrapped.getInt();
            headerFixedSize += 4;

            //2. Read blowfishIVEncryptedBytesSize at 4 - 8 byte --> num2
            wrapped = ByteBuffer.wrap(Arrays.copyOfRange(fileContent, headerFixedSize, headerFixedSize + 4));
            int blowfishIVEncryptedBytesSize = wrapped.getInt();
            headerFixedSize += 4;

            //3. Read aesPassEncryptedBytesSize at 8 - 12 byte --> num3
            wrapped = ByteBuffer.wrap(Arrays.copyOfRange(fileContent, headerFixedSize, headerFixedSize + 4));
            int aesPassEncryptedBytesSize = wrapped.getInt();
            headerFixedSize += 4;

            //4. Read randomAESSaltEncyptedBytesSize at 12 - 16 byte --> num4
            wrapped = ByteBuffer.wrap(Arrays.copyOfRange(fileContent, headerFixedSize, headerFixedSize + 4));
            int randomAESSaltEncyptedBytesSize = wrapped.getInt();
            headerFixedSize += 4;

            //5. Read aesIVEncryptedBytes at 16 -20 byte --> num5
            wrapped = ByteBuffer.wrap(Arrays.copyOfRange(fileContent, headerFixedSize, headerFixedSize + 4));
            int aesIVEncryptedBytesSize = wrapped.getInt();
            headerFixedSize += 4;

            //6. Read bytes from 20 to num1 to get blowfishKeyEncryptedBytes and decrypt it using RSA
            byte[] blowfishKeyEncryptedBytes = Arrays.copyOfRange(fileContent, headerFixedSize, headerFixedSize + blowfishKeyEncryptedBytesSize);
            byte[] blowfishKeyBytes = crypto.decrypt(blowfishKeyEncryptedBytes);
            headerFixedSize += blowfishKeyEncryptedBytesSize;

            //7. Read bytes from (20+num1) to num2 to get blowfishIVEncryptedBytesSize and decrypt it using RSA
            byte[] blowfishIVEncryptedBytes = Arrays.copyOfRange(fileContent, headerFixedSize, headerFixedSize + blowfishIVEncryptedBytesSize);
            byte[] blowfishIVBytes = crypto.decrypt(blowfishIVEncryptedBytes);
            headerFixedSize += blowfishIVEncryptedBytesSize;

            //8. Read bytes from (20+num1+num2) to num3 to get aesPassEncryptedBytesSize and decrypt it using RSA7
            byte[] aesPassEncryptedBytes = Arrays.copyOfRange(fileContent, headerFixedSize, headerFixedSize + aesPassEncryptedBytesSize);
            byte[] aesPassBytes = crypto.decrypt(aesPassEncryptedBytes);
            headerFixedSize += aesPassEncryptedBytesSize;

            //9. Read bytes from (20+num1+num2+num3) to num4 to get randomAESSaltEncyptedBytesSize and decrypt it using RSA
            byte[] randomAESSaltEncyptedBytes = Arrays.copyOfRange(fileContent, headerFixedSize, headerFixedSize + randomAESSaltEncyptedBytesSize);
            byte[] randomAESSaltBytes = crypto.decrypt(randomAESSaltEncyptedBytes);
            headerFixedSize += randomAESSaltEncyptedBytesSize;

            //10. Read bytes from (20+num1+num2+num3+num4) to num5 to get aesIVEncryptedBytesSize and decrypt it using RSA
            byte[] aesIVEncryptedBytes = Arrays.copyOfRange(fileContent, headerFixedSize, headerFixedSize + aesIVEncryptedBytesSize);
            byte[] aesIVBytes = crypto.decrypt(aesIVEncryptedBytes);
            headerFixedSize += aesIVEncryptedBytesSize;

            //11. Get main content at (20 + num1 + num2 + num3 + num4 + num5) to file length --> content1
            byte[] content1 = Arrays.copyOfRange(fileContent, headerFixedSize, fileContent.length);

            //12. Decrypt content1 using AES with params of (8), (9), (10) --> content2
            String aesPass = new String(aesPassBytes);

            SymCryptographal aesCrypto = new AESCryptography(aesPass.toCharArray(), randomAESSaltBytes);
            aesCrypto.setIV(aesIVBytes);

            byte[] content2 = aesCrypto.decrypt(content1);

            //13. Decrypt content2 using Blowfish with params of (6), (7) --> content3
            SymCryptographal blowfishCrypto = new BlowfishCryptography(blowfishKeyBytes);
            blowfishCrypto.setIV(blowfishIVBytes);
            byte[] content3 = blowfishCrypto.decrypt(content2);

            if (Arrays.equals(FileUtil.CHECKSUM_BYTE_SHA1(content3), checkSumBytes)) {
                return content3;
            } else {
                throw new SJException(SJErrorCode.SHA1_CHECKSUM_NOT_EQUAL);
            }

        } catch (Exception e) {
            throw new SJException(e, SJErrorCode.TECHNICAL);
        }
    }

}
