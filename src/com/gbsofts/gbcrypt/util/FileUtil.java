package com.gbsofts.gbcrypt.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.security.CodeSource;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.zip.CRC32;
import java.util.zip.Checksum;


/**
 *
 * @author Luong Dang Dung
 */
public class FileUtil {

    public static byte[] getByteArray(String filepath) throws FileNotFoundException, IOException {

        byte[] inputBytes = null;
        File input = new File(filepath);

        inputBytes = new byte[(int) input.length()];

        InputStream is = new FileInputStream(filepath);

        is.read(inputBytes);

        is.close();

        return inputBytes;
    }

    public static void writeFile(byte[] outputBytes, String outputFile) throws FileNotFoundException, IOException {

        OutputStream os = new FileOutputStream(outputFile);

        os.write(outputBytes);

        os.flush();

        os.close();

    }

    public static long CHECKSUM(byte[] input) {
        Checksum checksum = new CRC32();

        checksum.update(input, 0, input.length);

        return checksum.getValue();
    }

    public static String CHECKSUM_SHA1(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest mDigest = MessageDigest.getInstance("SHA1");

        byte[] result = mDigest.digest(input);

        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < result.length; i++) {
            sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
        }

        return sb.toString();
    }

    public static byte[] CHECKSUM_FILE_SHA1(String file) throws Exception {

        MessageDigest md = MessageDigest.getInstance("SHA1");

        FileInputStream fis = new FileInputStream(file);

        byte[] buffer = new byte[1024];

        int byteRead = 0;

        while ((byteRead = fis.read(buffer)) != -1) {
            md.update(buffer, 0, byteRead);
        }

        fis.close();

        return md.digest();

    }

    public static byte[] CHECKSUM_BYTE_SHA1(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest mDigest = MessageDigest.getInstance("SHA1");

        return mDigest.digest(input);
    }

    public static String getCurdir() throws URISyntaxException {
        String jarDir = "";

        CodeSource codeSource = FileUtil.class.getProtectionDomain().getCodeSource();
        File jarFile = new File(codeSource.getLocation().toURI().getPath());
        jarDir = jarFile.getParentFile().getPath();

        return jarDir;
    }

    public static byte[] concat(byte[] a, byte[] b) {
        int aLen = a.length;
        int bLen = b.length;
        byte[] c = new byte[aLen + bLen];
        System.arraycopy(a, 0, c, 0, aLen);
        System.arraycopy(b, 0, c, aLen, bLen);
        return c;
    }

    public static byte[] INT_TO_BYTE_ARRAY(int input) {

        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.putInt(input);
        return bb.array();

    }

    public static String SHA_256(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(input.getBytes());

        byte byteData[] = md.digest();

        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < byteData.length; i++) {
            String hex = Integer.toHexString(0xff & byteData[i]);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
    

}
