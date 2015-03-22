package com.gbsofts.gbcrypt.crypto;

import com.gbsofts.gbcrypt.config.CustomConfig;
import com.gbsofts.gbcrypt.config.SystemConfig;
import com.gbsofts.gbcrypt.util.FileUtil;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.Arrays;
import java.util.logging.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.streetjava.exception.SJErrorCode;
import org.streetjava.exception.SJException;

/**
 * This class describes file crypto operators.
 *
 *
 * @author Luong Dang Dung
 */
public class FileCryptography implements FileCryptographal {

    static Logger logger = LogManager.getLogger(FileCryptography.class.getName());

    private final Cryptographal crypto;

    private final boolean isReplace;

    public FileCryptography(Cryptographal _crypto, boolean _isReplace) {
        crypto = _crypto;
        isReplace = _isReplace;
    }

    /**
     * 1. Analyze file size to calculate number of child (data chunk) <br/>
     * 1.1 Create temp file for outputfile <br/>
     * 1.2 Write encrypte header sign <br/>
     * 2. Write version section to header <br/>
     * 3. Write length of SHA1 checksum of original file <br/>
     * 4. Write SHA1 check sum of original file <br/>
     * 5. Write child count to header <br/>
     * 6.1 Encrypt data of child1 <br/>
     * 6.2 Write length of encrypted child1 <br/>
     * 6.3 Write encrypted child1 bytes <br/>
     * 7. Loop (6.1),(6.2),(6.3) to other childs <br/>
     *
     * @param inputFile
     * @param outputFile
     * @throws SJException
     */
    @Override
    public void encryptFile(String inputFile, String outputFile) throws SJException {
        RandomAccessFile raf = null;
        DataOutputStream dos = null;

        try {
            logger.trace("begin encrypt file: " + inputFile);

            raf = new RandomAccessFile(inputFile, "r");
            long fileSize = raf.length();

            if (fileSize == 0) {
                return;
            }

            //1. Analyze file size to calculate number of child (data chunk)
            int childSize = CustomConfig.CHILD_SIZE;
            long mod = fileSize % Long.parseLong(String.valueOf(childSize));
            long childCountL = (fileSize - mod) / Long.parseLong(String.valueOf(childSize)) + 1;
            int childCount = Integer.parseInt(String.valueOf(childCountL));

            //1.1 Create temp file for outputfile
            String tempExtension = "."+ System.nanoTime() + SystemConfig.ENCRYPTED_EXTENSION;
            String oldOutputFile = outputFile;
            outputFile = outputFile + tempExtension;

            //1.2 Write encrypte header sign
            dos = new DataOutputStream(new FileOutputStream(outputFile));
            dos.write(SystemConfig.ENCRYPTED_HEADER_BLOCK);

            //2. Write version section to header
            dos.writeInt(SystemConfig.VERSION);

            //3. Write length of SHA1 checksum of original file
            byte[] fileCheckSumBytes = FileUtil.CHECKSUM_FILE_SHA1(inputFile);
            dos.writeInt(fileCheckSumBytes.length);

            //4. Write SHA1 check sum of original file
            dos.write(fileCheckSumBytes);

            //5. Write child count to header
            dos.writeInt(childCount);

            //process child data
            long currentIndex = 0;
            int count = 1;

            logger.trace("begin write child");
            logger.trace("childCount=" + childCount);
            logger.trace("fileSize=" + fileSize);
            logger.trace("childSize=" + childSize);
            while (count <= childCount) {

                if (count == childCount) {
                    if (mod > 0) {
                        childSize = Integer.parseInt(String.valueOf(mod));
                    }
                }

                raf.seek(currentIndex);

                byte[] childContentBytes = new byte[childSize];
                logger.trace("reading child " + count);
                int byteReadSize = raf.read(childContentBytes);

                logger.trace("encrypting child " + count);
                byte[] encryptedContent = crypto.encrypt(childContentBytes);

                logger.trace("writing encrypted child " + count + " to file");
                dos.writeInt(encryptedContent.length);
                dos.write(encryptedContent);

                currentIndex += byteReadSize;

                count++;
            }
            
            

            dos.flush();

            dos.close();

            dos = null;
            
            raf.close();
            
            raf = null;
            
            logger.trace(inputFile+":"+oldOutputFile);
            
            if (inputFile.equals(oldOutputFile)){
                if (isReplace){
                    //delete old file
                    File in = new File(inputFile);
                    in.delete();

                    //renew temp file to original file
                    new File(outputFile).renameTo(new File(oldOutputFile));
                    
                    logger.trace("complete writing file: " + oldOutputFile);
                }else{
                    logger.trace("complete writing file: " + outputFile);
                }
            }else{
                //renew temp file to original file
                 new File(outputFile).renameTo(new File(oldOutputFile));
                 logger.trace("complete writing file: " + oldOutputFile);
            }
            

        } catch (Exception e) {
            throw new SJException(e, SJErrorCode.TECHNICAL);
        } finally {
            if (dos != null) {
                try {
                    dos.flush();

                    dos.close();

                } catch (IOException ex) {
                    java.util.logging.Logger.getLogger(FileCryptography.class.getName()).log(Level.SEVERE, null, ex);
                }
            }


            try {
                if (raf != null) {
                    raf.close();
                }
            } catch (IOException ex) {
                java.util.logging.Logger.getLogger(FileCryptography.class.getName()).log(Level.SEVERE, null, ex);
            }

            logger.trace("end encrypt file");

        }

    }

    /**
     * 0.1 read encrypted header sign <br/>
     * 1. read version of header <br/>
     * 2. read length of SHA1 checksum <br/>
     * 3. read SHA1 checksum bytes <br/>
     * 3.1 create temp file for output file <br/>
     * 4. read child count <br/>
     * 5. read length encrypted of child1 6. read bytes of child1 7. decrypt
     * child1 --> content1 8. write content1 to outputfile 9. loop (6),(7),(8)
     * for other child <br/>
     *
     * @param inputFile
     * @param outputFile
     * @throws SJException
     */
    @Override
    public void decryptFile(String inputFile, String outputFile) throws SJException {
        DataInputStream dis = null;
        DataOutputStream dos = null;

        try {
            logger.trace("begin decrypt file: " + inputFile);

            dis = new DataInputStream(new FileInputStream(inputFile));

            //0.1 read encrypted header sign
            logger.trace("check encrypted heade sign");
            byte[] headerSign = new byte[4];
            dis.read(headerSign);

            if (!Arrays.equals(SystemConfig.ENCRYPTED_HEADER_BLOCK, headerSign)) {
                logger.error(SJErrorCode.HEADER_SIGN_INCORRECT.toString()+ ":" + inputFile);
                return;
            }

            //1. read version of header
            int version = dis.readInt();
            if (version != SystemConfig.VERSION){
                logger.error("System version:"+SystemConfig.VERSION + "----" + "Encrypt version:"+version);
                logger.error(SJErrorCode.INCORECT_VERSION.toString() + ":" + inputFile);
                return;
            }

            //2. read length of SHA1 checksum
            int checksumSize = dis.readInt();

            //3. read SHA1 checksum bytes
            byte[] checkSumBytes = new byte[checksumSize];
            dis.read(checkSumBytes);

            //3.1 create temp file for output file
            String tempExtension = "."+ System.nanoTime()+SystemConfig.DECRYPTED_EXTENSION;
            String oldOutputFile = outputFile;
            outputFile = outputFile + tempExtension;
            dos = new DataOutputStream(new FileOutputStream(outputFile));
    
            //4. read child count
            int childCount = dis.readInt();

            int count = 1;

            while (count <= childCount) {
                logger.trace("reading child " + count);

                int encryptedChildSize = dis.readInt();
                byte[] encryptedChildBytes = new byte[encryptedChildSize];
                dis.read(encryptedChildBytes);

                logger.trace("decrypting child " + count);
                byte[] decryptedChildBytes = crypto.decrypt(encryptedChildBytes);

                logger.trace("writing child " + count + " to file");
                dos.write(decryptedChildBytes);

                count++;
            }

            logger.trace("validating checksum SHA1");
            byte[] checkSumOutputFile = FileUtil.CHECKSUM_FILE_SHA1(outputFile);

            if (Arrays.equals(checkSumBytes, checkSumOutputFile)) {
                logger.trace("checksum ok, decrypt successfully!");
            } else {
                logger.error(SJErrorCode.SHA1_CHECKSUM_NOT_EQUAL.toString()+":"+outputFile);
                return;
            }
            
            dos.flush();;
            
            dos.close();
            
            dos = null;
            
            dis.close();
            
            dis = null;
            
            
            if (inputFile.equals(oldOutputFile)){
                if (isReplace){
                    //delete old file
                    File in = new File(inputFile);
                    in.delete();

                    //renew temp file to original file
                    new File(outputFile).renameTo(new File(oldOutputFile));
                    
                    logger.trace("complete writing file: " + oldOutputFile);
                }else{
                    logger.trace("complete writing file: " + outputFile);
                }
            }else{
                //renew temp file to original file
                 new File(outputFile).renameTo(new File(oldOutputFile));
                 logger.trace("complete writing file: " + oldOutputFile);
            }
            
            

        } catch (Exception e) {
            throw new SJException(e, SJErrorCode.TECHNICAL);
        } finally {
            if (dos != null) {
                try {
                    dos.flush();
                    dos.close();
                } catch (IOException ex) {
                    java.util.logging.Logger.getLogger(FileCryptography.class.getName()).log(Level.SEVERE, null, ex);
                }
            }

            if (dis != null) {
                try {
                    dis.close();
                } catch (IOException ex) {
                    java.util.logging.Logger.getLogger(FileCryptography.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
    }

    private String getExtension() {
        if (!isReplace) {
            return ".encrypted";
        } else {
            return "";
        }
    }

}
