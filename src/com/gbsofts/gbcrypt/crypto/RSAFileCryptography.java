package com.gbsofts.gbcrypt.crypto;

import com.gbsofts.gbcrypt.util.FileUtil;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.streetjava.exception.SJErrorCode;
import org.streetjava.exception.SJException;

/**
 * This class implements file crypto using RSA
 * 
 * @author Luong Dang Dung
 */
public class RSAFileCryptography implements FileCryptographal {

    private final AsymCryptographal crypto;

    public RSAFileCryptography(AsymCryptographal _crypto) {
        crypto = _crypto;
    }

    @Override
    public void encryptFile(String inputFile,  String outputFile) throws SJException{
        try{
            byte[] inputFileBytes = FileUtil.getByteArray(inputFile);

            encryptChunk(inputFileBytes, outputFile);
        }catch(Exception e){
            throw new SJException(e,SJErrorCode.TECHNICAL);
        }
    }

    @Override
    public void decryptFile(String inputFile,  String outputFile) throws SJException {
        try{
            byte[] inputFileBytes = FileUtil.getByteArray(inputFile);

            decryptChunk(inputFileBytes, outputFile);
        }catch(Exception e){
            throw new SJException(e, SJErrorCode.TECHNICAL);
        }
    }

    private void encryptChunk(byte[] inputBytes, String outfile) throws SJException {
        try {
            int allLength = inputBytes.length;
            

            DataOutputStream os = new DataOutputStream(new FileOutputStream(outfile));

            int fix = 117; //prefered for RSA 1024 (1024/8 - 11)
            
            if (fix > allLength){
                fix = allLength;
            }

            byte[] content = new byte[0];
            byte[] chunk = Arrays.copyOfRange(inputBytes, 0, fix);

            
            int count = 0;

            List<Integer> headerList = new ArrayList<Integer>();
            
            
            while (chunk.length == fix) {
                byte[] outputFileBytes = crypto.encrypt(chunk);
                
                //mark numberofbyte will be write to file
                os.writeInt(outputFileBytes.length);
                
                byte[] newcontent =  FileUtil.concat(content, outputFileBytes);
                content = new byte[newcontent.length];
                content = newcontent;
                
                count += fix;
                
                if ((count)>allLength){
                    chunk = Arrays.copyOfRange(inputBytes, count-fix, allLength);
                }else{
                    if ((count+fix)>allLength){
                        chunk = Arrays.copyOfRange(inputBytes, count, allLength);
                    }else{
                        chunk = Arrays.copyOfRange(inputBytes, count, count + fix);
                    }
                    
                }
            }

            if (chunk.length < fix && chunk.length > 0) {
                byte[] outputFileBytes = crypto.encrypt(chunk);
                
                byte[] newcontent =  FileUtil.concat(content, outputFileBytes);
                content = new byte[newcontent.length];
                content = newcontent;
                
                //mark numberofbyte will be write to file

                os.writeInt(outputFileBytes.length);
            }
           
            
            //write -1 to indicate end of header
            os.writeInt(-1);
            
            //write all data
            os.write(content);
            
            System.out.println("e:"+content.length);

            os.flush();

            os.close();
        } catch (Exception e) {
            throw new SJException(e, SJErrorCode.TECHNICAL);
        }
    }
    
    private void decryptChunk(byte[] inputBytes,  String outfile) throws SJException {
        try{
            byte[] block = new byte[4];
            
            int fix = 4;
            
            int count =0;
            
            int encryptedBytes = 0;
            
            int startReadIndex = 0;
            
            List<Integer> header = new ArrayList<Integer>();
            
            
            while (encryptedBytes>=0){
                ByteBuffer wrapped = ByteBuffer.wrap(Arrays.copyOfRange(inputBytes, count, count+fix));
                encryptedBytes = wrapped.getInt();
                startReadIndex+= fix;
                header.add(encryptedBytes);
                count+=fix;
                //System.out.println(encryptedBytes);
            }
            
           
            //begin decrypt
            int readCount =  startReadIndex;
            OutputStream os = new FileOutputStream(outfile);
            for(int encryptedSize : header){
                System.out.println(encryptedSize);
                if (encryptedSize >=0){
                    byte[] encryptedChunkBytes = Arrays.copyOfRange(inputBytes, readCount, readCount+encryptedSize);
                    os.write(crypto.decrypt(encryptedChunkBytes));
                   
                    readCount+=encryptedSize;
                    
                }else{
                    break;
                }
            }
             
            os.flush();
            
            os.close();
            
        }catch(Exception e){
            throw new SJException(e, SJErrorCode.TECHNICAL);
        }
    }

    

}
