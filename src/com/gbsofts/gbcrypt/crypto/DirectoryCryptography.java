package com.gbsofts.gbcrypt.crypto;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.streetjava.exception.SJErrorCode;
import org.streetjava.exception.SJException;

/**
 * This file implement directory crypto.<br />
 * 
 * Directory crypto depends on each file crypto.<br/>
 * 
 * @author Luong Dang Dung
 */
public class DirectoryCryptography implements DirectoryCryptographal {

    static Logger logger = LogManager.getLogger(DirectoryCryptography.class.getName());

    private final FileCryptographal crypto;

    Path srcPath;
    Path dstPath;

    Map<String, String> fileList = new HashMap<>();

    public DirectoryCryptography(FileCryptographal _crypto) {
        crypto = _crypto;
    }

    /**
     * 1. set paths <br/>
     * 2. scan and create directories for outputDir<br/>
     * 3. encrypt files which have collected
     * 
     * @param inputDir
     * @param outputDir
     * @throws SJException
     */
    @Override
    public void encryptDir(String inputDir, String outputDir) throws SJException {
        try {
            srcPath = Paths.get(inputDir);
            dstPath = Paths.get(outputDir);

            scanDir(inputDir);

            for (Map.Entry<String, String> entry : fileList.entrySet()) {
                crypto.encryptFile(entry.getKey(), entry.getValue());

                Runtime.getRuntime().gc();
            }
        } catch (Exception e) {
            throw new SJException(e, SJErrorCode.TECHNICAL);
        }
    }

    private void scanDir(String newDir) throws IOException {

        Files.createDirectories(dstPath.resolve(srcPath
                .relativize(Paths.get(newDir))));

        File dir = new File(newDir);

        String[] list = dir.list();

        for (String f : list) {
            File file = new File(newDir + File.separator + f);

            if (file.isDirectory()) {
                scanDir(file.getAbsolutePath());
            } else {
                String oldFile = file.getAbsolutePath();
                String newFile = dstPath.resolve(srcPath
                        .relativize(Paths.get(file.getAbsolutePath()))).toString();

                fileList.put(oldFile, newFile);

                logger.trace("found " + oldFile);
            }
        }

    }

    /**
     * 1. set paths <br/>
     * 2. scan and create directories for outputDir<br/>
     * 3. decrypt files which have collected
     * 
     * @param inputDir
     * @param outputDir
     * @throws SJException
     */
    @Override
    public void decryptDir(String inputDir, String outputDir) throws SJException {
        try {
            srcPath = Paths.get(inputDir);
            dstPath = Paths.get(outputDir);

            scanDir(inputDir);
            
            for (Map.Entry<String, String> entry : fileList.entrySet()) {
                logger.trace("decrypt oldfile:"+entry.getKey());
                logger.trace("decrypt newfile:"+entry.getValue());
                crypto.decryptFile(entry.getKey(), entry.getValue());

                Runtime.getRuntime().gc();
            }
        } catch (Exception e) {
            throw new SJException(e, SJErrorCode.TECHNICAL);
        }
    }

}
