package com.gbsofts.gbcrypt.config;

import com.gbsofts.gbcrypt.util.FileUtil;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.URISyntaxException;
import java.util.Properties;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.LoggerContext;

/**
 * This file sore configuration which have loaded from external properties file.
 * 
 * @author Luong Dang Dung
 */
public class CustomConfig {

    public static String PRIVATE_KEY_PATH = ""; //private key path for decrypting
    public static String PUBLIC_KEY_PATH = ""; //public key path for encrypting
    public static int CHILD_SIZE = 1073741824; //child size in byte
    public static int RSA_LENGTH = 4096; //default length is 4096, dont change it
    public static String ENCRYPT_FILE_PATH = "";
    public static String ENCRYPT_FOLDER_PATH = "";
    public static String DECRYPT_FILE_PATH = "";
    public static String DECRYPT_FOLDER_PATH = "";
    public static boolean IS_REPLACE = true; //is output file replace original file?
    public static String LOG_LEVEL = "INFO";
    public static boolean IS_WRITE_LOG = true;
    public static String LOG_PATH = ""; //default is current directory

    private static void LOAD_CONFIGS() throws FileNotFoundException, URISyntaxException, IOException, ClassNotFoundException, IllegalArgumentException, IllegalAccessException {

        InputStream is = new FileInputStream(FileUtil.getCurdir() + File.separator + SystemConfig.PROPERTIES_FILE);

        Properties props = new Properties();

        props.load(is);
        is.close();

        Class c = Class.forName(SystemConfig.CONFIG_CLASS);
        Field[] fields = c.getFields();

        for (Field field : fields) {
            String fieldname = field.getName();
            String fieldtype = field.getType().toString();

            switch (fieldtype) {

                case "class java.lang.String": {
                    field.set(null, String.valueOf(props.get(fieldname)).trim());
                    break;
                }
                case "int": {
                    field.set(null, Integer.parseInt(String.valueOf(
                            props.get(fieldname)).trim()));
                    break;
                }
                case "long": {
                    field.set(null, Long.parseLong(String.valueOf(
                            props.get(fieldname)).trim()));
                    break;
                }
                case "boolean": {
                    field.set(null, Boolean.parseBoolean(String.valueOf(
                            props.get(fieldname)).trim()));
                    break;
                }
                

            }

        }

    }

    public static void WRITE_CONFIG() throws ClassNotFoundException, IllegalArgumentException, IllegalAccessException, FileNotFoundException, URISyntaxException, IOException {
        OutputStream os = new FileOutputStream(FileUtil.getCurdir() + File.separator + SystemConfig.PROPERTIES_FILE);

        Properties props = new Properties();
        
        Class c = Class.forName(SystemConfig.CONFIG_CLASS);
        Field[] fields = c.getFields();

        for (Field field : fields) {
            String fieldname = field.getName();
            Object fieldvalue = field.get(null);

            props.put(fieldname, String.valueOf(fieldvalue));
        }
        
        String header = "GBCrypt version " + SystemConfig.VERSION;
        
        props.store(os, header);
        
        os.flush();
        
        os.close();

    }

    /**
     * config logFilename at current jar file location
     */
    private static void INIT_LOG() throws URISyntaxException {
        
        if ("".equals(LOG_PATH) || LOG_PATH == null){
            System.setProperty("logFilename", FileUtil.getCurdir() + File.separator + SystemConfig.LOG_FILE);
        }else{
            System.setProperty("logFilename", LOG_PATH);
        }

        System.setProperty("logLogLevel", LOG_LEVEL);
        LoggerContext ctx
                = (org.apache.logging.log4j.core.LoggerContext) LogManager.getContext(false);
        
        for(Logger logger : ctx.getLoggers()){
            logger.setAdditive(CustomConfig.IS_WRITE_LOG);
        }
        
        ctx.reconfigure();
    }

    public static void init() throws URISyntaxException, IOException, FileNotFoundException, ClassNotFoundException, IllegalArgumentException, IllegalAccessException {
        LOAD_CONFIGS();

        INIT_LOG();
        
        CHECK_KEYS();
    }
    
    private static void CHECK_KEYS(){
        File prvKey = new File(CustomConfig.PRIVATE_KEY_PATH);
        
        if (!prvKey.exists()){
            CustomConfig.PRIVATE_KEY_PATH = "";
        }
        
        File pubKey = new File(CustomConfig.PUBLIC_KEY_PATH);
        
        if (!pubKey.exists()){
            CustomConfig.PUBLIC_KEY_PATH = "";
        }
        
    }
}
