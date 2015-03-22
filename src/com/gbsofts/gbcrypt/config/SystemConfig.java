package com.gbsofts.gbcrypt.config;

/**
 * This file store system configuration which apply to entire application
 * 
 * @author Luong Dang Dung
 */
public class SystemConfig {
    public final static int VERSION = 1; //it is major version, when crypto logic change, this version will be inceased
    public final static int MINOR_VERSION = 1; //it is minor version, when something change without crypto logic, this minor version will be inceased
    public final static byte[] ENCRYPTED_HEADER_BLOCK =  {24,0,5,84}; //the sign which detect encrypted file header
    public static int BLOCK_RSA_READ = CustomConfig.RSA_LENGTH / 8 - 11;
    public final static String ENCRYPTED_EXTENSION = ".gbecrypted";
    public final static String DECRYPTED_EXTENSION = ".gbdecrypted";
    public final static String PUBLIC_KEY_FILE="gb_lock_publickey";
    public final static String PRIVATE_KEY_FILE="gb_unlock_privatekey";
    public final static String CONFIG_CLASS = "com.gbsofts.gbcrypt.config.CustomConfig";
    public final static String PROPERTIES_FILE = "gbcrypt.properties";
    public final static String LOG_FILE = "gbcrypt_log.log";
}
