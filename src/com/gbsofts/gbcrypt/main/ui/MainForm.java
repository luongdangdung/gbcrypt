package com.gbsofts.gbcrypt.main.ui;

import com.gbsofts.gbcrypt.config.CustomConfig;
import com.gbsofts.gbcrypt.config.SystemConfig;
import com.gbsofts.gbcrypt.util.UIUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.streetjava.util.SJUtil;

/**
 *
 * @author Luong Dang Dung
 */
public class MainForm extends javax.swing.JFrame {

    static {
        try {
            CustomConfig.init();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static Logger logger = LogManager.getLogger(MainForm.class.getName());

    /**
     * Creates new form frmMain
     */
    public MainForm() {
        initComponents();
        UIUtil.SET_FRAME_CENTER(this);
        lblVersion.setText("Version "+ SystemConfig.VERSION + "." + SystemConfig.MINOR_VERSION);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel1 = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTextArea1 = new javax.swing.JTextArea();
        jLabel2 = new javax.swing.JLabel();
        lblVersion = new javax.swing.JLabel();
        jMenuBar1 = new javax.swing.JMenuBar();
        mnKey = new javax.swing.JMenu();
        mnGenerateKeys = new javax.swing.JMenuItem();
        mnImportKeys = new javax.swing.JMenuItem();
        mnEncrypt = new javax.swing.JMenu();
        mnEncryptFile = new javax.swing.JMenuItem();
        mnEncryptDir = new javax.swing.JMenuItem();
        mnDecrypt = new javax.swing.JMenu();
        mnDecryptFile = new javax.swing.JMenuItem();
        mnDecryptDir = new javax.swing.JMenuItem();
        mnSettings = new javax.swing.JMenu();
        mnConfiguration = new javax.swing.JMenuItem();
        mnHelp = new javax.swing.JMenu();
        mnLicense = new javax.swing.JMenuItem();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("GBCrypt");
        setResizable(false);

        jTextArea1.setEditable(false);
        jTextArea1.setColumns(20);
        jTextArea1.setLineWrap(true);
        jTextArea1.setText("Welcome to GBCrypt\n\nIf this is first time you use GBCrypt, please pay attention to read some guidelines:\n\n1. Choose Key / Generate Keys (for first time only, the second time in use, you can pass this step)\n\n2. Choose Encrypt or Decrypt menu\n- If you want to secure file, you can choose Encrypt / Encrypt File\n- if you want to secure whole directory, you can choose Encrypt / Encrypt Directory\n- If you want to remove secure of file, you can choose Decrypt / Decrypt File\n- If you want to remove secure of directory, you can choose Decrypt / Decrypt Directory\n\n3. For futher infomation, please access http://gbcrypt.misamap.com");
        jTextArea1.setWrapStyleWord(true);
        jScrollPane1.setViewportView(jTextArea1);

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 582, Short.MAX_VALUE))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 234, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 6, Short.MAX_VALUE))
        );

        jLabel2.setText("Developed by Luong Dang Dung");

        lblVersion.setText("Version");

        mnKey.setText("Key");

        mnGenerateKeys.setText("Generate Keys");
        mnGenerateKeys.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mnGenerateKeysActionPerformed(evt);
            }
        });
        mnKey.add(mnGenerateKeys);

        mnImportKeys.setText("Import Keys");
        mnImportKeys.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mnImportKeysActionPerformed(evt);
            }
        });
        mnKey.add(mnImportKeys);

        jMenuBar1.add(mnKey);

        mnEncrypt.setText("Encrypt");

        mnEncryptFile.setText("Encrypt File");
        mnEncryptFile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mnEncryptFileActionPerformed(evt);
            }
        });
        mnEncrypt.add(mnEncryptFile);

        mnEncryptDir.setText("Encypt Directory");
        mnEncryptDir.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mnEncryptDirActionPerformed(evt);
            }
        });
        mnEncrypt.add(mnEncryptDir);

        jMenuBar1.add(mnEncrypt);

        mnDecrypt.setText("Decrypt");

        mnDecryptFile.setText("Decrypt File");
        mnDecryptFile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mnDecryptFileActionPerformed(evt);
            }
        });
        mnDecrypt.add(mnDecryptFile);

        mnDecryptDir.setText("Decrypt Directory");
        mnDecryptDir.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mnDecryptDirActionPerformed(evt);
            }
        });
        mnDecrypt.add(mnDecryptDir);

        jMenuBar1.add(mnDecrypt);

        mnSettings.setText("Setting");

        mnConfiguration.setText("Configuration");
        mnConfiguration.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mnConfigurationActionPerformed(evt);
            }
        });
        mnSettings.add(mnConfiguration);

        jMenuBar1.add(mnSettings);

        mnHelp.setText("Help");

        mnLicense.setText("License");
        mnLicense.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mnLicenseActionPerformed(evt);
            }
        });
        mnHelp.add(mnLicense);

        jMenuBar1.add(mnHelp);

        setJMenuBar(jMenuBar1);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(lblVersion)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jLabel2)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(lblVersion))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void mnGenerateKeysActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mnGenerateKeysActionPerformed
        UIUtil.SHOW_FRAME(new GererateKeysForm());
    }//GEN-LAST:event_mnGenerateKeysActionPerformed

    private void mnImportKeysActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mnImportKeysActionPerformed
        UIUtil.SHOW_FRAME(new ImportKeysForm());
    }//GEN-LAST:event_mnImportKeysActionPerformed

    private void mnEncryptFileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mnEncryptFileActionPerformed
        if (checkPublicKey()) {
            UIUtil.SHOW_FRAME(new EncryptFileForm());
        }
    }//GEN-LAST:event_mnEncryptFileActionPerformed

    private void mnEncryptDirActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mnEncryptDirActionPerformed
        if (checkPublicKey()) {
            UIUtil.SHOW_FRAME(new EncryptDirectoryForm());
        }
    }//GEN-LAST:event_mnEncryptDirActionPerformed

    private void mnDecryptFileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mnDecryptFileActionPerformed
        if (checkPrivateKey()) {
            UIUtil.SHOW_FRAME(new DecryptFileForm());
        }
    }//GEN-LAST:event_mnDecryptFileActionPerformed

    private void mnDecryptDirActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mnDecryptDirActionPerformed
        if (checkPrivateKey()) {
            UIUtil.SHOW_FRAME(new DecryptDirectoryForm());
        }
    }//GEN-LAST:event_mnDecryptDirActionPerformed

    private void mnConfigurationActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mnConfigurationActionPerformed
        try {
            UIUtil.SHOW_FRAME(new SystemSettingForm());
        } catch (Exception ex) {
            logger.error(SJUtil.GET_STACKTRACE(ex));
        }
    }//GEN-LAST:event_mnConfigurationActionPerformed

    private void mnLicenseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mnLicenseActionPerformed
        UIUtil.SHOW_FRAME(new LicenseForm());
    }//GEN-LAST:event_mnLicenseActionPerformed

    private boolean checkPublicKey() {
        if (CustomConfig.PUBLIC_KEY_PATH.equals("")) {
            UIUtil.POPUP(this, "Please import public key to encrypt data");
            return false;
        } else {
            return true;
        }
    }

    private boolean checkPrivateKey() {
        if (CustomConfig.PRIVATE_KEY_PATH.equals("")) {
            UIUtil.POPUP(this, "Please import private key to decrypt data");
            return false;
        } else {
            return true;
        }
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(MainForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(MainForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(MainForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(MainForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new MainForm().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel jLabel2;
    private javax.swing.JMenuBar jMenuBar1;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTextArea jTextArea1;
    private javax.swing.JLabel lblVersion;
    private javax.swing.JMenuItem mnConfiguration;
    private javax.swing.JMenu mnDecrypt;
    private javax.swing.JMenuItem mnDecryptDir;
    private javax.swing.JMenuItem mnDecryptFile;
    private javax.swing.JMenu mnEncrypt;
    private javax.swing.JMenuItem mnEncryptDir;
    private javax.swing.JMenuItem mnEncryptFile;
    private javax.swing.JMenuItem mnGenerateKeys;
    private javax.swing.JMenu mnHelp;
    private javax.swing.JMenuItem mnImportKeys;
    private javax.swing.JMenu mnKey;
    private javax.swing.JMenuItem mnLicense;
    private javax.swing.JMenu mnSettings;
    // End of variables declaration//GEN-END:variables
}
