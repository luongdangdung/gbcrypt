package com.gbsofts.gbcrypt.main.ui;

import com.gbsofts.gbcrypt.config.CustomConfig;
import com.gbsofts.gbcrypt.crypto.DirectoryCryptographal;
import com.gbsofts.gbcrypt.crypto.DirectoryCryptographalFactory;
import com.gbsofts.gbcrypt.util.UIUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.streetjava.util.SJUtil;

/**
 *
 * @author Luong Dang Dung
 */
public class DecryptDirectoryForm extends javax.swing.JFrame {

    static Logger logger = LogManager.getLogger(DecryptDirectoryForm.class.getName());
    
    /**
     * Creates new form EncryptDirectoryForm
     */
    public DecryptDirectoryForm() {
        initComponents();
        
        txtPrivateKey.setText(CustomConfig.PRIVATE_KEY_PATH);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        txtSourceDir = new javax.swing.JTextField();
        cmdDecrypt = new javax.swing.JButton();
        cmdBrowseSourceDir = new javax.swing.JButton();
        jLabel2 = new javax.swing.JLabel();
        cmdBrowseDestinationDir = new javax.swing.JButton();
        chkReplaceName = new javax.swing.JCheckBox();
        jLabel3 = new javax.swing.JLabel();
        txtPrivateKey = new javax.swing.JLabel();
        txtDestinationDir = new javax.swing.JTextField();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setTitle("Decrypt Directory");

        jLabel1.setText("Source Directory");

        txtSourceDir.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                txtSourceDirActionPerformed(evt);
            }
        });

        cmdDecrypt.setText("Decrypt");
        cmdDecrypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cmdDecryptActionPerformed(evt);
            }
        });

        cmdBrowseSourceDir.setText("Browse");
        cmdBrowseSourceDir.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cmdBrowseSourceDirActionPerformed(evt);
            }
        });

        jLabel2.setText("Destination Directory");

        cmdBrowseDestinationDir.setText("Browse");
        cmdBrowseDestinationDir.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cmdBrowseDestinationDirActionPerformed(evt);
            }
        });

        chkReplaceName.setText("Replace name");

        jLabel3.setText("Current Private Key");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jLabel2)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(txtDestinationDir, javax.swing.GroupLayout.PREFERRED_SIZE, 241, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jLabel1)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(txtSourceDir, javax.swing.GroupLayout.PREFERRED_SIZE, 241, javax.swing.GroupLayout.PREFERRED_SIZE)))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(cmdBrowseSourceDir, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(cmdBrowseDestinationDir, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                    .addComponent(chkReplaceName)
                    .addComponent(cmdDecrypt)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addComponent(jLabel3)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(txtPrivateKey, javax.swing.GroupLayout.PREFERRED_SIZE, 327, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(12, 12, 12)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(txtSourceDir, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(cmdBrowseSourceDir))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(cmdBrowseDestinationDir)
                    .addComponent(txtDestinationDir, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(chkReplaceName)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(cmdDecrypt)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(txtPrivateKey, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabel3))
                .addContainerGap(15, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void txtSourceDirActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_txtSourceDirActionPerformed
        txtDestinationDir.setText(UIUtil.GET_FILE_PATH(this));
    }//GEN-LAST:event_txtSourceDirActionPerformed

    private void cmdDecryptActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cmdDecryptActionPerformed
        try{
            DirectoryCryptographal dirCrypto = DirectoryCryptographalFactory.getInstance().create(CustomConfig.RSA_LENGTH, CustomConfig.PUBLIC_KEY_PATH, CustomConfig.PRIVATE_KEY_PATH, chkReplaceName.isSelected());
            
            dirCrypto.decryptDir(txtSourceDir.getText(), txtDestinationDir.getText());

            UIUtil.POPUP(this, "Decrypt directory successfully!");
        }catch(Exception e){
            logger.error(SJUtil.GET_STACKTRACE(e));
        }
    }//GEN-LAST:event_cmdDecryptActionPerformed

    private void cmdBrowseSourceDirActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cmdBrowseSourceDirActionPerformed
        txtSourceDir.setText(UIUtil.GET_DIR_PATH(this));
    }//GEN-LAST:event_cmdBrowseSourceDirActionPerformed

    private void cmdBrowseDestinationDirActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cmdBrowseDestinationDirActionPerformed
        txtDestinationDir.setText(UIUtil.GET_DIR_PATH(this));
    }//GEN-LAST:event_cmdBrowseDestinationDirActionPerformed

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
            java.util.logging.Logger.getLogger(DecryptDirectoryForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(DecryptDirectoryForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(DecryptDirectoryForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(DecryptDirectoryForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new DecryptDirectoryForm().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JCheckBox chkReplaceName;
    private javax.swing.JButton cmdBrowseDestinationDir;
    private javax.swing.JButton cmdBrowseSourceDir;
    private javax.swing.JButton cmdDecrypt;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JTextField txtDestinationDir;
    private javax.swing.JLabel txtPrivateKey;
    private javax.swing.JTextField txtSourceDir;
    // End of variables declaration//GEN-END:variables
}
