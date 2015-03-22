package com.gbsofts.gbcrypt.util;

import java.awt.Dimension;
import java.awt.Toolkit;
import javax.swing.ImageIcon;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;

/**
 *
 * @author Luong Dang Dung
 */
public class UIUtil {

    public static void SET_FRAME_CENTER(JFrame frame) {
        Dimension screenSize = new Dimension(Toolkit.getDefaultToolkit().getScreenSize());
        Dimension windowSize = new Dimension(frame.getPreferredSize());
        int wdwLeft = screenSize.width / 2 - windowSize.width / 2;
        int wdwTop = screenSize.height / 2 - windowSize.height / 2;
        frame.pack();
        frame.setLocation(wdwLeft, wdwTop);
    }
    
    public static void setDialogCenter(JDialog frame) {
        Dimension screenSize = new Dimension(Toolkit.getDefaultToolkit().getScreenSize());
        Dimension windowSize = new Dimension(frame.getPreferredSize());
        int wdwLeft = screenSize.width / 2 - windowSize.width / 2;
        int wdwTop = screenSize.height / 2 - windowSize.height / 2;
        frame.pack();
        frame.setLocation(wdwLeft, wdwTop);
    }
    

    public static JFileChooser SHOW_JFILECHOOSER(String title, String approvetext, int fileselectionmode, boolean multiselection) {
        JFileChooser chooser = new JFileChooser();
        //chooser.setCurrentDirectory(new java.io.File("."));
        
        chooser.setDialogTitle(title);
        chooser.setApproveButtonText(approvetext);
        chooser.setFileSelectionMode(fileselectionmode);
        chooser.setMultiSelectionEnabled(multiselection);
        

        return chooser;
    }
    
    public static void SET_FRAME_ICON(JFrame f, String iconPath){
        f.setIconImage(new ImageIcon(f.getClass().getResource(iconPath)).getImage());
    }
    
    public static void SHOW_FRAME(final JFrame frame){
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                frame.setVisible(true);
                SET_FRAME_CENTER(frame);
            }
        });
    
    }
    
    public static void POPUP(JFrame frame, String message){
        JOptionPane.showMessageDialog(frame, message);
    }
    
    public static String GET_DIR_PATH(JFrame frame) {
        String result = "";

        JFileChooser chooser = UIUtil.SHOW_JFILECHOOSER(
                "Choose one directory", "Select",
                JFileChooser.DIRECTORIES_ONLY, false);

        //    
        if (chooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
            result = chooser.getSelectedFile().getAbsolutePath();
        }

        return result;
    }

    public static String GET_FILE_PATH(JFrame frame) {
        String result = "";

        JFileChooser chooser = UIUtil.SHOW_JFILECHOOSER(
                "Choose file", "Select",
                JFileChooser.FILES_ONLY, false);
 
        if (chooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
            result = chooser.getSelectedFile().getAbsolutePath();
        }

        return result;
    }
    
    public static String SAVE_FILE_PATH(JFrame frame) {
        String result = "";

        JFileChooser chooser = UIUtil.SHOW_JFILECHOOSER(
                "Enter File Name To Save", "Accept",
                JFileChooser.FILES_ONLY, false);
 
        if (chooser.showSaveDialog(frame) == JFileChooser.APPROVE_OPTION) {
            result = chooser.getSelectedFile().getAbsolutePath();
        }

        return result;
    }
    
    public static String SAVE_DIR_PATH(JFrame frame) {
        String result = "";

        JFileChooser chooser = UIUtil.SHOW_JFILECHOOSER(
                "Enter Directory Name To Save", "Accept",
                JFileChooser.DIRECTORIES_ONLY, false);
 
        if (chooser.showSaveDialog(frame) == JFileChooser.APPROVE_OPTION) {
            result = chooser.getSelectedFile().getAbsolutePath();
        }

        return result;
    }
}
