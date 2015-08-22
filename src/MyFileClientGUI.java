import java.util.*;
import java.io.*;
import java.net.*;
import javax.swing.*;
import java.awt.event.*;
import java.awt.*;
import java.security.*;

public class MyFileClientGUI extends JFrame implements ActionListener
{

	Container content;
	JButton listFiles, uploadFile, downloadFile, deleteFile, terminateConnection;
	FileClient f_client;
	UserToken token;	//global token
	static String fsListFile = "trustedFileServers.txt";   //File holding File Servers connected to
	PublicKey servPubKey;  //File servers public key

	public void runMyFileClientGUI(UserToken tokenLocal, String serverName, int serverPort, FileClient created_client)
	{
		token = tokenLocal;
		/*boolean hasConnected = f_client.connect(serverName, serverPort);
		
		//Quit if user fails to connect
		if(!hasConnected)
		{
			JOptionPane.showMessageDialog(this,
			"Failed to connect to the " + serverName + ".\n" +
			"Contact system administrator if problem persists.",
			"Error Connecting!",
			JOptionPane.ERROR_MESSAGE);		
		}
		
		else	//create the GUI
		{*/
		    //Retrieve the file servers public key from file server
		    //servPubKey = f_client.getServerPublicKey(token);

			//set the f_client and get the public key
			FileClient f_client = created_client;
			servPubKey = token.getPublicKey();
			
		    //Create new file server object 
		    FileServerID currentFS = new FileServerID(serverName, serverPort, servPubKey);
		    
		    //Retrieve all trusted file servers client has connected to previously
		    ArrayList<FileServerID> trustedServers = MyFileClient.parseTrustedServers();
		    
		    //Check if client has connected to file server once before
		    if(!currentFS.isTrustedServer(trustedServers))
		    {
		        //If first time connecting: verify that they trust file servers public key
		        if(!acceptPublicKey(servPubKey))
		        {
		            //Client doesn't trust file server
                    JOptionPane.showMessageDialog(this, 
                            "Session terminated.",
                            "Session End",
                            JOptionPane.PLAIN_MESSAGE);
                    return;
		        }
		        else
		        {
		            //Client trusts file server so add to trusted servers list
		            trustedServers.add(currentFS);
		            try
		            {
	                    ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(fsListFile));
	                    
	                    for(FileServerID fs : trustedServers)
	                    {
	                        out.writeObject(fs);
	                    }
	                    out.close();
	                    
	                    //print that it was added
                        JOptionPane.showMessageDialog(this, 
                                "File Server trusted.  Added to list of trusted servers.",
                                "Trusting Server",
                                JOptionPane.PLAIN_MESSAGE);
		            }
		            catch(Exception e)
		            {
	                      JOptionPane.showMessageDialog(this, 
	                                "Error when adding "+serverName+" to the list of trusted servers.",
	                                "ERROR",
	                                JOptionPane.ERROR_MESSAGE);
		            }
		        }
		    }
		    
		    //Verify that a secure channel can be obtained so encrypted messages can be sent 
		    if(!f_client.obtainSecureChannel(servPubKey, token))
		    {
		        JOptionPane.showMessageDialog(this, 
                        "Could not establish a secure connection.",
                        "ERROR",
                        JOptionPane.ERROR_MESSAGE);
                return;
		    }
		    
		    
			//setting up the window
			content = this.getContentPane();
			content.setLayout(new GridLayout(5,1));
			this.setTitle( serverName + " File Menu" );
			setSize(225, 583);			
								
			//create buttons		
			listFiles = new JButton("List Files on " + serverName);
			uploadFile = new JButton("Upload File to " + serverName);
			downloadFile = new JButton("Download File from " + serverName);
			deleteFile = new JButton("Delete File on " + serverName);
			terminateConnection = new JButton("Terminate Connection");
			
			//set names
			listFiles.setName("listFiles");
			uploadFile.setName("uploadFile");
			downloadFile.setName("downloadFile");
			deleteFile.setName("deleteFile");
			terminateConnection.setName("terminateConnection");
			
			
			//add buttons
			this.add( listFiles );
			this.add( uploadFile );
			this.add( downloadFile );	
			this.add( deleteFile );
			this.add( terminateConnection );				
					
			//add action listeners
			listFiles.addActionListener(this);
			uploadFile.addActionListener(this);
			downloadFile.addActionListener(this);
			deleteFile.addActionListener(this);
			terminateConnection.addActionListener(this);
			
			//adding colors
			listFiles.setBackground(Color.lightGray);
			listFiles.setForeground(Color.yellow);
			uploadFile.setBackground(Color.lightGray);
			uploadFile.setForeground(Color.yellow);
			downloadFile.setBackground(Color.lightGray);
			downloadFile.setForeground(Color.yellow);
			deleteFile.setBackground(Color.lightGray);
			deleteFile.setForeground(Color.yellow);
			terminateConnection.setBackground(Color.lightGray);
			terminateConnection.setForeground(Color.yellow);
				
			setVisible(true);
		//}
		
		return;
		
	}//END runMyFileClient
	
	public void actionPerformed(ActionEvent e)	//check which buttons have been hit
	{
	
		String destFile, fileName, inputGroup, sourceFile;
		//figure out which component was clicked
		Component whichButton = (Component) e.getSource();
		switch( whichButton.getName() )
		{
			case "listFiles":	//list files, the files are printed to the command line
				try
				{									
					ArrayList<String> filesOnServer = (ArrayList)f_client.listFiles(token);
					
					if(filesOnServer != null && !filesOnServer.isEmpty())
					{
						String fileString = "";
						for(String file : filesOnServer)
						{
							fileString = fileString + file + "\n";
						}
						
						JOptionPane.showMessageDialog(this, 
								fileString,
								"Files Viewable by " + token.getSubject(),
								JOptionPane.PLAIN_MESSAGE);
					}
					else
					{
						JOptionPane.showMessageDialog(this, 
								"No files found on server for " + token.getSubject(),
								"Files On Server",
								JOptionPane.PLAIN_MESSAGE);
					}
					
				}
				
				catch(Exception exe)
				{
					JOptionPane.showMessageDialog(this,
					"Please verify the following:\n" +
					"\t- There exists files on this file server.\n" +
					"\t- You have access to such files existing on this file server.\n" +
					"Please contact system administrator if these conditions are met.",
					"Error Retrieving Files!",
					JOptionPane.ERROR_MESSAGE);
				}
				
			break;
			
			case "uploadFile":	//upload specified file
				
				inputGroup = JOptionPane.showInputDialog(this, "Enter which group to upload the file to:");
				sourceFile = JOptionPane.showInputDialog(this, "Please enter the full path of file to upload to " + inputGroup + ":");
				destFile = JOptionPane.showInputDialog(this, "Please enter the name for file to be called on server:");
				
				if(!f_client.upload(sourceFile, destFile, inputGroup, token))
				{
					JOptionPane.showMessageDialog(this,
					"Please verify the following:\n" +
					"\t- The group actually exists on the server.\n" +
					"\t- The file being uploaded exists on local file system.\n" +
					"\t- The file being uploaded does not already exist on file server.\n" +
					"\t- You have the right to upload a file to group " + inputGroup + " on the server.",
					"Error Uploading File!",
					JOptionPane.ERROR_MESSAGE);
				}
				
				else
				{
					JOptionPane.showMessageDialog(this,
					"Successfully uploaded specified file to group " + inputGroup + ".\n" +
					" -From local location: "+ sourceFile + "\n" +
					" -To server location: " + destFile,
					"Upload Successful!",
					JOptionPane.PLAIN_MESSAGE);
				}
				
			break;
			
			case "downloadFile":	//download specified file
				
				sourceFile = JOptionPane.showInputDialog(this, "Enter the name of the file you wish to download:");
				destFile = JOptionPane.showInputDialog(this, "Enter the full path of the location you wish to download " + sourceFile + " to:");
			
				if(!f_client.download(sourceFile, destFile, token))
				{
					JOptionPane.showMessageDialog(this,
					"Please verify the following:\n" +
					"\t- The file being downloaded exists on the file server.\n" +
					"\t- The file being downloaded does not already exist on your system.\n" +
					"\t- You have the right to download the file from the server.\n" +
					"Please contact system administrator if these conditions are met.",
					"Error Downloading File!",
					JOptionPane.ERROR_MESSAGE);
				}
				
				else
				{
					JOptionPane.showMessageDialog(this,
					"Successfully uploaded specified file: " + sourceFile + ".\n" +
					" -From server location: "+ sourceFile + "\n" +
					" -To local location: " + destFile,
					"Download Successful!",
					JOptionPane.PLAIN_MESSAGE);
				}
			
			break;
			
			case "deleteFile":	//deletes specified file
				
				fileName = JOptionPane.showInputDialog(this, "Please enter the name of the file you wish to delete:");
			
				if(!f_client.delete(fileName, token)) 
				{
					JOptionPane.showMessageDialog(this,
					"Please verify the following:\n" +
					"\t- The file actually exists on the server.\n" +
					"\t- You have the right to delete the file from the server.\n" +
					"Please contact system administrator if these conditions are met.",
					"Error Deleting File!",
					JOptionPane.ERROR_MESSAGE);
				}
				
				else
				{
					JOptionPane.showMessageDialog(this,
					"Successfully deleted specified file " + fileName + ".",
					"Delete Successful!",
					JOptionPane.PLAIN_MESSAGE);
				}
			break;
			
			case "terminateConnection":	//terminates the connection
				
				f_client.disconnect();
				
				java.awt.Window win[] = java.awt.Window.getWindows(); 
				for(int i=0;i<win.length;i++)
				{ 
					if(win[i].isFocused())
					{
						win[i].dispose(); 
						break;
					}
				} 
			
			break;
			
			default:	//error, should never come here
				JOptionPane.showMessageDialog(this,
				"A Button was clicked incorrectly.",
				"ERROR",
				JOptionPane.ERROR_MESSAGE);
		}
	}			
	
	/*Check if user will accept file server public key
	 * Similar to SSH to a server for the first time
	*/
    private boolean acceptPublicKey(PublicKey pk)
    {
        String prompt = "The server's host key is not cached.  You have no gaurantee that" +
                " the file server is the computer you think it is." +
                "The server's RSA key fingerprint is:\n" +
                MyFileClient.createThumbprint(pk.getEncoded()) +
                "\nDo you trust this server?";
        
        JTextArea msg = new JTextArea(prompt);
        msg.setLineWrap(true);
        msg.setWrapStyleWord(true);
        JScrollPane scrollMsg = new JScrollPane(msg);
        
        int reply = JOptionPane.showConfirmDialog(this, 
                scrollMsg,
                "First Connection",
                JOptionPane.YES_NO_OPTION);
        
        if(reply == JOptionPane.YES_OPTION)
        {
            return true;
        }
        else
        {
            return false;
        }
    }

}
