import java.util.*;
import java.io.*;
import java.net.*;
import javax.swing.*;
import java.awt.event.*;
import java.awt.*;

/* cryptography libraries */
import java.security.*;
import javax.crypto.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class MyGroupClientGUI extends JFrame implements ActionListener
{

	Container content;
	JButton fileButton, newUser, deleteUser, newGroup, deleteGroup, addUserToGroup, deleteUserFromGroup, listMembers, logOut;
	UserToken token;	//global token
	
	GroupClient g_client;
	public MyGroupClientGUI(GroupClient client) {
		g_client = client;
	}
	
	public void runMyGroupClientGUI(UserToken tokenLocal, String serverName, int serverPort)
	{
		token = tokenLocal;
		boolean hasConnected = true;//g_client.connect(serverName, serverPort);
		
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
		{
			//setting up the window
			content = this.getContentPane();
			content.setLayout(new GridLayout(9,1));
			this.setTitle( "Main Menu" );
			setSize(225, 1050);			
								
			//create buttons		
			fileButton = new JButton("Connect to a File Server");
			newUser = new JButton("Create a New User");
			deleteUser = new JButton("Delete an Existing User");
			newGroup = new JButton("Create a New Group");
			deleteGroup = new JButton("Delete an Existing Group");
			addUserToGroup = new JButton("Add a User to a Group");
			deleteUserFromGroup = new JButton("Delete a User from a Group");
			listMembers = new JButton("List the Members of a Group");
			logOut = new JButton("Logout");
			
			//set names
			fileButton.setName("fileButton");
			newUser.setName("newUser");
			deleteUser.setName("deleteUser");
			newGroup.setName("newGroup");
			deleteGroup.setName("deleteGroup");
			addUserToGroup.setName("addUserToGroup");
			deleteUserFromGroup.setName("deleteUserFromGroup");
			listMembers.setName("listMembers");
			logOut.setName("logOut");
			
			
			//add buttons
			this.add( fileButton );
			this.add( newUser );
			this.add( deleteUser );
			this.add( newGroup );	
			this.add( deleteGroup );
			this.add( addUserToGroup );
			this.add( deleteUserFromGroup );	
			this.add( listMembers );
			this.add( logOut );				
					
			//add action listeners
			fileButton.addActionListener(this);
			newUser.addActionListener(this);
			deleteUser.addActionListener(this);
			newGroup.addActionListener(this);
			deleteGroup.addActionListener(this);
			addUserToGroup.addActionListener(this);
			deleteUserFromGroup.addActionListener(this);
			listMembers.addActionListener(this);
			logOut.addActionListener(this);
			
			//adding colors
			fileButton.setBackground(Color.lightGray);
			fileButton.setForeground(Color.yellow);
			newUser.setBackground(Color.lightGray);
			newUser.setForeground(Color.yellow);
			deleteUser.setBackground(Color.lightGray);
			deleteUser.setForeground(Color.yellow);
			newGroup.setBackground(Color.lightGray);
			newGroup.setForeground(Color.yellow);
			deleteGroup.setBackground(Color.lightGray);
			deleteGroup.setForeground(Color.yellow);
			addUserToGroup.setBackground(Color.lightGray);
			addUserToGroup.setForeground(Color.yellow);
			deleteUserFromGroup.setBackground(Color.lightGray);
			deleteUserFromGroup.setForeground(Color.yellow);
			listMembers.setBackground(Color.lightGray);
			listMembers.setForeground(Color.yellow);
			logOut.setBackground(Color.lightGray);
			logOut.setForeground(Color.yellow);
				
			setVisible(true);
		}
		
		return;
		
	}//END runMyFileClient
	
	public void actionPerformed(ActionEvent e)	//check which buttons have been hit
	{
	
		String inputName, inputGroup, groupName;
		//figure out which component was clicked
		Component whichButton = (Component) e.getSource();
		switch( whichButton.getName() )
		{
			case "fileButton":	//start a file client
			
				try
				{								
					String ipAddress = JOptionPane.showInputDialog(this, "Enter the Server Name of the File Server:");
				
					String port = JOptionPane.showInputDialog(this, "Enter the port number of " + ipAddress + ":");		
					int portNumber = Integer.parseInt(port);
					
					//Create FileClient instance 
					FileClient f_client = new FileClient();
					
					//Connect GroupClient to FileClient instance for communication
					f_client.connectGroupClient(g_client, token, ipAddress);
					
					//Verify that the FileClient has appropriately connected
					boolean hasConnectedFile = f_client.connect(ipAddress, portNumber);
		
					//Quit if user fails to connect
					if(!hasConnectedFile)
					{
						JOptionPane.showMessageDialog(this,
						"Failed to connect to the " + ipAddress + ".\n" +
						"Contact system administrator if problem persists.",
						"Error Connecting!",
						JOptionPane.ERROR_MESSAGE);		
						f_client.disconnect();	//disconnect client instead of return		
					}
					
					else	//run the code to get the file client actually running
					{
						UserToken fileToken = g_client.getFileServerToken( token, f_client.getServerPublicKey(token) );	//gets the file server token that is specific to the file server the user wants to connect to
						MyFileClientGUI fClient_UI = new MyFileClientGUI();
						fClient_UI.runMyFileClientGUI(fileToken, ipAddress, portNumber, f_client);
						//fClient_UI.runMyFileClientGUI(token, ipAddress, portNumber);	//send the group name
					}
				}
				
				catch(Exception exe)
				{
					JOptionPane.showMessageDialog(this,
					"Please enter a valid IP Address and Port Number.",
					"Error Connecting!",
					JOptionPane.ERROR_MESSAGE);
				}
				
			break;
		
			case "newUser":	//create new user for the server
				
				inputName = JOptionPane.showInputDialog(this, "Enter the name of the user to create:");
				
				// Get user password
		String password = JOptionPane.showInputDialog(this, "Enter your password: ");
		byte[] passBytes = password.getBytes();

		// Add BouncyCastle Provider
		Security.addProvider(new BouncyCastleProvider());

		// Placeholder to hold password hash
		byte[] hash = new byte[0];

		try 
		{
				
			// Declare SHA-256 hash function
			MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
			
			// Perform hash on user password
			sha256.update(passBytes);
		
			// Get user password hash
			hash = sha256.digest();

		} 
			
		catch (Exception exe) 
		{
			//ERROR message
			JOptionPane.showMessageDialog(this,
			"Something wrong happened with password...",
			"ERROR!",
			JOptionPane.ERROR_MESSAGE);
			
			System.exit(-1);
		}
				
				if(!g_client.createUser(inputName, hash, token))
				{
					JOptionPane.showMessageDialog(this,
					"Please verify the following:\n" +
					"\t- The user does not already exist on the server.\n" +
					"\t- You have the right to create users on the server.\n" +
					"Please contact system administrator if these conditions are met.",
					"Failed To Create User!",
					JOptionPane.ERROR_MESSAGE);

				}
				
				else
				{
					JOptionPane.showMessageDialog(this,
					"Successfully created user " + inputName + ".",
					"User Creation Successful!",
					JOptionPane.PLAIN_MESSAGE);
				}
				
			break;
			
			case "deleteUser":	//delete a user from the server
				
				inputName = JOptionPane.showInputDialog(this, "Enter the name of the user to delete:");		
				if(!g_client.deleteUser(inputName, token))
				{
					JOptionPane.showMessageDialog(this,
					"Please verify the following:\n" +
					"\t- The user actually exists on the server.\n" +
					"\t- You have the right to delete users on the server.\n" +
					"Please contact system administrator if these conditions are met.",
					"Failed To Delete User!",
					JOptionPane.ERROR_MESSAGE);
				}
				
				else
				{
					JOptionPane.showMessageDialog(this,
					"Successfully deleted user " + inputName + ".",
					"User Deletion Successful!",
					JOptionPane.PLAIN_MESSAGE);
				}
				
			break;
			
			case "newGroup":	//create a new group on the server
			
				inputGroup = JOptionPane.showInputDialog(this, "Enter the name of the group to create:");
				if(!g_client.createGroup(inputGroup, token))
				{
					JOptionPane.showMessageDialog(this,
					"Please verify the following:\n" +
					"\t- The group does not already exist on the server.\n" +
					"\t- You have the right to create groups on the server.\n" +
					"Please contact system administrator if these conditions are met.",
					"Failed To Create New Group!",
					JOptionPane.ERROR_MESSAGE);
				}
				
				else
				{
					JOptionPane.showMessageDialog(this,
					"Successfully created group " + inputGroup + ".",
					"Group Creation Successful!",
					JOptionPane.PLAIN_MESSAGE);
				}
			
			break;
			
			case "deleteGroup":	//delete a group on the server
				
				groupName = JOptionPane.showInputDialog(this, "Enter the name of the group to delete:");
				if(!g_client.deleteGroup(groupName, token))
				{
					JOptionPane.showMessageDialog(this,
					"Please verify the following:\n" +
					"\t- The group actually exists on the server.\n" +
					"\t- You have the right to delete groups on the server.\n" +
					"Please contact system administrator if these conditions are met.",
					"Failed To Delete Group!",
					JOptionPane.ERROR_MESSAGE);
				}
				
				else
				{
					JOptionPane.showMessageDialog(this,
					"Successfully deleted group " + groupName + ".",
					"Delete Successful!",
					JOptionPane.PLAIN_MESSAGE);
				}
				
			break;
			
			case "addUserToGroup":	//add user to a group
			
				inputGroup = JOptionPane.showInputDialog(this, "Enter the name of the group to add a user to:");
				inputName = JOptionPane.showInputDialog(this, "Enter the name of the user to add to " + inputGroup + ":");
				
				if(!g_client.addUserToGroup(inputName, inputGroup, token))
				{
					JOptionPane.showMessageDialog(this,
					"Please verify the following:\n" +
					"\t- The group actually exists on the server.\n" +
					"\t- The user actually exists on the server.\n" +
					"\t- You have the right to add a user to a group on the server.\n" +
					"Please contact system administrator if these conditions are met.",
					"Failed to add user " + inputName + " to group " + inputGroup + "!",
					JOptionPane.ERROR_MESSAGE);
				}
				
				else
				{
					JOptionPane.showMessageDialog(this,
					"Successfully added user " + inputName + " to group " + inputGroup + ".",
					"Successfully Added User!",
					JOptionPane.PLAIN_MESSAGE);
				}
				
			break;
			
			case "deleteUserFromGroup":	//delete a user from a group
			
				inputGroup = JOptionPane.showInputDialog(this, "Enter the name of the group to delete a user from:");
				inputName = JOptionPane.showInputDialog(this, "Enter the name of the user to delete from " + inputGroup + ":");
				
				if(!g_client.deleteUserFromGroup(inputName, inputGroup, token))
				{
					JOptionPane.showMessageDialog(this,
					"Please verify the following:\n" +
					"\t- The group actually exists on the server.\n" +
					"\t- The user actually exists on the server.\n" +
					"\t- You have the right to delete a user from a group on the server.\n" +
					"Please contact system administrator if these conditions are met.",
					"Failed to delete user " + inputName + " from group " + inputGroup + "!",
					JOptionPane.ERROR_MESSAGE);
				}
				
				else
				{
					JOptionPane.showMessageDialog(this,
					"Successfully deleted user " + inputName + " from group " + inputGroup + ".",
					"Successfully Deleted User!",
					JOptionPane.PLAIN_MESSAGE);
				}
				
			break;
			
			case "listMembers":	//list members of group
				
				groupName = JOptionPane.showInputDialog(this, "Enter the name of the group to view:");
				
				ArrayList<String> members = (ArrayList)g_client.listMembers(groupName, token);
				
				if(members == null)
				{
					JOptionPane.showMessageDialog(this,
					"Please verify the following:\n" +
					"\t- The group actually exists on the server.\n" +
					"\t- You are the owner of group " + groupName + ".\n" +
					"Please contact system administrator if these conditions are met.",
					"Failed to retrieve users in group " + groupName + "!",
					JOptionPane.ERROR_MESSAGE);
				}
				
				else
				{
					
					String memberString = "";
					for(String member : members)
					{
						memberString = memberString + member + "\n";
					}
					
					JOptionPane.showMessageDialog(this, 
							memberString,
							groupName + " Members",
							JOptionPane.PLAIN_MESSAGE);

				}
				
			break;
			
			case "logOut":	//log out by closing the program
				
				/*g_client.disconnect();
				
				java.awt.Window win[] = java.awt.Window.getWindows(); 
				for(int i=0;i<win.length;i++)
				{ 
					if(win[i].isFocused())
					{
						win[i].dispose(); 
						break;
					}
				} Ryan's code: probably do not need for now since we just go to this menu first*/
				
				System.exit(0);				
			break;
			
			default:	//error, should never come here
				JOptionPane.showMessageDialog(this,
				"A Button was clicked incorrectly.",
				"ERROR",
				JOptionPane.ERROR_MESSAGE);
		}
	}			
	
}
