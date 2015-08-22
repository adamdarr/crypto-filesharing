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

public class UserInterfaceGUI extends JFrame implements ActionListener
{

	String userName, groupServerName;
	int groupPortNumber;
	Container content;
	JButton groupButton, fileButton, logOut;
	UserToken token;
	static GroupClient g_client = new GroupClient();
	
	public static void main(String[] args) throws IOException	//start running it
	{
		UserInterfaceGUI JR = new UserInterfaceGUI();
		JR.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	}//END main()
	
	
	public UserInterfaceGUI()	throws IOException
	{
		/*Start of entrance prompts*/
		groupServerName = JOptionPane.showInputDialog(this, "Enter the Group Server name: ");
		if( groupServerName == null )	//means the did not enter something or tried to close the box
		{
			System.exit(0);
		}
		
		boolean isAString = true;	//to get a correct port number with some error checking
		while( isAString )
		{
			try 
			{
				String port = JOptionPane.showInputDialog(this, "Enter the Port Number of " + groupServerName + ": ");

				if( port == null )	//means the did not enter something or tried to close the box
				{
					System.exit(0);
				}
				
				groupPortNumber = Integer.parseInt( port );
			}
			
			catch( NumberFormatException exe )	//the number was not a number
			{
				continue;
			}
			
			isAString = false;	//get out of loop
		}
		
		//Username and password addition to login and hide password
		JPanel credentials = new JPanel( new GridLayout( 0, 1, 2, 2 ) );	//credentials for "Username" and "Password"
		credentials.add( new JLabel( "Username:", SwingConstants.RIGHT ) );
		credentials.add( new JLabel( "Password:", SwingConstants.RIGHT ) );
		
		JPanel mainPanel = new JPanel( new BorderLayout( 5, 5 ) );
		mainPanel.add( credentials, BorderLayout.WEST );

		//add the labels for login
		JPanel labels = new JPanel( new GridLayout( 0, 1, 2, 2 ) );
		
		//add username label
		JTextField userNameLabel = new JTextField();
		labels.add( userNameLabel );
		
		//add password label
		JPasswordField passwordLabel = new JPasswordField();
		labels.add( passwordLabel );
		
		mainPanel.add( labels, BorderLayout.CENTER );
		JOptionPane.showMessageDialog( new JFrame(), mainPanel, "Login", JOptionPane.QUESTION_MESSAGE );

		userName = userNameLabel.getText();
		if( userName == null )	//means the did not enter something or tried to close the box
		{
			System.exit(0);
		}

		// Get user password
		String password = new String( passwordLabel.getPassword() );
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
			
		catch (Exception e) 
		{
			//ERROR message
			JOptionPane.showMessageDialog(this,
			"Something wrong happened with password...",
			"ERROR!",
			JOptionPane.ERROR_MESSAGE);
			
			System.exit(-1);
		}
				
		token = getUserToken(userName, hash, groupServerName, groupPortNumber);
				
		//end of entrance prompts
		
		if(token == null)
		{
			//ERROR message
			JOptionPane.showMessageDialog(this,
			"Verify credentials were typed correctly.\n" +
			"If problem persists, contact system administrator.",
			"Connection Not Made!",
			JOptionPane.ERROR_MESSAGE);
		}
		
		else
		{
			//start group client
			try
			{									
				MyGroupClientGUI gClient_UI = new MyGroupClientGUI( g_client );
				
				gClient_UI.runMyGroupClientGUI(token, groupServerName, groupPortNumber);
				
				//TOKEN ACCEPTED: valid user so bring up server menu	MAYBE MOVE THIS
				JOptionPane.showMessageDialog(this,
				"Welcome " + userName + "!",
				"Credentials Are Valid!",
				JOptionPane.PLAIN_MESSAGE);
			}
			catch(Exception exe)
			{
				JOptionPane.showMessageDialog(this,
				"Please enter a valid IP Address and Port Number.",
				"Error Connecting!",
				JOptionPane.ERROR_MESSAGE);
				System.exit(-1);	//may change this
			}
		
			
			//setting up the window
			/*content = this.getContentPane();
			content.setLayout(new GridLayout(2,1));
			this.setTitle( "Main Menu" );
			setSize(225, 234);			
								
			//create buttons		
			groupButton = new JButton("Connect to Group Server");
			fileButton = new JButton("Connect to File Server");
			logOut = new JButton("Logout");
			
			//set names
			groupButton.setName("groupButton");
			fileButton.setName("fileButton");
			logOut.setName("logOut");
			
			//add buttons
			this.add( groupButton );
			this.add( fileButton );
			this.add( logOut );		
					
			//add action listeners
			groupButton.addActionListener(this);
			fileButton.addActionListener(this);
			logOut.addActionListener(this);
			
			//adding colors
			groupButton.setBackground(Color.lightGray);
			groupButton.setForeground(Color.yellow);
			fileButton.setBackground(Color.lightGray);
			fileButton.setForeground(Color.yellow);
			logOut.setBackground(Color.lightGray);
			logOut.setForeground(Color.yellow);

				
			setVisible(true);*/
		}
	}//END startInterface()
	
	public void actionPerformed(ActionEvent e)	//check which buttons have been hit
	{
		//figure out which component was clicked
		/*(Component whichButton = (Component) e.getSource();
		switch( whichButton.getName() )
		{
			case "groupButton":	//start group client
				try
				{									
					MyGroupClientGUI gClient_UI = new MyGroupClientGUI();
					
					gClient_UI.runMyGroupClientGUI(token, groupServerName, groupPortNumber);
				}
				catch(Exception exe)
				{
					JOptionPane.showMessageDialog(this,
					"Please enter a valid IP Address and Port Number.",
					"Error Connecting!",
					JOptionPane.ERROR_MESSAGE);
				}
			break;
			
			case "fileButton":	//start file client
				try
				{					
					String ipAddress = JOptionPane.showInputDialog(this, "Enter the Server Name of the File Server:");
				
					String port = JOptionPane.showInputDialog(this, "Enter the port number of " + ipAddress + ":");		
					int portNumber = Integer.parseInt(port);
					
					MyFileClientGUI fClient_UI = new MyFileClientGUI();
		
					fClient_UI.runMyFileClientGUI(token, ipAddress, portNumber);
				}
				
				catch(Exception exe)
				{
					JOptionPane.showMessageDialog(this,
					"Please enter a valid IP Address and Port Number.",
					"Error Connecting!",
					JOptionPane.ERROR_MESSAGE);
				}
			break;
			
			case "logOut":	//log out by closing the program
				System.exit(0);
			break;
			
			default:	//error, should never come here
				JOptionPane.showMessageDialog(this,
				"A Button was clicked incorrectly.",
				"ERROR",
				JOptionPane.ERROR_MESSAGE);
		}*/
	}			
	
	public static UserToken getUserToken(String userName, byte[] hash, String serverName, int serverPortNumber)
	{

		//GroupClient g_client = new GroupClient();
		g_client.connect(serverName, serverPortNumber);
		
		//Should a token exist, user exists.  Return the token
		if(g_client.isConnected())
		{			
			UserToken token = g_client.getToken(userName, hash);
			
			if(!(token == null))
			{
				//g_client.disconnect();
				return token;
			}
		}
		
		//No such user existed so return null
		g_client.disconnect();
		return null;
		
	}//END getUserToken
	

}//END UserInterface class