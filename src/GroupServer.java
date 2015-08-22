/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file.
 */

/*
 * TODO: This file will need to be modified to save state related to
 *       groups that are created in the system
 *
 */

import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.util.*;

/* cryptography libraries */
import java.security.*;
import javax.crypto.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GroupServer extends Server {

	public static final int SERVER_PORT = 8765;
	public UserList userList;
	public GroupList groupList;
	public GroupFileList groupKeyList;

	public GroupServer() {
		super(SERVER_PORT, "ALPHA");
	}

	public GroupServer(int _port) {
		super(_port, "ALPHA");
	}

	public void start() {
		// Overwrote server.start() because if no user file exists, initial admin account needs to be created

		String userFile = "UserList.bin";
		String groupFile = "GroupList.bin";
		String groupKeyFile = "GroupKeyList.bin";
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;
        ObjectInputStream groupKeyStream;

		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));

		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);
			userList = (UserList)userStream.readObject();
		}
		catch(FileNotFoundException e)
		{

			System.out.println("UserList File Does Not Exist. Creating UserList...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Enter your username: ");
			String username = console.next();

			// Get new user password
			String password = new String(System.console().readPassword("Enter your password: "));

			// ensures user doesn't enter a 0 length password
			while(password.length() == 0) {
				System.out.println("\nError: No password entered.");
				password = new String(System.console().readPassword("Please enter your password: "));
			}

			byte[] passBytes = password.getBytes();

			// Add BouncyCastle Provider
			Security.addProvider(new BouncyCastleProvider());

			// Declare byte array to hold hash
			byte[] hash = new byte[0];

			try {

				// Declare SHA-256 hash function
				MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
			
				// Perform hash on user password
				sha256.update(passBytes);
			
				// Get user password hash
				hash = sha256.digest();

			} catch (Exception e2) {
				System.out.println("Error hashing user password.");
				System.exit(-1);
			}
			
			//to create a new rsa key pair and save them to two different files
			try
			{
				//create a RSA Key pair(FOR T2)
				KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
				KeyPair rsaPair = pairGenerator.generateKeyPair();	

				//save public key to a file
				byte[] pubKey = rsaPair.getPublic().getEncoded();
				FileOutputStream pubKeyFile = new FileOutputStream("groupPubKey.txt");
				pubKeyFile.write(pubKey);
				pubKeyFile.close();
			
				//save private key to a file
				byte[] privKey = rsaPair.getPrivate().getEncoded();
				FileOutputStream privKeyFile = new FileOutputStream("groupPrivKey.txt");
				privKeyFile.write(privKey);
				privKeyFile.close();
			}
		
			catch(Exception exe)
			{
				System.out.println("Error creating RSA Key Pair");
				System.exit(-1);
			}

			//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
			userList = new UserList();
			userList.addUser(username, hash);
			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");
		}
		catch(IOException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}

		try
		{
			FileInputStream fis2 = new FileInputStream(groupFile);
			groupStream = new ObjectInputStream(fis2);
			groupList = (GroupList)groupStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("GroupList File Does Not Exist. Creating GroupList...");

			groupList = new GroupList();
		}
		catch(IOException e)
		{
			System.out.println("Error reading from GroupList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from GroupList file");
			System.exit(-1);
		}

	    //Retrieve the groupKeyList for holding AES keys per file
        try
          {
              FileInputStream fis3 = new FileInputStream(groupKeyFile);
              groupKeyStream = new ObjectInputStream(fis3);
              groupKeyList = (GroupFileList)groupKeyStream.readObject();
              //System.out.println("READING GROUP KEY LIST IN");
              //System.out.println(groupKeyList);
          }
          catch(FileNotFoundException e)
          {
              System.out.println("GroupKeyList File Does Not Exist. Creating GroupKeyList...");
              groupKeyList = new GroupFileList();
              groupKeyList.addGroupToTable("ADMIN");
          }
          catch(IOException e)
          {
              System.out.println("Error reading from GroupKeyList file");
              System.exit(-1);
          }
          catch(ClassNotFoundException e)
          {
              System.out.println("Error reading from GroupKeyList file");
              System.exit(-1);
          }
		
		//Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();

		//This block listens for connections and creates threads on new connections
		try
		{

			final ServerSocket serverSock = new ServerSocket(port);

			Socket sock = null;
			GroupThread thread = null;

			while(true)
			{
				sock = serverSock.accept();
				thread = new GroupThread(sock, this);
				thread.start();
			}
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}

	}

}

//This thread saves the user list
class ShutDownListener extends Thread
{
	public GroupServer my_gs;

	public ShutDownListener (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;
		ObjectOutputStream outStream2;
		ObjectOutputStream outStream3;

		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			outStream.writeObject(my_gs.userList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}

		try
		{
			outStream2 = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
			outStream2.writeObject(my_gs.groupList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		
        try
        {
            outStream3 = new ObjectOutputStream(new FileOutputStream("GroupKeyList.bin"));
            outStream3.writeObject(my_gs.groupKeyList);
        }
        catch(Exception e)
        {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }

	}
}

class AutoSave extends Thread
{
	public GroupServer my_gs;

	public AutoSave (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave group and user lists...");
				ObjectOutputStream outStream;
				ObjectOutputStream outStream2;
				ObjectOutputStream outStream3;
				
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
					outStream.writeObject(my_gs.userList);
                    
                    outStream2 = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
                    outStream.writeObject(my_gs.groupList);
                    
                    outStream3 = new ObjectOutputStream(new FileOutputStream("GroupKeyList.bin"));
                    outStream.writeObject(my_gs.groupKeyList);
				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}

			}
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}
		} while(true);
	}
}
