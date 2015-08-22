
import java.util.Scanner;
import java.util.List;

/* cryptography libraries */
import java.security.*;
import javax.crypto.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class MyGroupClient {

	GroupClient g_client;

	public MyGroupClient(GroupClient client) {
		g_client = client;
	}
	
	public void runMyGroupClient(UserToken token)
	{
		Scanner kbd = new Scanner(System.in);
		boolean displayMenu = true;
		
		boolean hasConnected = true;
		//g_client.connect(serverName, serverPort);

		//System.out.println(g_client.isSessionKeySet());
		
		//Quit if user fails to connect
		if(!hasConnected)
		{
			System.out.println("\nFailed to connect to the Group Server.\n" +
								"Contact system administrator if problem persists.");
			return;			
		}
		
		do
		{
			int menuChoice = -1;
			
			System.out.print("\n_________________\n");
			System.out.print("\n~~~ MAIN MENU ~~~\n" +
							"1: Connect to a File Server\n" +
							"2: Create a new user\n" +
							"3: Delete an existing user\n" +
							"4: Create a new group\n"+
							"5: Delete an existing group\n"+
							"6: Add a user to a group\n"+
							"7: Delete a user from a group\n"+
							"8: List the members of a group\n"+
							"9: Logout\n"+
							"Enter the menu numbers :"+
							" >> ");
			
			try
			{
				menuChoice = Integer.parseInt(kbd.next());
				
			}
			catch(Exception justAnotherReallyLongVariableNameLOL)
			{
				menuChoice = -1;
			}
			
			if(menuChoice == 1)	//connect to a file server
			{
				try
				{
					System.out.print("\n\nPlease enter the Server Name of the File Server.\n" +
									"  >> ");
					String ipAddress = kbd.next();
				
					System.out.print("\nPlease enter the port number of the File Server.\n" +
									"  >> ");

					int portNumber = Integer.parseInt(kbd.next());
					
					System.out.print("\nInitializing connection to file server at the following: \n" +
							"IP Address: " + ipAddress + "\n" + 
							"Port Number: " + portNumber + "\n");
							
					//Create a FileClient instance
					FileClient f_client = new FileClient();
					
					//Connect the GroupClient instance to the FileClient instance for communication
					f_client.connectGroupClient(g_client, token, ipAddress);
					
					//Verify that the FileClient has appropriately connected
					boolean hasConnectedFile = f_client.connect(ipAddress, portNumber);			

					//Quit if user fails to connect
					if(!hasConnectedFile)
					{
						System.out.println("\nFailed to connect to the File Server.\n" +
									"Contact system administrator if problem persists.");
						f_client.disconnect();	//disconnect client instead of return			
					}
					else	//run the code to get the file client actually running
					{
						UserToken fileToken = g_client.getFileServerToken( token, f_client.getServerPublicKey(token) );	//gets the file server token that is specific to the file server the user wants to connect to
						MyFileClient fClient_UI = new MyFileClient();
						fClient_UI.runMyFileClient(fileToken, ipAddress, portNumber, f_client);
						//fClient_UI.runMyFileClient(token, ipAddress, portNumber);
					}
		
				}
				catch(Exception e)
				{
					System.out.println("Please enter a valid IP Address and Port Number.");
				}
			}
			
			//If input acceptable: execute choice
			else if(menuChoice == 2) //Create new user
			{	
				System.out.println("\n\n~~~ User Creation ~~~");
				System.out.print("\nPlease enter the name of the user to create: \n" +
								"  >> ");
				String inputName = kbd.next();

				// Get user password
				String password = new String(System.console().readPassword("\nPlease enter the password for the user you wish to create: \n" +
								"  >> "));

				// ensures user doesn't enter a 0 length password
				while(password.length() == 0) {
					System.out.println("\nError: No password entered.");
					password = new String(System.console().readPassword("Please enter the password for the user you wish to create: \n" +
								"  >> "));
				}

				byte[] passBytes = password.getBytes();

				// Add BouncyCastle Provider
				Security.addProvider(new BouncyCastleProvider());

				// Declare hash placeholder
				byte[] hash = new byte[0];

				try {
				
					// Declare SHA-256 hash function
					MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
			
					// Perform hash on user password
					sha256.update(passBytes);
			
					// Get user password hash
					hash = sha256.digest();

				} catch (Exception e) {
					System.out.println("Error hashing user password.");
					System.exit(-1);
				}
				
				if(!g_client.createUser(inputName, hash, token))
				{
					System.out.println("ERROR: Failed to create new user: " + inputName + ".\n" +
										"Please verify the following:\n" +
										"\t- The user does not already exist on the server.\n" +
										"\t- You have the right to create users on the server.\n" +
										"Please contact system administrator if these conditions are met.\n");
				}
				else
				{
					System.out.println("\nSuccessfully created user " + inputName + ".\n");
				}
			}
			else if(menuChoice == 3) //Delete existing user
			{
				System.out.println("\n\n~~~ User Deletion ~~~");
				System.out.print("\nPlease enter the name of the user to delete: \n" +
								"  >> ");
				String inputName = kbd.next();
				
				if(!g_client.deleteUser(inputName, token))
				{
					System.out.println("ERROR: Failed to delete specified user: " + inputName + ".\n" +
										"Please verify the following:\n" +
										"\t- The user actually exists on the server.\n" +
										"\t- You have the right to delete users on the server.\n" +
										"Please contact system administrator if these conditions are met.\n");
				}
				else
				{
					System.out.println("\nSuccessfully deleted user " + inputName + ".\n");
				}
				
			}
			else if(menuChoice == 4) //Create new group
			{
				
				System.out.println("\n\n~~~ Group Creation ~~~");
				System.out.print("\nPlease enter the name of the group to create: \n" +
								"  >> ");
				String inputGroup = kbd.next();
				
				if(!g_client.createGroup(inputGroup, token))
				{
					System.out.println("ERROR: Failed to create new group: " + inputGroup + ".\n" +
										"Please verify the following:\n" +
										"\t- The group does not already exist on the server.\n" +
										"\t- You have the right to create groups on the server.\n" +
										"Please contact system administrator if these conditions are met.\n");
				}
				else
				{
					System.out.println("\nSuccessfully created group " + inputGroup + ".\n");
				}
				
			}
			else if(menuChoice == 5) //Delete existing group
			{
				System.out.println("\n\n~~~ Group Deletion ~~~");
				System.out.print("\nPlease enter the name of the group to delete: \n" +
								"  >> ");
				String groupName = kbd.next();
				
				if(!g_client.deleteGroup(groupName, token))
				{
					System.out.println("ERROR: Failed to delete specified group: " + groupName + ".\n" +
										"Please verify the following:\n" +
										"\t- The group actually exists on the server.\n" +
										"\t- You have the right to delete groups on the server.\n" +
										"Please contact system administrator if these conditions are met.\n");
				}
				else
				{
					System.out.println("\nSuccessfully deleted group " + groupName + ".\n");
				}
				
			}
			else if(menuChoice == 6) //Add user to a group
			{
				
				System.out.println("\n\n~~~ Add User to Group ~~~");
				
				System.out.print("\nPlease enter the name of the group to add a user to: \n" +
								"  >> ");
				String inputGroup = kbd.next();
				
				System.out.print("\nPlease enter the name of the user to add to " + inputGroup + ": \n" +
								"  >> ");
				String inputName = kbd.next();
				
				if(!g_client.addUserToGroup(inputName, inputGroup, token))
				{
					System.out.println("ERROR: Failed to add user " + inputName + " to group " + inputGroup + ".\n" +
										"Please verify the following:\n" +
										"\t- The group actually exists on the server.\n" +
										"\t- The user actually exists on the server.\n" +
										"\t- You have the right to add a user to a group on the server.\n" +
										"Please contact system administrator if these conditions are met.\n");
				}
				else
				{
					System.out.println("\nSuccessfully added user " + inputName + " to group " + inputGroup + ".\n");
				}

			}
			else if(menuChoice == 7) //Delete user from a group
			{
				
				System.out.println("\n\n~~~ Delete User from Group ~~~");
				
				System.out.print("\nPlease enter the name of the group to delete a user from: \n" +
								"  >> ");
				String inputGroup = kbd.next();
				
				System.out.print("\nPlease enter the name of the user to delete from " + inputGroup + ": \n" +
								"  >> ");
				String inputName = kbd.next();
				
				if(!g_client.deleteUserFromGroup(inputName, inputGroup, token))
				{
					System.out.println("ERROR: Failed to delete user " + inputName + " from group " + inputGroup + ".\n" +
										"Please verify the following:\n" +
										"\t- The group actually exists on the server.\n" +
										"\t- The user actually exists on the server.\n" +
										"\t- You have the right to delete a user from a group on the server.\n" +
										"Please contact system administrator if these conditions are met.\n");
				}
				else
				{
					System.out.println("\nSuccessfully deleted user " + inputName + " from group " + inputGroup + ".\n");
				}

			}
			else if(menuChoice == 8) //List the members of a group
			{
				
				System.out.println("\n\n~~~ List Users in Group ~~~");
				System.out.print("\nPlease enter the name of the group to view: \n" +
								"  >> ");
				String groupName = kbd.next();
				
				List<String> members = g_client.listMembers(groupName, token);
				
				if(members == null)
				{
					System.out.println("ERROR: Failed to retrieve users in group " + groupName + ".\n" +
										"Please verify the following:\n" +
										"\t- The group actually exists on the server.\n" +
										"\t- You are the owner of group " + groupName + ".\n" +
										"Please contact system administrator if these conditions are met.\n");
				}
				else if(members.isEmpty())
				{
					System.out.println("No members of this group exist.\n");
				}
				else
				{
					System.out.print("\nUsers in " + groupName + ":\n");
					for(String member : members)
					{
						System.out.print(member + "\n");					
					}
					
					System.out.println();
				}

			}
			else if(menuChoice == 9) //Logout
			{
				displayMenu = false;
				g_client.disconnect();
				System.out.println("\n\nGoodbye!!");
			}
			else
			{
				System.out.println("\nInvalid input: Please enter appropriate number from the menu.");	
			}
			
			
		}while(displayMenu);
		
		
		
	}//END runMyGroupClient()

}
