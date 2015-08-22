import java.util.Scanner;
import java.io.File;

/* cryptography libraries */
import java.security.*;
import javax.crypto.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class MaliciousUserInterface
{

	static GroupClient g_client = new GroupClient();
	
	public static void main(String[] args)
	{
		
		startUserInterface();
		
	}//END main()
	
	
	public static void startUserInterface()
	{
		Scanner kbd = new Scanner(System.in);
		boolean userLoggingIn = true;
				
		System.out.println("Welcome to the CS1653 Group-Based File Sharing Application");
		
		//Let user attempt to login until acceptable credentials OR user exits
		do
		{
			//Verify user would like to login
			boolean willLogin = topMenu();
			
			//If user does NOT want to login: exit
			if(!willLogin)
			{
				System.out.println("Goodbye!!");
				userLoggingIn = false;
			}
			else //User DOES want to login: proceed by getting group server info and username
			{
				String userName = "";
				UserToken token = null;
				
				System.out.print("\n\nPlease enter the Server Name of the Group Server.\n" +
						"  >> ");
				String groupServerName = kbd.next();
	
				System.out.print("\nPlease enter the Port Number of the Group Server.\n" +
						"  >> ");
				int groupPortNumber = Integer.parseInt(kbd.next());
				
				System.out.print("\nPlease enter your username: ");
				userName = kbd.next();

				// Add BouncyCastle Provider
				Security.addProvider(new BouncyCastleProvider());

				Scanner scanner = null;
				boolean passFound = false;

				try {
					scanner = new Scanner(new File("en_US.dic"));
				} catch (Exception e) {
					System.out.println("Error");
				}

				while (scanner.hasNextLine() && !passFound) {
			          String password = scanner.nextLine();

			          int index = password.indexOf('/');
			          
			          if(index != -1) {
			          	password = password.substring(0, index);
			          }

			          byte[] passBytes = password.getBytes();

					// Placeholder to hold password hash
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
					
					token = getUserToken(userName, hash, groupServerName, groupPortNumber);
					if(token == null)
					{
						System.out.println("ERROR: Username does not exist or password entered incorrectly.\n" +
											"Verify credentials were typed correctly. \n" +
											"If problem persists, contact system administrator.");
					}
					else
					{
						//TOKEN ACCEPTED: Try Connecting now
						//serverMenu(userName, token, groupServerName, groupPortNumber);
						
						try
						{					
							System.out.println("Initializing connection to the Group Server.");

							System.out.println("Username: " + userName + " Password: " + password);
										
							MyGroupClient gClient_UI = new MyGroupClient(g_client);
						
							gClient_UI.runMyGroupClient(token);

							passFound = true;
						}
						catch(Exception iLikeGivingThesePointlessNames)
						{
							System.out.println("Please enter a valid IP Address and Port Number.");
							System.exit(-1);
						}
				}

			    }
	
	
			}
			
		}while(userLoggingIn);

		
	}//END startInterface()
	
	
	/*public static void serverMenu(String username, UserToken token, String groupServerName, int groupPortNumber)
	{
		Scanner kbd = new Scanner(System.in);
		
		boolean displayMenu = true;
		
		System.out.println("\nWelcome " + username +"!!");
		
		do
		{
			int menuChoice = -1;
			
			System.out.print("\n_____________________________\n"+
							"\n~~~ SERVER SELECTION MENU ~~~\n" +
							"1: Connect to Group Server\n" +
							"2: Connect to File Server\n" +
							"3: Logout\n"+
							"Enter the menu numbers :"+
							" >> ");
			
			try
			{
				menuChoice = Integer.parseInt(kbd.next());
				
			}
			catch(Exception reallyLongVariableNameForHoldingExceptionLOL)
			{
				menuChoice = -1;
			}
			
			//If input acceptable: execute choice
			if(menuChoice == 1) //GROUP CLIENT
			{
				try
				{					
					System.out.println("Initializing connection to the Group Server.");
									
					MyGroupClient gClient_UI = new MyGroupClient();
					
					gClient_UI.runMyGroupClient(token, groupServerName, groupPortNumber);
				}
				catch(Exception iLikeGivingThesePointlessNames)
				{
					System.out.println("Please enter a valid IP Address and Port Number.");
				}
				
			}
			else if(menuChoice == 2) //FILE CLIENT
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
		
					MyFileClient fClient_UI = new MyFileClient();
		
					fClient_UI.runMyFileClient(token, ipAddress, portNumber);
		
				}
				catch(Exception e)
				{
					System.out.println("Please enter a valid IP Address and Port Number.");
				}
				
			}
			else if(menuChoice == 3) //LOGOUT
			{
				//USER CHOSE TO LOGOUT
				System.out.println("Goodbye!!");
				displayMenu = false;
			}
			else
			{
				System.out.println("\nInvalid input: Please enter appropriate number from the menu.");				
			}
			
		}while(displayMenu);
		
	}//END serverMenu()*/
	
	
	public static UserToken getUserToken(String userName, byte[] hash, String serverName, int serverPortNumber)
	{

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
	
	
	public static boolean topMenu()
	{
		Scanner kbd = new Scanner(System.in);
		
		boolean wantsToLogin = false;
		
		boolean acceptInput = true;
		int welcomeOption = -1;
		String input;
		
		do
		{
			System.out.print("\n__________________\n"+
								"\n~~~ LOGIN MENU ~~~\n"+
								"1: Login\n"+
								"2: Exit\n"+
								"Enter the menu numbers :"+
								" >> ");
			
			try
			{
				welcomeOption = Integer.parseInt(kbd.next());
				
				if(welcomeOption == 1)
				{
					//get token shit to verify dis fools login.
					wantsToLogin = true;
					acceptInput = false;
				}
				else if(welcomeOption == 2)
				{
					acceptInput = false;
				}
				else
				{
					System.out.println("Invalid input: Please enter '1'' or '2' ...");
				}
				
			}
			catch(Exception e)
			{
				System.out.println("Invalid input: Please enter '1' or '2' ...");
			}
						
		}while(acceptInput); //END do-while
		
		return wantsToLogin;	
		
	}//END topMenu()


}//END UserInterface class