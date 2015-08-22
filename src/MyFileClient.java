
import java.util.Scanner;
import java.util.List;
import java.util.HashMap;
import java.io.*;
import java.security.*;
import java.util.ArrayList;


public class MyFileClient {

	FileClient f_client;
	PublicKey servPubKey;
	static String fsListFile = "trustedFileServers.txt";

	public void runMyFileClient(UserToken token, String serverName, int serverPort, FileClient created_client)
	{
		
		Scanner kbd = new Scanner(System.in);
		boolean displayMenu = true;
				
		/*boolean hasConnected = f_client.connect(serverName, serverPort);
		
		//Quit if user fails to connect
		if(!hasConnected)
		{
			System.out.println("\nFailed to connect to the File Server.\n" +
								"Contact system administrator if problem persists.");
			return;			
		}
		
        //Retrieve the file servers public key from file server
		servPubKey = f_client.getServerPublicKey(token);	*/

		//set the f_client and get the public key
		FileClient f_client = created_client;
		servPubKey = token.getPublicKey();
		
        //Create new file server object 
		FileServerID currentFS = new FileServerID(serverName, serverPort, servPubKey);
		
        //Retrieve all trusted file servers client has connected to previously
		ArrayList<FileServerID> trustedServers = parseTrustedServers();

/*
		//DEBUG
		for(FileServerID fs : trustedServers)
		{
		    System.out.println("Server: "+ fs.getAddress() + " " + fs.getPort());
		    System.out.println(createThumbprint(fs.getKey().getEncoded()));
		}
*/
		
        //Check if client has connected to file server once before
		if(currentFS.isTrustedServer(trustedServers))
		{
		    System.out.println("File Server at "+serverName+" authorized.");
		}
		else
		{
            //If first time connecting: verify that they trust file servers public key
		    if(!acceptPublicKey(servPubKey))
		    {
                //Client doesn't trust file server
		        System.out.println("Session terminated.\n");
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
		            System.out.println("File Server trusted.  Added to list of trusted servers.");
		            
		        }
		        catch(Exception e)
		        {
		            System.out.println("Error when adding "+serverName+" to the list of trusted servers.");
		        }
		        
		    }
		}
		
		//Verify that a secure channel can be obtained so encrypted communications can take place
		if(!f_client.obtainSecureChannel(servPubKey, token))
		{
		    System.out.println("Could not establish a secure connection.");
		    return;
		}

		do
		{
			int menuChoice = -1;
			
			System.out.print("\n________________________\n"+
							"\n~~~ FILE SERVER MENU ~~~\n" +
							"1: List files on " + serverName + "\n" +
							"2: Upload file to " + serverName + "\n" +
							"3: Download file from " + serverName + "\n"+
							"4: Delete file from " + serverName + "\n"+
							"5: Terminate connection\n"+
							"Enter the menu numbers :"+
							"  >> ");
			
			try
			{
				menuChoice = Integer.parseInt(kbd.next());
				
			}
			catch(Exception justAnotherReallyLongVariableNameLOL)
			{
				menuChoice = -1;
			}
			
			//If input acceptable: execute choice
			if(menuChoice == 1) //List files on server
			{	
				List<String> filesOnServer = f_client.listFiles(token);
				
				if(filesOnServer == null)
				{
					System.out.println("\nERROR: Failed to retrieve list of files on File Server at " + serverName + ".\n" +
										"Please verify the following:\n" +
										"\t- There exists files on this file server.\n" +
										"\t- You have access to such files existing on this file server.\n" +
										"Please contact system administrator if these conditions are met.\n");
				}
				else if(filesOnServer.isEmpty())
				{
					System.out.println("There are no files existing in which you have access to.\n");
				}
				else
				{
					System.out.print("\nFiles accessible by " + token.getSubject() + ":\n");
					
					for(String file : filesOnServer)
					{
						System.out.print(file + "\n");					
					}
					
					System.out.println();
				}

			}
			else if(menuChoice == 2) //Upload file to server
			{
				
				System.out.println("\n\n~~~ Upload File to Server ~~~");
				
				System.out.print("\nPlease enter which group to upload the file to: \n" +
								"  >> ");
				String inputGroup = kbd.next();
				
				System.out.print("\nPlease enter the full path of file to upload to " + inputGroup + ": \n" +
								"  >> ");
				String sourceFile = kbd.next();
				
				System.out.print("\nPlease enter the name for file to be called on server: \n" +
						"  >> ");
				String destFile = kbd.next();
				
				if(!f_client.upload(sourceFile, destFile, inputGroup, token))
				{
					System.out.println("\nERROR: Failed to upload file to " + inputGroup + ".\n" +
										"Please verify the following:\n" +
										"\t- The group actually exists on the server.\n" +
										"\t- The file being uploaded exists on local file system.\n" +
										"\t- The file being uploaded does not already exist on file server.\n" +
										"\t- You have the right to upload a file to group " + inputGroup + " on the server.\n" +
										"Please contact system administrator if these conditions are met.\n");
				}
				else
				{
					System.out.println("\nSuccessfully uploaded specified file to group " + inputGroup + ".\n" +
										" -From local location: "+ sourceFile + "\n" +
										" -To server location: " + destFile + "\n");
				}

			}
			else if(menuChoice == 3) //Download file from server
			{
				System.out.println("\n\n~~~ Download File from Server ~~~");
				
				System.out.print("\nPlease enter the name of the file you wish to download : \n" +
								"  >> ");
				String sourceFile = kbd.next();
				
				System.out.print("\nPlease enter the full path of the location you wish to download the file to : \n" +
					"  >> ");
				String destFile = kbd.next();
				
				if(!f_client.download(sourceFile, destFile, token))
				{
					System.out.println("\nERROR: Failed to download file: " + sourceFile + ".\n" +
										"Please verify the following:\n" +
										"\t- The file being downloaded exists on the file server.\n" +
										"\t- The file being downloaded does not already exist on your system.\n" +
										"\t- You have the right to download the file from the server.\n" +
										"Please contact system administrator if these conditions are met.\n");
				}
				else
				{
					System.out.println("\nSuccessfully downloaded specified file: " + sourceFile + ".\n" +
										" -From server location: "+ sourceFile + "\n" +
										" -To local location: " + destFile + "\n");
				}

				//.download(String sourceFile, String destFile, UserToken token)
				//Allows owner of token to download specified file IF member of group
				//in which file is shared
			}
			else if(menuChoice == 4) //Delete file from server
			{

				System.out.println("\n\n~~~ Delete File from Server ~~~");

				System.out.print("\nPlease enter the filename of the file you wish to delete: \n" +
								"  >> ");
				String filename = kbd.next();

				if(!f_client.delete(filename, token)) {
					System.out.println("ERROR: Failed to delete file: " + filename + ".\n" +
										"Please verify the following:\n" +
										"\t- The file actually exists on the server.\n" +
										"\t- You have the right to delete the file from the server.\n" +
										"Please contact system administrator if these conditions are met.\n");
				} else {
					System.out.println("\nSuccessfully deleted specified file: " + filename + ".\n");
				}
			}
			else if(menuChoice == 5) //Terminate connection
			{
				displayMenu = false;
				System.out.println("Goodbye!!");
				f_client.disconnect();
			}
			else
			{
				System.out.println("\nInvalid input: Please enter appropriate number from the menu.");	
			}
			
			
		}while(displayMenu);
		
				
	}//END runMyFileClient
		
	//Check if user will accept file server public key
	private boolean acceptPublicKey(PublicKey pk)
	{
	    System.out.println("The server's host key is not cached.  You have no gaurantee that" +
	                        " the file server is the computer you think it is." +
	                        "The server's RSA key fingerprint is:");

	    System.out.println(createThumbprint(pk.getEncoded()));
	    System.out.println("\nDo you trust this server? (y/n)");
	    
	    Scanner kb = new Scanner(System.in);
	    String input;
	    do
	    {
	        input = kb.nextLine().toLowerCase();
	        
	        if(!input.equals("y") && !input.equals("n"))
	        {
	            System.out.println("Please press 'y' to answer Yes and 'n' to answer No.");
	        }
	    }while(!input.equals("y") && !input.equals("n"));
	    
	    if(input.equals("y"))
	    {
	        return true;
	    }
	    else
	    {
	        return false;
	    }
	}

    //Create readable hex thumbprint to display to user
    public static String createThumbprint(byte[] byteText)
    {
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[byteText.length * 2];

        for(int i = 0; i < byteText.length; i++)
        {
            int v = byteText[i] & 0xFF;
            hexChars[i * 2] = hexArray[v >>> 4];
            hexChars[i * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
        
    }
    
    //Parse file for trusted file servers
    public static ArrayList<FileServerID> parseTrustedServers()
    {
        ArrayList<FileServerID> trustedServers = new ArrayList<FileServerID>();
        
        try
        {
            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream(fsListFile));
            Object obj = null;
            
            while((obj = inputStream.readObject()) != null)
            {
                if(obj instanceof FileServerID)
                {
                    trustedServers.add((FileServerID)obj);
                }
            }
            return trustedServers;
        }
        catch(Exception e)
        {
            return trustedServers;
        }

    }
	
	
}
