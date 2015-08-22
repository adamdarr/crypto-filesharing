/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

import java.security.*;
import javax.crypto.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class FileServer extends Server {
	
	public static final int SERVER_PORT = 4321;
	public static FileList fileList;
	
	//private KeyPair keys = null;
	private PublicKey fsPublicKey;     //Holds file servers public key
	private PrivateKey fsPrivateKey;   //Holds file servers private key
	
	public FileServer() {
		super(SERVER_PORT, "FilePile");
	}

	public FileServer(int _port) {
		super(_port, "FilePile");
	}
	
	public void start() {
        // Add BouncyCastle Provider
        Security.addProvider(new BouncyCastleProvider());
	    
	    //Retrieve RSA keys if generated or create new key pair if they have not been generated
	    try
	    {
	        ObjectInputStream getPubKey = new ObjectInputStream(new FileInputStream("fileServPubKey.txt"));
	        ObjectInputStream getPrivKey = new ObjectInputStream(new FileInputStream("fileServPrivKey.txt"));
	        
	        fsPublicKey = (PublicKey)getPubKey.readObject();
	        fsPrivateKey = (PrivateKey)getPrivKey.readObject();
	        
	        getPubKey.close();
	        getPrivKey.close();
	    }
	    catch(Exception e)
	    {
	        //Something went wrong or RSA keypair never generated.
	        //Generate new RSA keypair
	        System.out.println("Generating new RSA key pair for File Server");
	        
	        //Generate new RSA key pair and store locally
	        try{
	            KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
	            pairGenerator.initialize(4096);
	            KeyPair rsaPair = pairGenerator.generateKeyPair();
	            
	            //Store the newly created keys
	            fsPrivateKey = rsaPair.getPrivate();
	            fsPublicKey = rsaPair.getPublic();
	            
	            //Print the keys to a file for safe keeping
	            ObjectOutputStream setPubKey = new ObjectOutputStream(new FileOutputStream("fileServPubKey.txt"));
	            ObjectOutputStream setPrivKey = new ObjectOutputStream(new FileOutputStream("fileServPrivKey.txt"));
	            
	            setPubKey.writeObject(fsPublicKey);
	            setPrivKey.writeObject(fsPrivateKey);
	            
	            setPubKey.close();
	            setPrivKey.close();	            
	        }
	        catch(Exception ee)
	        {
	            System.out.println("ERROR: File Server failed to generate session keys.");
	        }
	        
	    }
	    
		String fileFile = "FileList.bin";
		ObjectInputStream fileStream;
		
		
		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		Thread catchExit = new Thread(new ShutDownListenerFS());
		runtime.addShutdownHook(catchExit);
		
		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(fileFile);
			fileStream = new ObjectInputStream(fis);
			fileList = (FileList)fileStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("FileList Does Not Exist. Creating FileList...");
			
			fileList = new FileList();
			
		}
		catch(IOException e)
		{
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		}
		
		File file = new File("shared_files");
		 if (file.mkdir()) {
			 System.out.println("Created new shared_files directory");
		 }
		 else if (file.exists()){
			 System.out.println("Found shared_files directory");
		 }
		 else {
			 System.out.println("Error creating shared_files directory");				 
		 }
		
		//Autosave Daemon. Saves lists every 5 minutes
		AutoSaveFS aSave = new AutoSaveFS();
		aSave.setDaemon(true);
		aSave.start();
		
		
		boolean running = true;
		
		try
		{			
			final ServerSocket serverSock = new ServerSocket(port);
			System.out.printf("%s up and running\n", this.getClass().getName());
			
			Socket sock = null;
			Thread thread = null;
			
			while(running)
			{
				sock = serverSock.accept();
				thread = new FileThread(sock);
				thread.start();
			}
			
			System.out.printf("%s shut down\n", this.getClass().getName());
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

//This thread saves user and group lists
class ShutDownListenerFS implements Runnable
{
	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;

		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
			outStream.writeObject(FileServer.fileList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSaveFS extends Thread
{
	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave file list...");
				ObjectOutputStream outStream;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
					outStream.writeObject(FileServer.fileList);
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
		}while(true);
	}
}
