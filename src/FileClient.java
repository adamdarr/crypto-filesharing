/* FileClient provides all the client functionality regarding the file server */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Scanner;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.math.BigInteger;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;
import java.util.ArrayList;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;



public class FileClient extends Client implements FileClientInterface {

    private SecretKey secretKey;
	private SecretKey DHSharedKey;
    private boolean secretKeyCreated = false;

    private GroupClient gc_communicator;    // used to communicate with group client 
    private String fileServerIP;        // used to contain which file server client is connected to
    private UserToken groupToken;       // used to store the user's group token for group client communication
    private BigInteger sessionNumber;	// used to prevent replay or reorder attacks
    
    private SealedObject encryptedResponse, encryptedMessage;
    
    /*
     * This method is used to obtain a secure communication channel
     * between the client and the file server.  It will also verify 
     * to the client that it is the file server in which they expect
     * to connect to 
     */
    public boolean obtainSecureChannel(PublicKey fsPublicKey, UserToken token)
    {
        //Add BouncyCastle Provider
        Security.addProvider(new BouncyCastleProvider());
        
        SealedObject encryptedMessage, encryptedResponse;

        //Generate an AES shared session key
        try
        {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            secretKey = keyGen.generateKey();
        }
        catch(Exception e)
        {
            System.out.println("Failed to generate session key.");
            return false;
        }

        //Begin establishing secure channel with server
        try
        {
            Envelope message, response;
            
            //Tell file server to expect message encrypted with their public key
            message = new Envelope("ENC-PUB");
            output.writeObject(message);
            output.reset();
			
			//message = new Envelope("AES");
			//message.addObject( secretKey );	//add the AES key

			Cipher cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipherRSA.init(Cipher.ENCRYPT_MODE, fsPublicKey);
            byte[] encryptedKey = cipherRSA.doFinal(secretKey.getEncoded());
			
			//encrypt the AES key message with the file server public key and send it
			//encryptedMessage = encryptEnvelope( message, fsPublicKey );
			output.writeObject( encryptedKey );
			output.reset();
			
			// Intialize Diffie Hellman parameter generator
    		AlgorithmParameterGenerator generator = AlgorithmParameterGenerator.getInstance("DiffieHellman");
    		generator.init(512);
			
			// Declare and set Diffie Hellman parameters
    		AlgorithmParameters parameters = generator.generateParameters();
    		DHParameterSpec specifications = (DHParameterSpec) parameters.getParameterSpec(DHParameterSpec.class);

    		BigInteger pValue = specifications.getP();
			BigInteger gValue = specifications.getG();
			int lValue = specifications.getL();
			
			// Client generates random # a for session key handshake
    		SecureRandom random = new SecureRandom();
    		BigInteger a = new BigInteger(lValue, random);
    		BigInteger clientDH = gValue.modPow(a, pValue);	// Client performs DH MODPOW for first half a DH key to make a second key 
			
			//create message DH-CLIENT
			message = new Envelope("DH-CLIENT");	//this envelope will have keys in it
			message.addObject( clientDH );	//add the client half of the DH key
			message.addObject( token );	//add the token to help verify who they are
			message.addObject( pValue );	//add the p value
			message.addObject( gValue );	//add the g value
			message.addObject( lValue );		//ad the l value
			
			//send the token with the one half of the DH key encrypted with the AES key
			encryptedMessage = encryptEnvelope( message, secretKey );
			output.writeObject( encryptedMessage );
			output.reset();
			
			encryptedResponse = (SealedObject) input.readObject();
			response = (Envelope) decryptEnvelope( encryptedResponse, secretKey );	//get the response by decrypting the encryptedReponse with the shared AES key
            
			//create the DHShared key 
			if( response.getMessage().equals("DH-SERVER") )
			{
				if( response.getObjContents().size() == 2 )	//there should only be 2 objects in it
				{
					
					BigInteger serverDH = (BigInteger)response.getObjContents().get(0);	//gets the server part of DH
					
					if( verifyServer( (byte[])response.getObjContents().get(1), serverDH, fsPublicKey ) )	//verify if the server is who they say they are
					{
						BigInteger DHMulti = serverDH.modPow(a, pValue);	//create g^ab mod p
					
						try
						{
							MessageDigest sha256 = MessageDigest.getInstance("SHA-256");	 // Declare SHA-256 hash function
							
							sha256.update( DHMulti.toByteArray() );	//perform the hash
							
							DHSharedKey = new SecretKeySpec( sha256.digest(), "AES" );	//creates the DHShared key as AES key from the hash
						}
						
						catch(Exception e)
						{
							System.out.println("Error hashing value.");
							System.exit(-1);
						}
					}
					
					else
					{
						return false;
					}
					
				}
			}
			
			else
			{
				return false;
			}
			
			//send a challenge with DHSharedKey
            //Generate a large integer as a challenge for file server to modify
			SecureRandom rando = new SecureRandom();	//retrieve secure random
            BigInteger challenge = new BigInteger(100, rando);
            sessionNumber = challenge;
			
            byte[] encodedChallenge = null;
			try
			{
				Cipher cipher = Cipher.getInstance("AES", "BC");
				cipher.init( Cipher.ENCRYPT_MODE, DHSharedKey );
				encodedChallenge = cipher.doFinal( challenge.toByteArray() );	//encrypt the challenge with the DHShared key
			}

            catch(Exception e)
            {
                System.out.println("Failed to encrypt session key with file servers public key.");
                System.out.println("ERROR: "+ e.getMessage());
            }
            
            //Package message
            message = new Envelope("CHALLENGE");
            message.addObject( encodedChallenge );

            encryptedMessage = encryptEnvelope( message, secretKey );
			output.writeObject( encryptedMessage );      

            encryptedResponse = (SealedObject) input.readObject();	//read in the DH-CLIENT Envelope
			response = (Envelope)decryptEnvelope( encryptedResponse, secretKey );	//use the brand new AES key
            //Verify File Server sent back the challenge answer signed with its private key
            if(response.getMessage().equals("ANSWER"))
            {
                if(response.getObjContents().size() == 1)
                {
					BigInteger correctAnswer = challenge.add( new BigInteger("5") );	//create correct answer as challenge + 5
                    BigInteger actualAnswer = null;	//answer that the server sent
					
					try	//decrypt the challenge
					{
						Cipher cipher = Cipher.getInstance( "AES", "BC" );
						cipher.init( Cipher.DECRYPT_MODE, DHSharedKey );
						actualAnswer = new BigInteger(cipher.doFinal( (byte[])response.getObjContents().get( 0 ) ));

					}
	                catch(Exception e)
	                {
						System.out.println("Failed to retrieve a session key from Challenge.");
	                    System.out.println("ERROR: "+ e.getMessage());
	                         
					}
					
					if( correctAnswer.equals( actualAnswer ) )
					{
						return true;	//finally able to obtain a secure channel
					}
					
					else
					{
						return false;
					}
				}
				
				else
				{
					return false;
				}
            }
            else
            {
                System.out.println("Could not verify challenge completion.");
				return false;
            }
            
        }
        catch(Exception e)
        {
            System.out.println("Failed to obtain shared session key.");
        }
        
        return false;
    }
    
    //Used to establish communication with the GroupClient
    public void connectGroupClient(GroupClient gc, UserToken gToken, String fileserver)
    {
        gc_communicator = gc;
        groupToken = gToken;
        fileServerIP = fileserver;
        
        System.out.println("CONNECTING GROUP CLIENT TO FILE CLIENT");
        System.out.println("Group Server:" + groupToken.getSubject());
        System.out.println("File Server:" + fileServerIP);
    }
    
	public boolean delete(String filename, UserToken token) {
		String remotePath;
		if (filename.charAt(0)=='/') {
			remotePath = filename.substring(1);
		}
		else {
			remotePath = filename;
		}
        try {		
            //Tell file server to expect messaeg encrypted with their public key
            Envelope message = new Envelope("ENC-SEC");
            output.writeObject(message);
            output.reset();

            // Increment session number
			sessionNumber = sessionNumber.add(BigInteger.ONE);
    
    		Envelope env = new Envelope("DELETEF"); //Success
    	    env.addObject(remotePath);
    	    env.addObject(token);

    	    // Compute HMAC
			byte[] hmac = hmac(env);

			// Add hmac to object
			env.addObject(hmac);

            // Encrypt message and write to server
            encryptedMessage = encryptEnvelope(env, secretKey);
            output.writeObject(encryptedMessage);
            output.reset();
            
            //Get the response from the server
            encryptedResponse = (SealedObject)input.readObject();
            env = (Envelope) decryptEnvelope(encryptedResponse, secretKey);

            // Increment session number
			sessionNumber = sessionNumber.add(BigInteger.ONE);

			// takes hmac of envelope without hmac on the end
			hmac = hmac(recreateEnv(env));
		    
			if (env.getMessage().compareTo("OK")==0) {
				if(env.getObjContents().size() != 1) {
					System.out.println("Error: Response too short.");
					return false;
				} else {
					byte[] serverHmac = (byte[]) env.getObjContents().get(0);
					if(!MessageDigest.isEqual(serverHmac, hmac)) {
						System.out.println("Error performing request: HMACs don't match.");
						return false;
					} else {
						System.out.printf("File %s deleted successfully\n", filename);
						return true;
					}
				}				
			}
			else {
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}			
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		} catch (Exception e1) {
			e1.printStackTrace();
		}
	    	
		return true;
		
	}

	public boolean download(String sourceFile, String destFile, UserToken token) {

	    if (sourceFile.charAt(0)=='/') {
	        sourceFile = sourceFile.substring(1);
	    }

	    File file = new File(destFile);
	    try {
	        //Tell file server to expect messaeg encrypted with their public key
            Envelope message = new Envelope("ENC-SEC");
	        output.writeObject(message);
	        output.reset();

	        // Increment session number
			sessionNumber = sessionNumber.add(BigInteger.ONE);

	        if (!file.exists()) {
	            file.createNewFile();
	            FileOutputStream fos = new FileOutputStream(file);

	            Envelope env = new Envelope("DOWNLOADF"); //Success
	            env.addObject(sourceFile);
	            env.addObject(token);

	             // Compute HMAC
				byte[] hmac = hmac(env);

				// Add hmac to object
				env.addObject(hmac);

	            encryptedMessage = encryptEnvelope(env, secretKey);
	            output.writeObject(encryptedMessage);
	            output.reset();

	            encryptedResponse = (SealedObject)input.readObject();
	            env = (Envelope) decryptEnvelope(encryptedResponse, secretKey);

	            // Increment session number
				sessionNumber = sessionNumber.add(BigInteger.ONE);

				// takes hmac of envelope without hmac on the end
				hmac = hmac(recreateEnv(env));

				byte[] serverHmac = (byte[]) env.getObjContents().get(2);

				if(!MessageDigest.isEqual(serverHmac, hmac)) {
					System.out.println("Error performing request: HMACs don't match.");
					System.out.println("here1");
					return false;
				}
				
				//Contact the Group Client so that it may retrieve an AES key from the server
                byte[][] AESinfo = gc_communicator.retrieveFileEncryptKey((ArrayList<String>)groupToken.getGroups(), sourceFile, fileServerIP, "download", groupToken);          
                SecretKey AESkey = null;
                IvParameterSpec IV = null;
                
                //Build the SecretKey and IvParameterSpec for decryption
                try
                {
                    AESkey = new SecretKeySpec(AESinfo[0], 0, AESinfo[0].length, "AES");
                    IV = new IvParameterSpec(AESinfo[1]);
                }
                catch(Exception eee)
                {
                    System.out.println("Failed to retrieve file encryption key from Group Server.");
                }

	            while (env.getMessage().compareTo("CHUNK")==0) { 
	                   //Decrypt THE FILE CHUNK
                    byte[] chunk = decryptChunk((byte[])env.getObjContents().get(0), AESkey, IV);
                    
	                fos.write(chunk, 0, (Integer)env.getObjContents().get(1));
	                //fos.write((byte[])env.getObjContents().get(0), 0,(Integer)env.getObjContents().get(1) );
	                System.out.printf(".");
	                env = new Envelope("DOWNLOADF"); //Success

	                // Increment session number
					sessionNumber = sessionNumber.add(BigInteger.ONE);

					// Compute HMAC
					hmac = hmac(env);

					// Add hmac to object
					env.addObject(hmac);

	                encryptedMessage = encryptEnvelope(env, secretKey);
	                output.writeObject(encryptedMessage);
	                output.reset();

	                encryptedResponse = (SealedObject)input.readObject();
	                env = (Envelope) decryptEnvelope(encryptedResponse, secretKey);

	                // Increment session number
					sessionNumber = sessionNumber.add(BigInteger.ONE);

					// takes hmac of envelope without hmac on the end
					hmac = hmac(recreateEnv(env));	

					serverHmac = (byte[]) env.getObjContents().get(env.getObjContents().size() - 1);

					if(!MessageDigest.isEqual(serverHmac, hmac)) {
						System.out.println("Error performing request: HMACs don't match.");
						return false;
					}	

	            }										
	            fos.close();

	            if(env.getMessage().compareTo("EOF")==0) {
	                fos.close();
	                System.out.printf("\nTransfer successful file %s\n", sourceFile);
	                env = new Envelope("OK"); //Success

	                // Increment session number
					sessionNumber = sessionNumber.add(BigInteger.ONE);

		            // Compute HMAC
					hmac = hmac(env);

					// Add hmac to object
					env.addObject(hmac);

	                encryptedMessage = encryptEnvelope(env, secretKey);
	                output.writeObject(encryptedMessage);
	                output.reset();
	            }
	            else {
	                System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
	                file.delete();
	                return false;								
	            }
	        }    

	        else {
	            System.out.printf("Error couldn't create file %s\n", destFile);
	            return false;
	        }


	    } catch (IOException e1) {

	        System.out.printf("Error couldn't create file %s\n", destFile);
	        return false;


	    }
	    catch (ClassNotFoundException e1) {
	        e1.printStackTrace();
	    } catch (Exception e1) {
	    	e1.printStackTrace();
	    }
	    return true;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token) {
		 try
		 {
			 Envelope message = null, e = null;
			 
			 //Tell file server to expect messaeg encrypted with their public key
	         message = new Envelope("ENC-SEC");
			 output.writeObject(message);
			 output.reset();

			 // Increment session number
			sessionNumber = sessionNumber.add(BigInteger.ONE);
	            
			 //Tell the server to return the member list
			 message = new Envelope("LFILES");
			 message.addObject(token); //Add requester's token

			 // Compute HMAC
			byte[] hmac = hmac(message);

			// Add hmac to object
			message.addObject(hmac);

	        encryptedMessage = encryptEnvelope(message, secretKey);
	        output.writeObject(encryptedMessage);
	        output.reset();
			 
	        encryptedResponse = (SealedObject)input.readObject();
	        e = (Envelope) decryptEnvelope(encryptedResponse, secretKey);

	        // Increment session number
			sessionNumber = sessionNumber.add(BigInteger.ONE);

			// takes hmac of envelope without hmac on the end
			hmac = hmac(recreateEnv(e));
	            
			 //If server indicates success, return the member list
			 if(e.getMessage().equals("OK"))
			 { 
			 	if(e.getObjContents().get(0) != null) {
					if(e.getObjContents().get(1) != null) {
						byte[] serverHmac = (byte[]) e.getObjContents().get(1);
						if(!MessageDigest.isEqual(serverHmac, hmac)) {
							System.out.println("Error performing request: HMACs don't match.");
							return null;
						} else {

							return (List<String>)e.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
						}
			 		}
			 	}
			 }
				
			 return null;
			 
		 }
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	}

	public boolean upload(String sourceFile, String destFile, String group, UserToken token) {
			
		if (destFile.charAt(0)!='/') {
			 destFile = "/" + destFile;
		 }
		
		try
		 {
			 
			 Envelope message = null, env = null;

			 //Tell file server to expect messaeg encrypted with their public key
	         message = new Envelope("ENC-SEC");
			 output.writeObject(message);
			 output.reset();

			 // Increment session number
			sessionNumber = sessionNumber.add(BigInteger.ONE);

			 //Tell the server to return the member list
			 message = new Envelope("UPLOADF");
			 message.addObject(destFile);
			 message.addObject(group);
			 message.addObject(token); //Add requester's token

			 // Compute HMAC
			byte[] hmac = hmac(message);

			// Add hmac to object
			message.addObject(hmac);
			 
			 encryptedMessage = encryptEnvelope(message, secretKey);
			 output.writeObject(encryptedMessage);
			 output.reset();

			File file = new File(sourceFile);
			FileInputStream fis = null;

			// error handling
			if (file.isFile() && file.canRead()) {
				fis = new FileInputStream(sourceFile);
			} else {
				// Don't care what this is since the file doesn't even exist
				input.readObject();

			 	// Increment session number
				sessionNumber = sessionNumber.add(BigInteger.ONE);

				return false;
			}

			 encryptedResponse = (SealedObject)input.readObject();
			 env = (Envelope) decryptEnvelope(encryptedResponse, secretKey);

			 // Increment session number
			sessionNumber = sessionNumber.add(BigInteger.ONE);

			// takes hmac of envelope without hmac on the end
			hmac = hmac(recreateEnv(env));

			byte[] serverHmac = (byte[]) env.getObjContents().get(env.getObjContents().size() - 1);

			if(!MessageDigest.isEqual(serverHmac, hmac)) {
				System.out.println("Error performing request: HMACs don't match.");
				return false;
			}
			else if(env.getMessage().equals("READY")) //If server indicates success, return the member list
			 { 
				System.out.printf("Meta data upload successful\n");
				
			}
			 else {
				
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				return false;
			 }
			
			//Contact the Group Client so that it can contact Group Server and retrieve an AES key to encrypt file
            ArrayList<String> groups = new ArrayList<String>();
            groups.add(group);
            byte[][] AESinfo = gc_communicator.retrieveFileEncryptKey(groups, destFile, fileServerIP, "upload", groupToken);          
            SecretKey AESkey = null;
            IvParameterSpec IV = null;
            
            //Build SecretKey and IvParameterSpec for encrypting files
            try
            {
                AESkey = new SecretKeySpec(AESinfo[0], 0, AESinfo[0].length, "AES");
                IV = new IvParameterSpec(AESinfo[1]);
            }
            catch(Exception eeeeee)
            {
                System.out.println("Failed to retrieve file encryption key from Group Server");
            }
            
			 do {
			     
				 byte[] buf = new byte[4096];

				 serverHmac = (byte[]) env.getObjContents().get(0);

				if(!MessageDigest.isEqual(serverHmac, hmac)) {
					System.out.println("Error performing request: HMACs don't match.");
					return false;
				} else if (env.getMessage().compareTo("READY")!=0) {
				 		System.out.printf("Server error: %s\n", env.getMessage());
				 		return false;
				 	}
				 	message = new Envelope("CHUNK");
					int n = fis.read(buf); //can throw an IOException
					if (n > 0) {
						System.out.printf(".");
					} else if (n < 0) {
						System.out.println("Read error");
						return false;
					}

					//ENCRYPT THE FILE CHUNK
					byte[] encryptedChunk = encryptChunk(buf, AESkey, IV);
					
					
					// Increment session number
					sessionNumber = sessionNumber.add(BigInteger.ONE);
					
					message.addObject(encryptedChunk);
					message.addObject(new Integer(n));

					 // Compute HMAC
					hmac = hmac(message);

					// Add hmac to object
					message.addObject(hmac);
					
		            encryptedMessage = encryptEnvelope(message, secretKey);
		            output.writeObject(encryptedMessage);
		            output.reset();
					
		            encryptedResponse = (SealedObject)input.readObject();
		            env = (Envelope) decryptEnvelope(encryptedResponse, secretKey);

		            // Increment session number
					sessionNumber = sessionNumber.add(BigInteger.ONE);

					// takes hmac of envelope without hmac on the end
					hmac = hmac(recreateEnv(env));	

					serverHmac = (byte[]) env.getObjContents().get(0);

					if(!MessageDigest.isEqual(serverHmac, hmac)) {
						System.out.println("Error performing request: HMACs don't match.");
						return false;
					}	
										
			 }
			 while (fis.available()>0);		 
					 
			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY")==0)
			 { 
				
				message = new Envelope("EOF");

				// Compute HMAC
				hmac = hmac(message);

				// Add hmac to object
				message.addObject(hmac);

	            encryptedMessage = encryptEnvelope(message, secretKey);
	            output.writeObject(encryptedMessage);
	            output.reset();
				
	            encryptedResponse = (SealedObject)input.readObject();
	            env = (Envelope) decryptEnvelope(encryptedResponse, secretKey);

	            // Increment session number
				sessionNumber = sessionNumber.add(BigInteger.ONE);

				// takes hmac of envelope without hmac on the end
				hmac = hmac(recreateEnv(env));	

				serverHmac = (byte[]) env.getObjContents().get(0);

				if(!MessageDigest.isEqual(serverHmac, hmac)) {
					System.out.println("Error performing request: HMACs don't match.");
					return false;
				} else if(env.getMessage().compareTo("OK")==0) {
					System.out.printf("\nFile data upload successful\n");
				}
				else {
					
					 System.out.printf("\nUpload failed: %s\n", env.getMessage());
					 return false;
				 }
				
			}
			 else {
				
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }
			 
		 }catch(Exception e1)
			{
				System.err.println("Error: " + e1.getMessage());
				e1.printStackTrace(System.err);
				 // Increment session number
				sessionNumber = sessionNumber.add(BigInteger.ONE);
				return false;
				}
		 return true;
	}
	
	//Method for encrypting file chunk
	public byte[] encryptChunk(byte[] chunk, SecretKey aesKey, IvParameterSpec iv)
	{
	    try
	    {
    	    // Specifiy AES cipher and intialize cipher to encrypt
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
            byte[] encryptedChunk = cipher.doFinal(chunk);
            return encryptedChunk;    
	    }
	    catch(Exception e)
	    {
	        System.out.println("Failed to encrypt chunk.");
	        System.out.println("Error: " + e.getMessage());
	        return null;
	    }       
	}
	
	//Method for decrypting file chunk
	public byte[] decryptChunk(byte[] encryptedChunk, SecretKey aesKey, IvParameterSpec iv)
	{
	    try
	    {
        // Specifiy AES cipher and intialize cipher to encrypt
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
            byte[] chunk = cipher.doFinal(encryptedChunk);
            return chunk;
	    }
	    catch(Exception e)
	    {
	        System.out.println("Failed to decrypt chunk.");
	        System.out.println("Error: "+ e.getMessage());
	        return null;
	    }
	}
	
	//Method to retrieve the file servers public key
    public PublicKey getServerPublicKey(UserToken token)
    {
        try
        {
            Envelope message = null, e = null;
            
            message = new Envelope("GETPUBKEY");
            message.addObject(token);
            output.writeObject(message);
            
            e = (Envelope)input.readObject();
            
            if(e.getMessage().equals("OK"))
            {
                return (PublicKey)e.getObjContents().get(0);
            }
            else
            {
                System.out.println("Server response: " + e.getMessage());
            }
            
        }
        catch(Exception e)
        {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;            
        }
        
        //If it gets here then bad things happened
        System.out.println("ERROR: Failed to send File Server public key.");
        return null;
    }
	
	public SealedObject encryptEnvelope(Envelope env, PublicKey key)	//this method is to encrypt with ther file servers public key
    {  
       try {
           // Specifiy AES cipher and intialize cipher to encrypt
           Cipher cipher = Cipher.getInstance("RSA", "BC");
           cipher.init(Cipher.ENCRYPT_MODE, key);

           // Encrypt our envelope
           SealedObject sealedEnv = new SealedObject(env, cipher);

           return sealedEnv;
       } catch (Exception e) {
           System.out.println("Error: Exception");
           e.printStackTrace();
       }

       return null;
    }
    
    public SealedObject encryptEnvelope(Envelope env, SecretKey key)
    {  
       try {
           // Specifiy AES cipher and intialize cipher to encrypt
           Cipher cipher = Cipher.getInstance("AES");
           cipher.init(Cipher.ENCRYPT_MODE, key);

           // Encrypt our envelope
           SealedObject sealedEnv = new SealedObject(env, cipher);

           return sealedEnv;
       } catch (Exception e) {
           System.out.println("Error: Exception");
           e.printStackTrace();
       }

       return null;
    }
    
    public Envelope decryptEnvelope(SealedObject sealedEnv, SecretKey key)
    {
       try {
           // Specifiy AES cipher and intialize cipher to decrypt
           Cipher cipher = Cipher.getInstance("AES");
           cipher.init(Cipher.DECRYPT_MODE, key);

           // Decrypt our envelope
           Envelope env = (Envelope) sealedEnv.getObject(cipher);

           return env;
       } catch (Exception e) {
           System.out.println("Error: Exception");
           e.printStackTrace();
       }
       return null;
    }

    // performs sha-256 hmac of envelope and session number
	 public byte[] hmac(Envelope env) throws Exception {
	 	Mac hmac = Mac.getInstance("HmacSHA256");
	 	hmac.init(DHSharedKey);

	 	// string we want to hmac
	 	String string = env.toString() + "\n" + sessionNumber;

	 	//System.out.println(string);

	 	// string converted to byte array
	 	byte[] bytes = string.getBytes();

	 	byte[] hmacBytes = hmac.doFinal(bytes);

	 	//System.out.println(hmacBytes);

	 	return hmacBytes;
	 }

	 // recreate envelope without hmac at the end so we can see if hmac match
	 public Envelope recreateEnv(Envelope env) {
	 	Envelope recreatedEnv = new Envelope(env.getMessage());

	 	ArrayList<Object> objectContents = env.getObjContents();

	 	for(int i = 0; i < objectContents.size() - 1; i++) {
	 		recreatedEnv.addObject(objectContents.get(i));
	 	}

	 	return recreatedEnv;
	 }
	 
	 public boolean verifyServer( byte[] serverSignature, BigInteger serverDH, PublicKey publicKey )		//this will check if the server is who they say they are and sent the DH
	{
		boolean verified = false;	//guilty until proven innocent 
		
		try
		{
			Signature rsaSignature = Signature.getInstance("SHA256withRSA");	//use SHA256 with RSA as the rsa signature compenents
			rsaSignature.initVerify( publicKey );	//initialized the verify with the correct public key for the thread
			rsaSignature.update( serverDH.toByteArray() );	//get ready to verify	
			
			if( rsaSignature.verify( serverSignature ) )	//the token was not tampered with
			{
				verified = true;
			}
		}
		
		catch(Exception e)
		{
		
		}
		return verified;
	}
    
    

}

