/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.util.List;
import java.util.Random;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.io.*;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
//import sun.misc.BASE64Decoder;
//import sun.misc.BASE64Encoder;


/* cryptography libraries */
import java.security.*;
import javax.crypto.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

//Crypto libraries
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.*;

import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;

import java.math.BigInteger;

public class FileThread extends Thread
{
	private final Socket socket;
	private PublicKey groupPubKey;
	
	//Holds the file servers RSA keypair
	private PrivateKey fsPrivateKey;
	private PublicKey fsPublicKey; 
	
	//Holds the session key between file server and client
	private SecretKey sharedSecret;
	private boolean hasSharedSecret;
	private SecretKey DHSharedKey;

	private BigInteger sessionNumber;	// used to prevent replay or reorder attacks

	public FileThread(Socket _socket)
	{
		socket = _socket;
		hasSharedSecret = false;

        // Add BouncyCastle Provider
        Security.addProvider(new BouncyCastleProvider());

	}

	public void run()
	{
		boolean proceed = true;
		try
		{
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			Envelope response;
			
       //INITIATE REVERSE HASH CHALLENGE///////////////////////////////////////////
            
            //Specify length of challenge number
            int N = 7;
            
            //Get random N-size integer
            Random rng = new Random();
            StringBuilder sb = new StringBuilder();
            for(int i = 0; i < N; i++)
            {
                if(i == 0)
                {
                    sb.append(rng.nextInt(9)+1);
                }
                else
                {
                    sb.append(rng.nextInt(10));
                }
            }
            
            //Build the BigInteger and initialize H(R) 
            BigInteger R = new BigInteger(sb.toString());
            byte[] h_of_R = new byte[0];
            
            try
            {
                //Get H(R)
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                sha256.update(R.toByteArray());
                h_of_R = sha256.digest();
                
                //Send N and H(R) to client
                Envelope puzzle = new Envelope("PUZZLE");
                puzzle.addObject(N);
                puzzle.addObject(h_of_R);
                output.writeObject(puzzle);
                output.reset();
                
                //Retrieve Clients answer
                Envelope puzzleAnswer = (Envelope)input.readObject();
                if(puzzleAnswer.getMessage().equals("ANSWER"))
                {
                    System.out.println("ANSWER");
                    
                    //Verify that client answer is equal to R
                    BigInteger answer = (BigInteger)puzzleAnswer.getObjContents().get(0);
                    if(R.equals(answer))
                    {
                        System.out.println("Steady connection to "+ socket.getInetAddress());
                        output.writeObject(new Envelope("SUCCESS"));
                        output.reset();
                    }
                    else
                    {
                        System.out.println("Denied connection to "+ socket.getInetAddress());
                        output.writeObject(new Envelope("FAIL"));
                        output.reset();
                        return;
                    }
                }
                else
                {
                    System.out.println("Client declined.");
                    return;
                }

            }
            catch(Exception e)
            {
                System.out.println("Error creating Rever Hash Puzzle.");
            }
            
//////////////// SUCCESSFUL HASH PUZZLE COMPLETION////////////
            
            
			//Read in Group Servers Public key
    		try
    		{
    			File f = new File("groupPubKey.txt");
    			FileInputStream fis = new FileInputStream(f);
    			DataInputStream dis = new DataInputStream(fis);
    			byte[] keyBytes = new byte[(int)f.length()];
    			dis.readFully(keyBytes);
    			dis.close();
    
    			X509EncodedKeySpec spec =
    			new X509EncodedKeySpec(keyBytes);
    			KeyFactory kf = KeyFactory.getInstance("RSA");
       
    			groupPubKey = kf.generatePublic(spec);
    		}
    		catch(Exception e)
    		{
    			System.out.println("ERROR: Group Public Key file not found! Shutting down.");
    		}
    		
    		//Get File Server public key
            ObjectInputStream getPubKey = new ObjectInputStream(new FileInputStream("fileServPubKey.txt"));
            fsPublicKey = (PublicKey)getPubKey.readObject();
            getPubKey.close();
            
            //Get File Server private key
            ObjectInputStream getPrivKey = new ObjectInputStream(new FileInputStream("fileServPrivKey.txt"));
            fsPrivateKey = (PrivateKey)getPrivKey.readObject();
            getPrivKey.close();

			do
			{
				Envelope e = (Envelope)input.readObject();
				SealedObject encryptedMessage, decryptedMessage, encryptedResponse;
				Envelope message;
				
				System.out.println("Request received: " + e.getMessage());
				
				//Handler to provide the File Server's public key to client requestor
				if(e.getMessage().equals("GETPUBKEY"))
				{
					UserToken token = (UserToken)e.getObjContents().get(0);	//get token
				
				    if(e.getObjContents().size() < 1)
				    {
				        response = new Envelope("FAIL-BADCONTENTS");
				    }
				    
				    else if( token == null)
				    {
				        response = new Envelope("FAIL-BADTOKEN");
				    }
				    
                    else if( !Token.verify( token, groupPubKey )  )   //the token was modified in transit, do not check for public key here
                    {
                        response = new Envelope("FAIL-BADTOKEN");
                    }
				    
				    else
				    {
		                response = new Envelope("OK"); //Success
		                
		                //provide file server public key to requestor
		                response.addObject(fsPublicKey);
				    }
				    
				    output.writeObject(response);
				    output.reset();
				}
				
				//Handler to accept a message encrypted with file servers public key
				if(e.getMessage().equals("ENC-PUB"))
				{
					byte[] encryptedKey = (byte[]) input.readObject();	//read in the AES key
					//response= (Envelope)decryptEnvelope( encryptedResponse, fsPrivateKey );
				   
				   if( encryptedKey != null )	//NOTE at this point we still do not fully trust the client
				   {
				   		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	                    cipher.init(Cipher.DECRYPT_MODE, fsPrivateKey);
	                    sharedSecret = new SecretKeySpec(cipher.doFinal(encryptedKey), "AES");
				   }
				   
				   else
				   {
						System.exit(-1);
				   }
				   
				   	encryptedMessage = (SealedObject) input.readObject();	//read in the DH-CLIENT Envelope
					message = (Envelope)decryptEnvelope( encryptedMessage, sharedSecret );	//use the brand new AES key

					System.out.println("Request received and decrypted to: " + message.getMessage());
				   
					//get the first AES key and then get the shared DH key
					BigInteger serverDH = null;	//server half of DH key
					if( message.getMessage().equals("DH-CLIENT") )
					{					
						if( message.getObjContents().size() == 5 )
						{
							if( Token.verify( (UserToken)message.getObjContents().get( 1 ), groupPubKey ) )
							{
								response = new Envelope( "DH-SERVER" );
								
								//get DH parts of the message
								BigInteger pValue = (BigInteger)message.getObjContents().get( 2 );	
								BigInteger gValue = (BigInteger)message.getObjContents().get( 3 );
								int lValue = (int)message.getObjContents().get( 4 );
								BigInteger clientDH = (BigInteger)message.getObjContents().get( 0 );
																
								//create serverDH
								SecureRandom random = new SecureRandom();
								BigInteger b = new BigInteger(lValue, random);
								serverDH = gValue.modPow(b, pValue);	// Server creates there half of the DH key 
								
								BigInteger DHMulti = clientDH.modPow(b, pValue);	//create g^ab mod p
								
								try
								{
									MessageDigest sha256 = MessageDigest.getInstance("SHA-256");	 // Declare SHA-256 hash function
									
									sha256.update( DHMulti.toByteArray() );	//perform the hash
							
									DHSharedKey = new SecretKeySpec( sha256.digest(), "AES" );	//creates the DHShared key as AES key from the hash
								}
								
								catch( Exception ee )
								{
									response = new Envelope( "FAIL" );
								}
							
							}
							
							else
							{
								response = new Envelope( "BAD-TOKEN" );
							}
						
							
						}
						
						else
						{
							response = new Envelope( "BAD-CONTENTS" );
						}
				    }
				   
					else
					{
						response = new Envelope( "BAD-CONTENTS" );
					}
			
					//fill up the response object now
					response.addObject( serverDH );
					response.addObject( signMessage( serverDH.toByteArray() ) );	//sign the serverDH and send it
					
					encryptedResponse = encryptEnvelope( response, sharedSecret );
					output.writeObject( encryptedResponse );
					output.reset();

					encryptedResponse = (SealedObject) input.readObject();	//read in the DH-CLIENT Envelope
					response = (Envelope)decryptEnvelope( encryptedResponse, sharedSecret );	//use the brand new AES key

					System.out.println("Request received and decrypted to: " + response.getMessage());
	
				    //get challenged by the client to make sure that they have the correct DHShared key
				    if(response.getMessage().equals("CHALLENGE"))
	                {
	                    //decode message and answer challenge
	                    if(response.getObjContents().size() == 1)
	                    {
							//Answer challenge to add five to the large integer
	                        BigInteger n1 = new BigInteger("0");
	                        BigInteger n2 = new BigInteger("5");

	                        byte[] encryptedChallenge = (byte[])response.getObjContents().get(0);
							try	//decrypt the challenge
							{
								Cipher cipher = Cipher.getInstance( "AES", "BC" );
								cipher.init( Cipher.DECRYPT_MODE, DHSharedKey );
								n1 = new BigInteger(cipher.doFinal(encryptedChallenge));
								sessionNumber = n1;
	                            hasSharedSecret = true;
							}
	                        catch(Exception ee)
	                        {
	                            System.out.println("Failed to retrieve a session key from Challenge.");
	                            System.out.println("ERROR: "+ e.getMessage());
	                            
	                        }

	                        BigInteger answer = n1.add(n2);	//Answer challenge by adding five to number
							byte[] encodedAnswer = null;
							try	//encrypt the answer
							{
								Cipher cipher = Cipher.getInstance("AES", "BC");
								cipher.init( Cipher.ENCRYPT_MODE, DHSharedKey );
								encodedAnswer = cipher.doFinal( answer.toByteArray() );	
							}
							catch(Exception ee)
							{
								System.out.println("Failed to retrieve a session key from Challenge.");
	                            System.out.println("ERROR: "+ ee.getMessage());
							}

	                        //Build message to send to client
	                        e = new Envelope("ANSWER");
	                        e.addObject(encodedAnswer);
	                        encryptedResponse = encryptEnvelope( e, sharedSecret );
							output.writeObject( encryptedResponse );
							output.reset();

	                    }

	                }

				}
				
				
				if(e.getMessage().equals("ENC-SEC"))
				{
				    encryptedMessage = (SealedObject)input.readObject();
				    e = (Envelope) decryptEnvelope(encryptedMessage, sharedSecret);
				    System.out.println("Request decrypted to: " + e.getMessage());

				    // Increment session number
					sessionNumber = sessionNumber.add(BigInteger.ONE);

					// takes hmac of envelope without hmac on the end
					byte[] hmac = hmac(recreateEnv(e));
				    
	                // Handler to list files that this user is allowed to see
	                if(e.getMessage().equals("LFILES"))
	                {
						UserToken token = (Token)e.getObjContents().get(0);	//get token
						byte[] clientHmac = (byte[])e.getObjContents().get(1);	// Extract hmac
						
						if(!MessageDigest.isEqual(clientHmac, hmac)) {
							response = new Envelope("FAIL");
							System.out.println("Error performing request: HMACs don't match.");
						} else if(e.getObjContents().size() < 1) 
	                    {
	                        response = new Envelope("FAIL-BADCONTENTS");    //Envelope does not hold anything
	                    } 
	                    
	                    else if( e.getObjContents().get(0) == null) 
	                    {
	                        response = new Envelope("FAIL-BADTOKEN");   //Token is null
	                    }
	                        
	                    else if( !Token.verify( token, groupPubKey ) || !token.getPublicKey().equals( fsPublicKey ) )   //the token was modified in transit or a stolen token is being used
	                    {
	                        response = new Envelope("FAIL-BADTOKEN");
	                    }
	                    
	                    else
	                    {
	                        UserToken yourToken = (UserToken)e.getObjContents().get(0);     //Extract token

	                        ArrayList<ShareFile> files = FileServer.fileList.getFiles();    //Get files associated with File Server
	                        ArrayList<String> userGroups = (ArrayList<String>) yourToken.getGroups();           //Get groups associated with User
	                        ArrayList<String> fileList = new ArrayList<String>();

	                        response = new Envelope("OK");

	                        for(ShareFile file : files) {
	                            //Check if file is in one of user's groups
	                            if(userGroups.contains(file.getGroup())) {
	                                //Add file path to response (might have to modify ShareFile method to return a filename)
	                                fileList.add(file.getPath());
	                            }
	                        }

	                        response.addObject(fileList);
	                    }
	                    // Increment session number
						sessionNumber = sessionNumber.add(BigInteger.ONE);

						// Add hmac to response
						response.addObject(hmac(response));

                        encryptedResponse = encryptEnvelope(response, sharedSecret);
                        output.writeObject(encryptedResponse);
                        output.reset();
	                }
	            
	                if(e.getMessage().equals("UPLOADF"))
	                {
						UserToken token = (Token)e.getObjContents().get(2);	//get token
						byte[] clientHmac = (byte[])e.getObjContents().get(3);	// Extract hmac
					
	                    if(e.getObjContents().size() < 3)
	                    {
	                        response = new Envelope("FAIL-BADCONTENTS");
	                    }
	                    
	                    else if(e.getObjContents().get(0) == null) 
	                    {
	                        response = new Envelope("FAIL-BADPATH");
	                    }
	                    
	                    else if(e.getObjContents().get(1) == null) 
	                    {
	                        response = new Envelope("FAIL-BADGROUP");
	                    }
	                    
	                    else if(e.getObjContents().get(2) == null) 
	                    {
	                        response = new Envelope("FAIL-BADTOKEN");
	                    }

	                     else if(e.getObjContents().get(3) == null) 
	                    {
	                        response = new Envelope("FAIL");
	                    }
	                    
	                    else if( !Token.verify( token, groupPubKey ) || !token.getPublicKey().equals( fsPublicKey ) )   //the token was modified in transit or a stolen token is being used
	                    {
	                        response = new Envelope("FAIL-BADTOKEN");
	                    } else if(!MessageDigest.isEqual(clientHmac, hmac)) {
							response = new Envelope("FAIL");
							System.out.println("Error performing request: HMACs don't match.");
						}   
	                    else 
	                    {
	                        String remotePath = (String)e.getObjContents().get(0);
	                        String group = (String)e.getObjContents().get(1);
	                        UserToken yourToken = (UserToken)e.getObjContents().get(2); //Extract token

	                        if (FileServer.fileList.checkFile(remotePath)) {
	                            System.out.printf("Error: file already exists at %s\n", remotePath);
	                            response = new Envelope("FAIL-FILEEXISTS"); //Success
	                        }
	                        
	                        else if (!yourToken.getGroups().contains(group)) {
	                            System.out.printf("Error: user missing valid token for group %s\n", group);
	                            response = new Envelope("FAIL-UNAUTHORIZED"); //Success
	                        }
	                        
	                        else  
	                        {
	                            File file = new File("shared_files/"+remotePath.replace('/', '_'));
	                            file.createNewFile();
	                            FileOutputStream fos = new FileOutputStream(file);
	                            System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

	                            response = new Envelope("READY"); //Success

	                            // Increment session number
								sessionNumber = sessionNumber.add(BigInteger.ONE);

								// Add hmac to response
								response.addObject(hmac(response));

	                            encryptedResponse = encryptEnvelope(response, sharedSecret);
	                            output.writeObject(encryptedResponse);
	                            output.reset();

	                            encryptedMessage = (SealedObject)input.readObject();
	                            e = (Envelope) decryptEnvelope(encryptedMessage, sharedSecret);

	                            clientHmac = (byte[])e.getObjContents().get(e.getObjContents().size() - 1);	// Extract hmac

	                            // Increment session number
								sessionNumber = sessionNumber.add(BigInteger.ONE);

								// takes hmac of envelope without hmac on the end
								hmac = hmac(recreateEnv(e));

								if(!MessageDigest.isEqual(clientHmac, hmac)) {
									response = new Envelope("FAIL");
									System.out.println("Error performing request: HMACs don't match.");
								} else {
	                            
		                            while (e.getMessage().compareTo("CHUNK")==0) {
		                                fos.write((byte[])e.getObjContents().get(0), 0, (Integer)e.getObjContents().get(1));
		                                
		                                response = new Envelope("READY"); //Success

		                                // Increment session number
										sessionNumber = sessionNumber.add(BigInteger.ONE);

										// Add hmac to response
										response.addObject(hmac(response));

		                                encryptedResponse = encryptEnvelope(response, sharedSecret);
		                                output.writeObject(encryptedResponse);
		                                output.reset();
		                                
		                                encryptedMessage = (SealedObject)input.readObject();
		                                e = (Envelope) decryptEnvelope(encryptedMessage, sharedSecret);

		                                if(e.getObjContents().size() == 3) {
		                                	clientHmac = (byte[])e.getObjContents().get(2);	// Extract hmac
		                                } else if (e.getMessage().compareTo("EOF") == 0) {
		                                	clientHmac = (byte[])e.getObjContents().get(0);	
		                                	break;
		                                }

	                            		// Increment session number
										sessionNumber = sessionNumber.add(BigInteger.ONE);

										// takes hmac of envelope without hmac on the end
										hmac = hmac(recreateEnv(e));

										if(!MessageDigest.isEqual(clientHmac, hmac)) {
											response = new Envelope("FAIL");
											System.out.println("Error performing request: HMACs don't match.");
											break;
				                        }
				                     }

		                            if(e.getMessage().compareTo("EOF")==0) {
		                                System.out.printf("Transfer successful file %s\n", remotePath);
		                                FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath);
		                                response = new Envelope("OK"); //Success
		                            }
		                            else {
		                                System.out.printf("Error reading file %s from client\n", remotePath);
		                                response = new Envelope("ERROR-TRANSFER"); //Success
		                            }

		                         }
	                            fos.close();
	                        }
	                    }

	                    	// Increment session number
							sessionNumber = sessionNumber.add(BigInteger.ONE);

							// Add hmac to response
							response.addObject(hmac(response));

	                       encryptedResponse = encryptEnvelope(response, sharedSecret);
	                       output.writeObject(encryptedResponse);
	                       output.reset();
	                }

	                else if (e.getMessage().compareTo("DOWNLOADF")==0) 
	                {

	                    String remotePath = (String)e.getObjContents().get(0);
	                    Token t = (Token)e.getObjContents().get(1);
	                    byte[] clientHmac = (byte[])e.getObjContents().get(2);	// Extract hmac

	                    ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
	                    if (sf == null) {
	                        System.out.printf("Error: File %s doesn't exist\n", remotePath);
	                        response = new Envelope("ERROR_FILEMISSING");

	                        // Increment session number
							sessionNumber = sessionNumber.add(BigInteger.ONE);

							// Add hmac to response
							response.addObject(hmac(response));

	                        encryptedResponse = encryptEnvelope(response, sharedSecret);
	                        output.writeObject(encryptedResponse);
	                        output.reset();

	                    }
	                    
	                    else if (!t.getGroups().contains(sf.getGroup())){
	                        System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
	                        response = new Envelope("ERROR_PERMISSION");

	                        // Increment session number
							sessionNumber = sessionNumber.add(BigInteger.ONE);

							// Add hmac to response
							response.addObject(hmac(response));

	                        encryptedResponse = encryptEnvelope(response, sharedSecret);
	                        output.writeObject(encryptedResponse);
	                        output.reset();
	                    }
	                    
	                    else if( !Token.verify( t, groupPubKey ) || !t.getPublicKey().equals( fsPublicKey ) )    //the token was modified in transit or a stolen token is being used
	                    {
	                        response = new Envelope("FAIL-BADTOKEN");

	                        // Increment session number
							sessionNumber = sessionNumber.add(BigInteger.ONE);

							// Add hmac to response
							response.addObject(hmac(response));

							encryptedResponse = encryptEnvelope(response, sharedSecret);
	                        output.writeObject(encryptedResponse);
	                        output.reset();

	                    } else if(!MessageDigest.isEqual(clientHmac, hmac)) {
							response = new Envelope("FAIL");
							System.out.println("Error performing request: HMACs don't match.");

							// Increment session number
							sessionNumber = sessionNumber.add(BigInteger.ONE);

							// Add hmac to response
							response.addObject(hmac(response));

							encryptedResponse = encryptEnvelope(response, sharedSecret);
	                        output.writeObject(encryptedResponse);
	                        output.reset();
						}
	                    
	                    else {

	                        try
	                        {
	                            File f = new File("shared_files/_"+remotePath.replace('/', '_'));
	                        if (!f.exists()) {
	                            System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
	                            response = new Envelope("ERROR_NOTONDISK");

	                            // Increment session number
								sessionNumber = sessionNumber.add(BigInteger.ONE);

								// Add hmac to response
								response.addObject(hmac(response));

	                            encryptedResponse = encryptEnvelope(response, sharedSecret);
	                            output.writeObject(encryptedResponse);
	                            output.reset();

	                        }
	                        else {
	                            FileInputStream fis = new FileInputStream(f);

	                            do {
	                                byte[] buf = new byte[4096];
	                                if (e.getMessage().compareTo("DOWNLOADF")!=0) {
	                                    System.out.printf("Server error: %s\n", e.getMessage());
	                                    break;
	                                }
	                                e = new Envelope("CHUNK");
	                                int n = fis.read(buf); //can throw an IOException
	                                if (n > 0) {
	                                    System.out.printf(".");
	                                } else if (n < 0) {
	                                    System.out.println("Read error");

	                                }


	                                e.addObject(buf);
	                                e.addObject(new Integer(n));

	                                // Increment session number
									sessionNumber = sessionNumber.add(BigInteger.ONE);

									// Add hmac to response
									e.addObject(hmac(e));

	                                encryptedResponse = encryptEnvelope(e, sharedSecret);
	                                output.writeObject(encryptedResponse);
	                                output.reset();

	                                encryptedMessage = (SealedObject)input.readObject();
	                                e = (Envelope) decryptEnvelope(encryptedMessage, sharedSecret);

	                        		//if(e.getObjContents().size() == 3) {
		                                clientHmac = (byte[])e.getObjContents().get(e.getObjContents().size() - 1);	// Extract hmac
		                            //} //else if (e.getMessage().compareTo("EOF") == 0) {
		                                //clientHmac = (byte[])e.getObjContents().get(0);	
		                                //break;
		                            //}

	                            		// Increment session number
										sessionNumber = sessionNumber.add(BigInteger.ONE);

										// takes hmac of envelope without hmac on the end
										hmac = hmac(recreateEnv(e));

										if(!MessageDigest.isEqual(clientHmac, hmac)) {
											response = new Envelope("FAIL");
											System.out.println("Error performing request: HMACs don't match.");
											break;
				                        }     


	                            }
	                            while (fis.available()>0);

	                            //If server indicates success, return the member list
	                            if(e.getMessage().compareTo("DOWNLOADF")==0)
	                            {

	                                e = new Envelope("EOF");

	                                // Increment session number
									sessionNumber = sessionNumber.add(BigInteger.ONE);

									// Add hmac to response
									e.addObject(hmac(e));

	                                encryptedResponse = encryptEnvelope(e, sharedSecret);
	                                output.writeObject(encryptedResponse);
	                                output.reset();

	                                encryptedMessage = (SealedObject)input.readObject();
	                                e = (Envelope) decryptEnvelope(encryptedMessage, sharedSecret);

	                                // Increment session number
									sessionNumber = sessionNumber.add(BigInteger.ONE);

									// takes hmac of envelope without hmac on the end
									hmac = hmac(recreateEnv(e));

									clientHmac = (byte[]) e.getObjContents().get(e.getObjContents().size() - 1);

									if(!MessageDigest.isEqual(clientHmac, hmac)) {
										System.out.println("Error performing request: HMACs don't match.");
									} else if(e.getMessage().compareTo("OK")==0) {
	                                    System.out.printf("File data upload successful\n");
	                                }
	                                else {
	                                    System.out.printf("Upload failed: %s\n", e.getMessage());
	                                }

	                            }
	                            else {

	                                System.out.printf("Upload failed: %s\n", e.getMessage());

	                            }
	                        }
	                        }
	                        catch(Exception e1)
	                        {
	                            System.err.println("Error: " + e.getMessage());
	                            e1.printStackTrace(System.err);

	                        }
	                    }
	                }
	                
	                else if (e.getMessage().compareTo("DELETEF")==0) 
	                {

	                    String remotePath = (String)e.getObjContents().get(0);
	                    Token t = (Token)e.getObjContents().get(1);
	                    byte[] clientHmac = (byte[])e.getObjContents().get(2);	// Extract hmac

	                    ShareFile sf = FileServer.fileList.getFile("/"+remotePath);

	                    if(!MessageDigest.isEqual(clientHmac, hmac)) {
							e = new Envelope("FAIL");
							System.out.println("Error performing request: HMACs don't match.");
						} else if (sf == null) {
	                        System.out.printf("Error: File %s doesn't exist\n", remotePath);
	                        e = new Envelope("ERROR_DOESNTEXIST");
	                    }
	                    
	                    else if (!t.getGroups().contains(sf.getGroup())){
	                        System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
	                        e = new Envelope("ERROR_PERMISSION");
	                    }
						
	                    else if( !Token.verify( t, groupPubKey ) || !t.getPublicKey().equals( fsPublicKey ) )    //the token was modified in transit or a stolen token is being used
	                    {
	                        e = new Envelope("FAIL-BADTOKEN");
	                    }
	                    
	                    else {

	                        try
	                        {


	                            File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));

	                            if (!f.exists()) {
	                                System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
	                                e = new Envelope("ERROR_FILEMISSING");
	                            }
	                            else if (f.delete()) {
	                                System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
	                                FileServer.fileList.removeFile("/"+remotePath);
	                                e = new Envelope("OK");
	                            }
	                            else {
	                                System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
	                                e = new Envelope("ERROR_DELETE");
	                            }


	                        }
	                        catch(Exception e1)
	                        {
	                            System.err.println("Error: " + e1.getMessage());
	                            e1.printStackTrace(System.err);
	                            e = new Envelope(e1.getMessage());
	                        }
	                    }

	                    // Increment session number
						sessionNumber = sessionNumber.add(BigInteger.ONE);

						// Add hmac to response
						e.addObject(hmac(e));

	                    encryptedResponse = encryptEnvelope(e, sharedSecret);
	                    output.writeObject(encryptedResponse);
	                    output.reset();

	                }
				}

				if(e.getMessage().equals("DISCONNECT"))
				{
					socket.close();
					proceed = false;
				}
			} while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	
    public Envelope decryptEnvelope(SealedObject sealedEnv, PrivateKey key) throws Exception	//decrypt messages with the server's private key
    {
       try {
           // Specifiy AES cipher and intialize cipher to decrypt
           Cipher cipher = Cipher.getInstance("RSA");
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
    
	//Decrypt sealed object using shared AES session key
    public Envelope decryptEnvelope(SealedObject sealedEnv, SecretKey key) throws Exception
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
    
    //Encrypt envelope using shared AES session key
    public SealedObject encryptEnvelope(Envelope env, SecretKey key) throws Exception
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
	 
	 private byte[] signMessage( byte[] array )
	 {
		byte[] signature = null;
		
		try 
		{
			Signature rsaSignature = Signature.getInstance("SHA256withRSA");	//use SHA256 with RSA as the rsa signature components
			rsaSignature.initSign( fsPrivateKey );	//initialize rsa signature
			rsaSignature.update( array );	//give the input as the the encrypted message
			signature = rsaSignature.sign();
						
		}
		
		catch (Exception e) 
		{

    	}
		
		return signature;
	 }

}
