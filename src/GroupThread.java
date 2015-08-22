/* This thread does all the work. It communicates with the client through Envelopes.
 * 
 */
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/* crypto libraries */
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.*;

import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Mac;
import javax.crypto.*;

import java.math.BigInteger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


/*METHODS AND CHANGES TODO:
 *     Remove group from Hashmap
 */

public class GroupThread extends Thread implements java.io.Serializable
{
	private final Socket socket;
	private GroupServer my_gs;
	private SecretKeySpec passwordKey;
	private SecretKeySpec sessionKey;
	private SecretKeySpec integrityKey;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private BigInteger sessionNumber;	// used to prevent replay or reorder attacks

	public GroupThread(Socket _socket, GroupServer _gs)
	{
		socket = _socket;
		my_gs = _gs;
	}
	
	public void run()
	{
		boolean proceed = true;

		try
		{
			Security.addProvider(new BouncyCastleProvider());

			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			
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
			
			
			//Proceed to accept Requests from Client
			do
			{
				Envelope message = (Envelope)input.readObject();
				System.out.println("Request received: " + message.getMessage());
				Envelope response;
				SealedObject encryptedMessage, encryptedResponse;
				
				if(message.getMessage().equals("GET"))//Client wants a token
				{
					String username = (String)message.getObjContents().get(0); //Get the username
					if(username == null || !my_gs.userList.checkUser(username))
					{
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
						output.reset();
					}
					else
					{
						// Get user's hashed password
						byte[] hashedPassword = my_gs.userList.getHashedPassword(username);

						// Set as shared key
						passwordKey = new SecretKeySpec(hashedPassword, "AES");

						// Intialize Diffie Hellman parameter generator
    					AlgorithmParameterGenerator generator = AlgorithmParameterGenerator.getInstance("DiffieHellman");
    					generator.init(512);

    					// Declare and set Diffie Hellman parameters
    					AlgorithmParameters parameters = generator.generateParameters();
    					DHParameterSpec specifications = (DHParameterSpec) parameters.getParameterSpec(DHParameterSpec.class);

    					BigInteger pValue = specifications.getP();
						BigInteger gValue = specifications.getG();
						int lValue = specifications.getL();

						response = new Envelope("DH-PARAMS");
						response.addObject(pValue);
						response.addObject(gValue);
						response.addObject(lValue);

						// Encrypt response and write to client
						encryptedResponse = encryptEnvelope(response, passwordKey);
						output.writeObject(encryptedResponse);
						output.reset();

						// Get message from client and decrypt
						encryptedMessage = (SealedObject)input.readObject();
						message = (Envelope) decryptEnvelope(encryptedMessage, passwordKey);
						System.out.println("Request received (and decrypted): " + message.getMessage());

						if(message.getMessage().equals("DH-MODPOW"))
						{
							ArrayList<Object> temp = null;
							temp = message.getObjContents();

							if(temp.size() == 2) {
								BigInteger clientSessionModPow = (BigInteger) temp.get(0);
								BigInteger clientIntegrityModPow = (BigInteger) temp.get(1); 

								// Client generates random # b for session key
    							SecureRandom random = new SecureRandom();
    							BigInteger b = new BigInteger(lValue, random);

    							// Client generates random # d for integrity key
    							random = new SecureRandom();
    							BigInteger d = new BigInteger(lValue, random);

    							// Server performs DH MODPOW for session key
    							BigInteger serverSessionModPow = gValue.modPow(b, pValue);

    							// Server performs DH MODPOW for integrity key
    							BigInteger serverIntegrityModPow = gValue.modPow(d, pValue);

    							// Server computes kValue for session key
    							BigInteger kValueSession = clientSessionModPow.modPow(b, pValue);

    							// Server computes kValue for integrity key
    							BigInteger kValueIntegrity = clientIntegrityModPow.modPow(d, pValue);

    							// Server computes session key (SHA-256 hash of kValue)
    							byte[] sessionKeyHash = new byte[0];

    							// Try catch for server, hash values used as shared key
      							try {

							        // Declare SHA-256 hash function
							        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
							      
							        // Perform hash on user password
							        sha256.update(kValueSession.toByteArray());
							      
							        // Get user password hash
							        sessionKeyHash = sha256.digest();

							      } catch (Exception e) {
							        System.out.println("Error hashing value.");
							        System.exit(-1);
							      }

							    sessionKey = new SecretKeySpec(sessionKeyHash, "AES");

							    // Server computes session key (SHA-256 hash of kValue)
    							byte[] integrityKeyHash = new byte[0];

    							// Try catch for server, hash values used as shared key
      							try {

							        // Declare SHA-256 hash function
							        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
							      
							        // Perform hash on user password
							        sha256.update(kValueIntegrity.toByteArray());
							      
							        // Get user password hash
							        integrityKeyHash = sha256.digest();

							      } catch (Exception e) {
							        System.out.println("Error hashing value.");
							        System.exit(-1);
							      }

							    integrityKey = new SecretKeySpec(integrityKeyHash, "AES");

							    // Generate random challenge for client for session key
    							BigInteger firstChallenge = new BigInteger(1024, random);

    							// Generate random challenge for client for integrity key
    							BigInteger integrityFirstChallenge = new BigInteger(1024, random);

    							// Set session number to first challenge to add additional randomness
    							sessionNumber = firstChallenge;

    							// Send Encrypted Response to client
							   	response = new Envelope("DH-MODPOW-RESP");
							   	response.addObject(serverSessionModPow);
							   	response.addObject(firstChallenge);
							   	response.addObject(serverIntegrityModPow);
							   	response.addObject(integrityFirstChallenge);
							   	encryptedResponse = encryptEnvelope(response, passwordKey);
								output.writeObject(encryptedResponse);
								output.reset();

							   	// Get challenge from client and decrypt
							   	encryptedMessage = (SealedObject)input.readObject();
							   	message = (Envelope) decryptEnvelope(encryptedMessage, sessionKey);
								System.out.println("Request received (and decrypted): " + message.getMessage());

								if(message.getMessage().equals("CHALLENGE")) {
									temp = null;
									temp = message.getObjContents();

									if(temp.size() == 2) {

										// Get the challenges from the client
										BigInteger clientFirstChallenge = (BigInteger) temp.get(0);
										BigInteger secondChallenge = (BigInteger) temp.get(1);

										// Check to see that challenge match
										if(clientFirstChallenge.equals(firstChallenge)) {
										
											try	//read public key from file
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
   
												publicKey = kf.generatePublic(spec);
											}
											catch(Exception e)
											{
												System.out.println("ERROR: Group Public Key file not found! Shutting down.");
												System.exit(-1);
											}
											
											try	//read the private key from the file
											{
												File f = new File("groupPrivKey.txt");
												FileInputStream fis = new FileInputStream(f);
												DataInputStream dis = new DataInputStream(fis);
												byte[] keyBytes = new byte[(int)f.length()];
												dis.readFully(keyBytes);
												dis.close();

												PKCS8EncodedKeySpec spec =
												new PKCS8EncodedKeySpec(keyBytes);
												KeyFactory kf = KeyFactory.getInstance("RSA");
												privateKey = kf.generatePrivate(spec);
											}
											
											catch(Exception e)
											{
												System.out.println("ERROR: Group Private Key file not found! Shutting down.");
												System.exit(-1);
											}
										
											// User earned their token (almost)
											UserToken yourToken = createToken( username );
											yourToken.setSignature( signToken( yourToken ) );	//sign the token
											
											//System.out.println( "Signature before sending: " + yourToken.getSignature() );
											
											// Send encrypted second challenge back to client along with encrypted user token
											response = new Envelope("CHALLENGE-OK");
											response.addObject(secondChallenge);
											//response.addObject(yourToken);
											
											encryptedResponse = encryptEnvelope(response, sessionKey);
											output.writeObject(encryptedResponse);
											output.reset();

											// Get challenge from client and decrypt
										   	encryptedMessage = (SealedObject)input.readObject();
										   	message = (Envelope) decryptEnvelope(encryptedMessage, integrityKey);
											System.out.println("Request received (and decrypted): " + message.getMessage());

											if(message.getMessage().equals("CHALLENGE-INTEGRITY")) {
												temp = null;
												temp = message.getObjContents();

												if(temp.size() == 2) {

													// Get the challenges from the client
													BigInteger clientIntegrityFirstChallenge = (BigInteger) temp.get(0);
													BigInteger clientIntegritySecondChallenge = (BigInteger) temp.get(1);

													// Challenges match
													if(clientIntegrityFirstChallenge.equals(integrityFirstChallenge)) {
														// Send encrypted second challenge back to client along with encrypted user token
														response = new Envelope("CHALLENGE-INTEGRITY-OK");
														response.addObject(clientIntegritySecondChallenge);
														response.addObject(yourToken);

														encryptedResponse = encryptEnvelope(response, integrityKey);
														output.writeObject(encryptedResponse);
														output.reset();
													}
												}
											}
										}
									}
								}
							}

						}

					}
				}
				else if(message.getMessage().equals("ENC"))
				{

					encryptedMessage = (SealedObject)input.readObject();
					message = (Envelope) decryptEnvelope(encryptedMessage, sessionKey);
					System.out.println("Request decrypted to: " + message.getMessage());

					// Increment session number
					sessionNumber = sessionNumber.add(BigInteger.ONE);

					// takes hmac of envelope without hmac on the end
					byte[] hmac = hmac(recreateEnv(message));

					if(message.getMessage().equals("CUSER")) //Client wants to create a user
					{
						//System.out.println("Is Session Key Set? " + isSessionKeySet());

						if(message.getObjContents().size() < 4)
						{
							response = new Envelope("FAIL");
						}
						else
						{
							response = new Envelope("FAIL");
							
							if(message.getObjContents().get(0) != null)
							{
								if(message.getObjContents().get(1) != null)
								{
									if(message.getObjContents().get(2) != null)
									{

										if(message.getObjContents().get(3) != null) {

											String username = (String)message.getObjContents().get(0); //Extract the username
											UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
											byte[] hashedPassword = (byte[])message.getObjContents().get(2);	//Extact the hashed password
											byte[] clientHmac = (byte[])message.getObjContents().get(3);	// Extract hmac

											if(!MessageDigest.isEqual(clientHmac, hmac)) {
												response = new Envelope("FAIL");
												System.out.println("Error performing request: HMACs don't match.");
											} else {
												if( Token.verify( yourToken, publicKey ) && createUser(username, hashedPassword, yourToken) )	//ability to short-circuit
												{
													response = new Envelope("OK"); //Success
												}
											}
										}
										
									}
								}
							}
						}

						// Increment session number
						sessionNumber = sessionNumber.add(BigInteger.ONE);

						// Add hmac to response
						response.addObject(hmac(response));
						
						encryptedResponse = encryptEnvelope(response, sessionKey);
						output.writeObject(encryptedResponse);
						output.reset();
					}
					else if(message.getMessage().equals("DUSER")) //Client wants to delete a user
					{
						
						if(message.getObjContents().size() < 3)
						{
							response = new Envelope("FAIL");
						}
						else
						{
							response = new Envelope("FAIL");
							
							if(message.getObjContents().get(0) != null)
							{
								if(message.getObjContents().get(1) != null)
								{
									if(message.getObjContents().get(2) != null) {
										String username = (String)message.getObjContents().get(0); //Extract the username
										UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
										byte[] clientHmac = (byte[])message.getObjContents().get(2);	// Extract hmac
										
										if(!MessageDigest.isEqual(clientHmac, hmac)) {
												response = new Envelope("FAIL");
												System.out.println("Error performing request: HMACs don't match.");
										} else {
											if( Token.verify( yourToken, publicKey ) && deleteUser(username, yourToken) )
											{
												response = new Envelope("OK"); //Success
											}
										}
									}
								}
							}
						}

						// Increment session number
						sessionNumber = sessionNumber.add(BigInteger.ONE);

						// Add hmac to response
						response.addObject(hmac(response));
						
						encryptedResponse = encryptEnvelope(response, sessionKey);
						output.writeObject(encryptedResponse);
						output.reset();
					}
					else if(message.getMessage().equals("CGROUP")) //Client wants to create a group
					{
					    
						if( message.getObjContents().size() < 3)	//check if the size of message is correct
						{
							response = new Envelope("FAIL");
						}
						
						else
						{
							response = new Envelope("FAIL");
							
							if( message.getObjContents().get( 0 ) != null )
							{
								if( message.getObjContents().get( 1 ) != null )
								{
									if(message.getObjContents().get(2) != null) {
										//Get all parts of the object
										String groupname = (String)message.getObjContents().get( 0 );
										UserToken token = (UserToken)message.getObjContents().get( 1 );
										byte[] clientHmac = (byte[])message.getObjContents().get(2);	// Extract hmac
										
										if(!MessageDigest.isEqual(clientHmac, hmac)) {
												response = new Envelope("FAIL");
												System.out.println("Error performing request: HMACs don't match.");
										} else {
										
											if( Token.verify( token, publicKey ) && createGroup( groupname, token ) )	//final check incase the group is not an actual group
											{
												response = new Envelope("OK"); //Success
											}
										}
									}
								}
							}
						}

						// Increment session number
						sessionNumber = sessionNumber.add(BigInteger.ONE);

						// Add hmac to response
						response.addObject(hmac(response));

						encryptedResponse = encryptEnvelope(response, sessionKey);
						output.writeObject(encryptedResponse);
						output.reset();
						
					}
					else if(message.getMessage().equals("DGROUP")) //Client wants to delete a group
					{
					    
						if( message.getObjContents().size() < 3 )	//check if the size of message is correct
						{
							response = new Envelope("FAIL");
						}
						
						else
						{
							response = new Envelope("FAIL");
							
							if( message.getObjContents().get( 0 ) != null )
							{
								if( message.getObjContents().get( 1 ) != null )
								{
									if(message.getObjContents().get(2) != null) {
										//Get all parts of the object
										String groupname = (String)message.getObjContents().get( 0 );
										UserToken token = (UserToken)message.getObjContents().get( 1 );
										byte[] clientHmac = (byte[])message.getObjContents().get(2);	// Extract hmac
									
										if(!MessageDigest.isEqual(clientHmac, hmac)) {
												response = new Envelope("FAIL");
												System.out.println("Error performing request: HMACs don't match.");
										} else {
										
											if( Token.verify( token, publicKey ) && deleteGroup( groupname, token ) )	//final check incase the group is not an actual group
											{
												response = new Envelope("OK"); //Success
											}
										}
									}
								}
							}
						}

						// Increment session number
						sessionNumber = sessionNumber.add(BigInteger.ONE);

						// Add hmac to response
						response.addObject(hmac(response));

						encryptedResponse = encryptEnvelope(response, sessionKey);
						output.writeObject(encryptedResponse);
						output.reset();
						
					}
					else if(message.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
					{
					
						if( message.getObjContents().size() < 3)	//check if the size of message is correct
						{
							response = new Envelope("FAIL");
						}
						
						else
						{
							response = new Envelope("FAIL");
							
							if( message.getObjContents().get( 0 ) != null )
							{
								if( message.getObjContents().get( 1 ) != null )
								{
									if( message.getObjContents().get(2) != null ) {
										//Get all parts of the object
										String group = (String)message.getObjContents().get( 0 );
										UserToken token = (UserToken)message.getObjContents().get( 1 );
										byte[] clientHmac = (byte[])message.getObjContents().get(2);	// Extract hmac
									
										ArrayList<String> memberList = listMembers( group, token );	//get list of members
										
										if(!MessageDigest.isEqual(clientHmac, hmac)) {
												response = new Envelope("FAIL");
												System.out.println("Error performing request: HMACs don't match.");
										} else {
										
											if( Token.verify( token, publicKey ) && memberList != null  )	//final check incase the group is not an actual group
											{
												response = new Envelope("OK"); //Success
												//print everything in the list
												response.addObject(memberList);
											
											}
										}

									}
								}
							}
						}

						// Increment session number
						sessionNumber = sessionNumber.add(BigInteger.ONE);

						// Add hmac to response
						response.addObject(hmac(response));

						encryptedResponse = encryptEnvelope(response, sessionKey);
						output.writeObject(encryptedResponse);
						output.reset();
						
					}
					else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
					{
					
					    if( message.getObjContents().size() < 4 )	//check if the size of message is correct
						{
							response = new Envelope("FAIL");
						}
						
						else
						{
							response = new Envelope("FAIL");
							
							if( message.getObjContents().get( 0 ) != null )
							{
								if( message.getObjContents().get( 1 ) != null )
								{
									if( message.getObjContents().get( 2 ) != null )
									{
										if(message.getObjContents().get(3) != null) {
											//Get all parts of the object
											String username = (String)message.getObjContents().get( 0 );
											String groupname = (String)message.getObjContents().get( 1 );
											UserToken token = (UserToken)message.getObjContents().get( 2 );
											byte[] clientHmac = (byte[])message.getObjContents().get(3);	// Extract hmac
										
											if(!MessageDigest.isEqual(clientHmac, hmac)) {
													response = new Envelope("FAIL");
													System.out.println("Error performing request: HMACs don't match.");
											} else {

												if( Token.verify( token, publicKey ) && addUserToGroup( username, groupname, token ) )
												{
													response = new Envelope("OK"); //Success
												}

											}
										}
									}
								}
							}
						}

						// Increment session number
						sessionNumber = sessionNumber.add(BigInteger.ONE);

						// Add hmac to response
						response.addObject(hmac(response));

						encryptedResponse = encryptEnvelope(response, sessionKey);
						output.writeObject(encryptedResponse);
						output.reset();
						
					}
					else if(message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
					{			
						
						if( message.getObjContents().size() < 4 )	//check if the size of message is correct
						{
							response = new Envelope("FAIL");
						}
						
						else
						{
							response = new Envelope("FAIL");
							
							if( message.getObjContents().get( 0 ) != null )
							{
								if( message.getObjContents().get( 1 ) != null )
								{
									if( message.getObjContents().get( 2 ) != null )
									{
										if(message.getObjContents().get(3) != null) {
											//Get all parts of the object
											String username = (String)message.getObjContents().get( 0 );
											String groupname = (String)message.getObjContents().get( 1 );
											UserToken token = (UserToken)message.getObjContents().get( 2 );
											byte[] clientHmac = (byte[])message.getObjContents().get(3);	// Extract hmac
										
											if(!MessageDigest.isEqual(clientHmac, hmac)) {
													response = new Envelope("FAIL");
													System.out.println("Error performing request: HMACs don't match.");
											} else {
										
												if( Token.verify( token, publicKey ) && deleteUserFromGroup( username, groupname, token ) )	//verify token
												{
													response = new Envelope("OK"); //Success
												}

											}
										}
									}
								}
							}
						}

						// Increment session number
						sessionNumber = sessionNumber.add(BigInteger.ONE);

						// Add hmac to response
						response.addObject(hmac(response));

						encryptedResponse = encryptEnvelope(response, sessionKey);
						output.writeObject(encryptedResponse);
						output.reset();
						
					}
                    else if(message.getMessage().equals("USERGETFILEKEY")) //Client wants to retrieve key for file uploading/downloading
                    {           
                        if( message.getObjContents().size() < 6 )   //check if the size of message is correct
                        {
                            response = new Envelope("FAIL");
                        }
                        
                        else
                        {
                            response = new Envelope("FAIL");
                            
                            if( message.getObjContents().get( 0 ) != null )
                            {
                                if( message.getObjContents().get( 1 ) != null )
                                {
                                    if( message.getObjContents().get( 2 ) != null )
                                    {
                                        if(message.getObjContents().get(3) != null) 
                                        {
                                            if(message.getObjContents().get(4) != null)
                                            {
                                                if(message.getObjContents().get(5) != null){
                                                    //Get all parts of the object
                                                    ArrayList<String> groups = (ArrayList<String>)message.getObjContents().get( 0 );
                                                    String filename = (String)message.getObjContents().get( 1 );
                                                    String servername = (String)message.getObjContents().get( 2 );
                                                    String typeOfKey = (String)message.getObjContents().get( 3 );
                                                    UserToken token = (UserToken)message.getObjContents().get( 4 );
                                                    byte[] clientHmac = (byte[])message.getObjContents().get(5);    // Extract hmac
                                                
                                                    if(!MessageDigest.isEqual(clientHmac, hmac)) {
                                                            response = new Envelope("FAIL");
                                                            System.out.println("Error performing request: HMACs don't match.");
                                                    } else {
                                                
                                                        if( Token.verify( token, publicKey ) ) //verify token
                                                        {
                                                            SecretKey aKey = null;
                                                            byte[] anIV = null;
                                                            if(typeOfKey.equals("upload") || typeOfKey.equals("download"))//User is trying to obtain key to upload/download
                                                            {
                                                                
                                                                aKey = fileRequestKey(groups, filename, servername, typeOfKey, token);
                                                                anIV = fileRequestIV(groups, aKey);
                                            if(aKey == null){ System.out.println("KEY IS NULL GROUP THREAD.");}
                                            if(anIV == null || anIV.length != 16){ System.out.println("IV messed up GROUP THREAD.");}
                                                                
                                                            }
                                                            
                                                            if(aKey != null)
                                                            {
                                                                //ADD AES KEY TO RESPONSE
                                                                response = new Envelope("OK"); //Success
                                                                response.addObject(aKey);
                                                                response.addObject(anIV);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Increment session number
                        sessionNumber = sessionNumber.add(BigInteger.ONE);

                        // Add hmac to response
                        response.addObject(hmac(response));

                        encryptedResponse = encryptEnvelope(response, sessionKey);
                        output.writeObject(encryptedResponse);
                        output.reset();
                        
                    }
					else if( message.getMessage().equals("OBTAINFILETOKEN") )	//Client wants a token for a specific file server
					{
						if( message.getObjContents().size() < 3 )	//check if the size of message is correct
						{
							response = new Envelope("FAIL");
						}
						
						else
						{
							response = new Envelope("FAIL");
							
							if( message.getObjContents().get( 0 ) != null )
							{
								if( message.getObjContents().get( 1 ) != null )
								{
									if(message.getObjContents().get(2) != null) {
										//Get all parts of the object
										UserToken groupToken = (UserToken)message.getObjContents().get( 0 );	
										PublicKey fileServerPubKey = (PublicKey)message.getObjContents().get( 1 );
										byte[] clientHmac = (byte[])message.getObjContents().get(2);	// Extract hmac
										
										if(!MessageDigest.isEqual(clientHmac, hmac)) {
											response = new Envelope("FAIL");
											System.out.println("Error performing request: HMACs don't match.");
										} else {
										
											UserToken fileToken = obtainFileToken( groupToken, fileServerPubKey );	//create the specific file token
											
											if( Token.verify( groupToken, publicKey ) && fileToken != null )	//verify token, after creating new token, but still is safe incase someone changed part of the groupToken
											{
												response = new Envelope("OK"); //Success
												response.addObject( fileToken );	//add the fileToken to the server
											}
										}
									}
								}
							}
						}

						// Increment session number
						sessionNumber = sessionNumber.add(BigInteger.ONE);

						// Add hmac to response
						response.addObject(hmac(response));

						encryptedResponse = encryptEnvelope(response, sessionKey);
						output.writeObject(encryptedResponse);
						output.reset();
						
					} else if(message.getMessage().equals("DISCONNECT")) {
						if( message.getObjContents().size() < 1 )	//check if the size of message is correct
						{
							response = new Envelope("FAIL");
						}

						if( message.getObjContents().get( 0 ) != null )
						{
							byte[] clientHmac = (byte[])message.getObjContents().get(0);	// Extract hmac

							if(!MessageDigest.isEqual(clientHmac, hmac)) {
								response = new Envelope("FAIL");
								System.out.println("Error performing request: HMACs don't match.");
							} else {
								socket.close(); //Close the socket
								proceed = false; //End this communication loop
							}
						}

					}
					
				} else {
					response = new Envelope("FAIL"); //Server does not understand client request

					// Increment session number
					sessionNumber = sessionNumber.add(BigInteger.ONE);

					// Add hmac to response
					response.addObject(hmac(response));

					encryptedResponse = encryptEnvelope(response, sessionKey);
					output.writeObject(encryptedResponse);
					output.reset();
				}
			
			}while(proceed);	
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	
	//Method to create tokens
	private UserToken createToken(String username) 
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			//Issue a new token with server's name, user's name, and user's groups
			UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username));
			return yourToken;
		}
		else
		{
			return null;
		}
	}
	
	
	//Method to create a user
	private boolean createUser(String username, byte[] hashedPassword, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		//Check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			//Get the user's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administrator
			if(temp.contains("ADMIN"))
			{
				//Does user already exist?
				if(my_gs.userList.checkUser(username))
				{
					return false; //User already exists
				}
				else
				{
					my_gs.userList.addUser(username, hashedPassword); 
					return true;
				}
			}
			else
			{
				return false; //requester not an administrator
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}
	
	//Method to delete a user
	private boolean deleteUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administer
			if(temp.contains("ADMIN"))
			{
				//Does user exist?
				if(my_gs.userList.checkUser(username))
				{
					//User needs deleted from the groups they belong
					ArrayList<String> deleteFromGroups = new ArrayList<String>();
					
					//This will produce a hard copy of the list of groups this user belongs
					for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++)
					{
						deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
					}
					
					//Delete the user from the groups
					//If user is the owner, removeMember will automatically delete group!
					for(int index = 0; index < deleteFromGroups.size(); index++)
					{
						my_gs.groupList.removeMember(username, deleteFromGroups.get(index));
					}
					
					//If groups are owned, they must be deleted
					ArrayList<String> deleteOwnedGroup = new ArrayList<String>();
					
					//Make a hard copy of the user's ownership list
					for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++)
					{
						deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
					}
					
					//Delete owned groups
					for(int index = 0; index < deleteOwnedGroup.size(); index++)
					{
						//Use the delete group method. Token must be created for this action
						deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup));
					}
					
					//Delete the user from the user list
					my_gs.userList.deleteUser(username);
					
					return true;	
				}
				else
				{
					return false; //User does not exist
					
				}
			}
			else
			{
				return false; //requester is not an administer
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}

	//Method to create a group
	private boolean createGroup(String groupname, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		//Check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			
			//Does group already exist?
			if(my_gs.groupList.checkGroup(groupname))
			{
				return false; //Group already exists
			}
				else
			{
				/* 	Add new group to groupList, 
					add requester to new group, 
					give requester group ownership  */
				my_gs.groupList.addGroup(groupname);
				my_gs.groupList.addMember(requester, groupname);
				my_gs.groupList.addOwnership(requester, groupname);

				/* 	Add new group to requester User object, 
					tell requester User object that requester is group owner */
				my_gs.userList.addGroup(requester, groupname);
				my_gs.userList.addOwnership(requester, groupname);
				
				//Add the group to groupKeyList so that it can hold encryption keys for files
				my_gs.groupKeyList.addGroupToTable(groupname);

				return true;
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}
	
	//Method to delete a group
	private boolean deleteGroup(String groupname, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			//Does group exist?
			if(my_gs.groupList.checkGroup(groupname))
			{
				ArrayList<String> groupMembers = my_gs.groupList.getMembers(groupname);
				ArrayList<String> groupOwnership = my_gs.groupList.getGroupOwnership(groupname);
				
				//Is user a member of the group? Does the user have ownership?
				if(groupMembers.contains(requester) && groupOwnership.contains(requester))
				{


					// Remove group ownerships
					for(int index = 0; index < groupOwnership.size(); index++)
					{
						my_gs.groupList.removeOwnership(groupOwnership.get(index), groupname);
					}

					// Remove ownership from User object
					for(int index = 0; index < groupOwnership.size(); index++)
					{
						my_gs.userList.removeOwnership(groupOwnership.get(index), groupname);
					}

					// Remove group members from Group object
					for(int index = 0; index < groupOwnership.size(); index++) {
						my_gs.groupList.removeMember(groupMembers.get(index), groupname);
					}

					// Remove group from User object
					for(int index = 0; index < groupOwnership.size(); index++) {
						my_gs.userList.removeGroup(groupMembers.get(index), groupname);
					}

					// Delete group from groupList
					my_gs.groupList.deleteGroup(groupname);
					
					// Remove group from KeyTable
		            my_gs.groupKeyList.removeGroupFromTable(groupname);


					return true;

				}
				else
				{
					return false; //Requester is not an owner and/or member
				}
			}
			else
			{
				return false; //Group doesn't exist
			}
		}
		else
		{
			return false; //Request doesn't exist
		}
	
	}	
	
	private boolean addUserToGroup( String user, String group, UserToken token )	//if UserToken is the owner of the group, add user to the group
	{
		String requester = token.getSubject();
		
		if( my_gs.userList.checkUser( requester ) && my_gs.userList.checkUser( user ))	//does requester exist? does user exist?
		{
			if( my_gs.groupList.checkGroup( group ) )	//does group exist?
			{
				ArrayList<String> groupMembers = my_gs.groupList.getMembers( group );
				ArrayList<String> groupOwnership = my_gs.groupList.getGroupOwnership( group );
				
				//Is user NOT a member of the group and does the requester have ownership?
				if( !groupMembers.contains(user) && groupOwnership.contains(requester) )
				{
					my_gs.groupList.addMember( user, group );	// add user to the Group object
					my_gs.userList.addGroup(user, group);
					return true;
				}
				
				else
				{
					return false; //requester is not an owner and/or member
				}
			}
			
			else
			{
				return false; //requester not an administrator
			}
		}
		
		else
		{
			return false; //requester does not exist
		}
	}
	
	private boolean deleteUserFromGroup( String user, String group, UserToken token )	//if UserToken is the owner of the group, deleter the user from the group
	{
		String requester = token.getSubject();
		
		if( my_gs.userList.checkUser( requester ) && my_gs.userList.checkUser(user) )	//does requester exist? does user exist?
		{

			if( my_gs.groupList.checkGroup( group ) )	//does group exist?
			{
				ArrayList<String> groupMembers = my_gs.groupList.getMembers( group );
				ArrayList<String> groupOwnership = my_gs.groupList.getGroupOwnership( group );
				
				//Is requester a member of the group and does the requester have ownership? Is the user a group member?
				if( groupMembers.contains(requester) && groupOwnership.contains(requester) && groupMembers.contains(user) )
				{

					// is the user a group owner?
					if(groupOwnership.contains(user)) {
						my_gs.groupList.removeOwnership(user, group);
						my_gs.userList.removeOwnership(user, group);
					}

					my_gs.groupList.removeMember(user, group);	// remove user from Group object
					my_gs.userList.removeGroup(user, group);		// remove group from User object

					return true;
				}
				
				else
				{
					return false; //requester is not an owner and/or member
				}
			}
			
			else
			{
				return false; //group doesn't exist
			}
		}
		
		else
		{
			return false; //request doesn't exist
		}
	
	}
	
	private ArrayList<String> listMembers( String group, UserToken token )	//returns a list of members in the group if UserToken is the owner
	{
		String requester = token.getSubject();
		
		if( my_gs.userList.checkUser( requester ) )	//does requester exist?
		{

			if( my_gs.groupList.checkGroup( group ) )	//does group exist?
			{
				ArrayList<String> groupMembers = my_gs.groupList.getMembers( group );
				ArrayList<String> groupOwnership = my_gs.groupList.getGroupOwnership( group );
				
				//Is requester a member of the group and does the requester have ownership?
				if( groupMembers.contains(requester) && groupOwnership.contains(requester) )
				{
					return my_gs.groupList.getMembers( group );	// get the members of the group
				}
				
				else
				{
					return null; //requester is not an owner and/or member
				}
			}
			
			else
			{
				return null; //group doesn't exist
			}
		}
		
		else
		{
			return null; //request doesn't exist
		}

	}
	
    //Generates and returns an AES key to be used to encrypt the file to be uploaded to file server
    private SecretKey fileRequestKey(ArrayList<String> groups, String fileName, String serverName, String typeOfKey, UserToken token)
    {

        String requester = token.getSubject();
        
        if( my_gs.userList.checkUser( requester ) ) //does requester exist?
        {
            if(typeOfKey.equals("upload"))  //User wants new key to upload a new file
            {
                boolean result = my_gs.groupKeyList.addKey(groups.get(0), fileName, serverName);
                if(result)
                {
                    return my_gs.groupKeyList.retrieveKey(groups.get(0), fileName, serverName);
                }
                else
                {
                    System.out.println("Failed to generate AES key for client for uploading.");
                    return null;
                }
            }
            else if(typeOfKey.equals("download"))   //User wants existing key to download a file
            {
                
                return my_gs.groupKeyList.retrieveKey(groups, fileName, serverName);
            }
        }
        
        System.out.println("Failed to find key for group");
        return null;
 
    }

    //Retrieve's the IV for a given AES key
    private byte[] fileRequestIV(ArrayList<String> groups, SecretKey key)
    {
        return my_gs.groupKeyList.retrieveIV(groups, key);
    }
    
    //Checks if file is in the file listing to see if a key has been generated for it
    private boolean isFileInListing(String groupname, String filename, String fileserver)
    {
        return my_gs.groupKeyList.isFileInListing(groupname, filename, fileserver);
    }

	public SealedObject encryptEnvelope(Envelope env, SecretKeySpec key) throws Exception
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

	 public Envelope decryptEnvelope(SealedObject sealedEnv, SecretKeySpec key) throws Exception
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
	 
	 private byte[] signToken( UserToken token )	//sign the token and return the signature 
	 {
	 	byte[] signature = null;
	 	
		try 
		{
			Signature rsaSignature = Signature.getInstance("SHA256withRSA", "BC");	//use SHA256 with RSA as the rsa signature components
			rsaSignature.initSign( privateKey );	//initialize rsa signature
			rsaSignature.update( token.toString().getBytes() );	//give the input as the the encrypted message
			signature = rsaSignature.sign();
						
		}
		
		catch (Exception e) 
		{

    	}
		
		return signature;
	 }
	 
	public UserToken obtainFileToken( UserToken groupToken, PublicKey fileServerPubKey )	//create a specific file token for the user
	{
		UserToken fileToken = createToken( groupToken.getSubject() );	//create the token
		fileToken.setPublicKey( fileServerPubKey.getEncoded() );
		fileToken.setSignature( signToken( fileToken ) );	
		
		return fileToken;
	}
	 
	// tester methods to see if session key is set
	 public boolean isSessionKeySet() {
	 	return !(sessionKey == null);
	 }

	 // performs sha-256 hmac of envelope and session number
	 public byte[] hmac(Envelope env) throws Exception {
	 	Mac hmac = Mac.getInstance("HmacSHA256");
	 	hmac.init(integrityKey);

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
}
