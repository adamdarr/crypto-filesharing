/* Implements the GroupClient Interface */

import java.util.ArrayList;
import java.util.List;
import java.io.ObjectInputStream;

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

public class GroupClient extends Client implements GroupClientInterface {

private SecretKeySpec passwordKey; 	
private SecretKeySpec sessionKey;
private SecretKeySpec integrityKey;
private BigInteger sessionNumber;	// used to prevent replay or reorder attacks

	 public UserToken getToken(String username, byte[] hashedPassword)
	 {
		try
		{
			Security.addProvider(new BouncyCastleProvider());

			UserToken token = null;
			Envelope message = null, response = null;
			SealedObject encryptedMessage, encryptedResponse;
		 		 	
			//Tell the server to return a token.
			message = new Envelope("GET");
			message.addObject(username); //Add user name string
			output.writeObject(message);
			output.reset();

			// Set shared key
			passwordKey = new SecretKeySpec(hashedPassword, "AES");
		
			//Get the response from the server
			encryptedResponse = (SealedObject)input.readObject();
			response = (Envelope) decryptEnvelope(encryptedResponse, passwordKey);
			
			if(response.getMessage().equals("DH-PARAMS"))
			{
				ArrayList<Object> temp = null;
				temp = response.getObjContents();

				if(temp.size() == 3) {
					BigInteger pValue = (BigInteger) temp.get(0);
					BigInteger gValue = (BigInteger) temp.get(1);
					int lValue = (int) temp.get(2);

					// Client generates random # a for session key handshake
    				SecureRandom random = new SecureRandom();
    				BigInteger a = new BigInteger(lValue, random);

    				// Client generates random # c for integrity key handshake
    				random = new SecureRandom();
    				BigInteger c = new BigInteger(lValue, random);

    				// Client performs DH MODPOW for session key 
    				BigInteger clientSessionModPow = gValue.modPow(a, pValue);

    				// Client performs DH MODPOW for integrity key
    				BigInteger clientIntegrityModPow = gValue.modPow(c, pValue);

					message = new Envelope("DH-MODPOW");
					message.addObject(clientSessionModPow);
					message.addObject(clientIntegrityModPow);
					
					// Encrypt message and write to server
					encryptedMessage = encryptEnvelope(message, passwordKey);
					output.writeObject(encryptedMessage);
					output.reset();
	
					//Get the response from the server
					encryptedResponse = (SealedObject)input.readObject();
					response = (Envelope) decryptEnvelope(encryptedResponse, passwordKey);

					if(response.getMessage().equals("DH-MODPOW-RESP"))
					{
						temp = null;
						temp = response.getObjContents();

						if(temp.size() == 4)
						{	
							BigInteger serverSessionModPow = (BigInteger) temp.get(0);
							BigInteger firstChallenge = (BigInteger) temp.get(1);
							BigInteger serverIntegrityModPow = (BigInteger) temp.get(2);
							BigInteger integrityFirstChallenge = (BigInteger) temp.get(3);

							// Set session number to first challenge to add additional randomness
    						sessionNumber = firstChallenge;

							// Client computes kValue for session key
    						BigInteger kValueSession = serverSessionModPow.modPow(a, pValue);

    						// Client computes kValue for integrity key
    						BigInteger kValueIntegrity = serverIntegrityModPow.modPow(c, pValue);

    						// Server computes session key (SHA-256 hash of kValue)
    						byte[] sessionKeyHash = new byte[0];

    						// Try catch for client, hash values used as shared key
      						try {
						       // Declare SHA-256 hash function
							    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
							      
						        // Perform hash on session key
						        sha256.update(kValueSession.toByteArray());
							      
						        // Get user password hash
						        sessionKeyHash = sha256.digest();

						      } catch (Exception e) {
						        System.out.println("Error hashing value.");
						        System.exit(-1);
						      }

						    // Set session key to our the key we just generated
						    sessionKey = new SecretKeySpec(sessionKeyHash, "AES");

						    // Server computes integrity key (SHA-256 hash of kValue)
    						byte[] integrityKeyHash = new byte[0];

    						// Try catch for client, hash values used as shared key
      						try {
						       // Declare SHA-256 hash function
							    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
							      
						        // Perform hash on session key
						        sha256.update(kValueIntegrity.toByteArray());
							      
						        // Get user password hash
						        integrityKeyHash = sha256.digest();

						      } catch (Exception e) {
						        System.out.println("Error hashing value.");
						        System.exit(-1);
						      }

						    // Set session key to our the key we just generated
						    integrityKey = new SecretKeySpec(integrityKeyHash, "AES");

							// Generate challenge for server using session key
						    BigInteger secondChallenge = new BigInteger(1024, random);

						    // Generate challenge for server using integrity key key
						    BigInteger integritySecondChallenge = new BigInteger(1024, random);

						    // Send first and second challenge back to server
						    message = new Envelope("CHALLENGE");
						    message.addObject(firstChallenge);
						    message.addObject(secondChallenge);

						    // Encrypt envelope
						    encryptedMessage = encryptEnvelope(message, sessionKey);
						    output.writeObject(encryptedMessage);
						    output.reset();

						    // Get server response and decrypt
						    encryptedResponse = (SealedObject)input.readObject();
						    response = (Envelope) decryptEnvelope(encryptedResponse, sessionKey);

							if(response.getMessage().equals("CHALLENGE-OK")) {
								temp = null;
								temp = response.getObjContents();

								if(temp.size() == 1) {
									BigInteger serverSecondChallenge = (BigInteger) temp.get(0);

									if(serverSecondChallenge.equals(secondChallenge)) {
										// Send first and second integrity challenges back to server
										message = new Envelope("CHALLENGE-INTEGRITY");
										message.addObject(integrityFirstChallenge);
										message.addObject(integritySecondChallenge);

										// Encrypt envelope
									    encryptedMessage = encryptEnvelope(message, integrityKey);
									    output.writeObject(encryptedMessage);
									    output.reset();

									    // Get server response and decrypt
									    encryptedResponse = (SealedObject)input.readObject();
									    response = (Envelope) decryptEnvelope(encryptedResponse, integrityKey);

									    if(response.getMessage().equals("CHALLENGE-INTEGRITY-OK")) {
									    	temp = null;
											temp = response.getObjContents();

											if(temp.size() == 2) {
												BigInteger serverIntegritySecondChallenge = (BigInteger) temp.get(0);

												if(serverIntegritySecondChallenge.equals(integritySecondChallenge)) {
													token = (UserToken) temp.get(1);
													return token;
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
			
			return null;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
		
	 }
	 
	 public boolean createUser(String username, byte[] hashedPassword, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				SealedObject encryptedMessage, encryptedResponse;

				//Tell group server to expect encrypted message
				message = new Envelope("ENC");
				output.writeObject(message);
				output.reset();

				// Increment session number
				sessionNumber = sessionNumber.add(BigInteger.ONE);

				//Tell the server to create a user
				message = new Envelope("CUSER");
				message.addObject(username); //Add user name string
				message.addObject(token); //Add the requester's token
				message.addObject(hashedPassword);	//Add the hashed password of the new user

				// Compute HMAC
				byte[] hmac = hmac(message);

				// Add hmac to object
				message.addObject(hmac);
				
				// Encrypt message and write to server
				encryptedMessage = encryptEnvelope(message, sessionKey);
				output.writeObject(encryptedMessage);
				output.reset();
			
				// Get server response and decrypt
				encryptedResponse = (SealedObject)input.readObject();
				response = (Envelope) decryptEnvelope(encryptedResponse, sessionKey);

				// Increment session number
				sessionNumber = sessionNumber.add(BigInteger.ONE);

				// takes hmac of envelope without hmac on the end
				hmac = hmac(recreateEnv(response));

				if(response.getObjContents().size() < 1) {
					System.out.println("Error: Server response too short.");
					return false;
				} else {
					if(response.getObjContents().get(0) != null) {
						byte[] serverHmac = (byte[]) response.getObjContents().get(0);
						if(!MessageDigest.isEqual(serverHmac, hmac)) {
							System.out.println("Error performing request: HMACs don't match.");
							return false;
						} else {
							//If server indicates success, return true
							if(response.getMessage().equals("OK"))
							{
								return true;
							}
						}
					}
				}
			
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteUser(String username, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				SealedObject encryptedMessage, encryptedResponse;

				//Tell group server to expect encrypted message
				message = new Envelope("ENC");
				output.writeObject(message);
				output.reset();

				// Increment session number
				sessionNumber = sessionNumber.add(BigInteger.ONE);
			 
				//Tell the server to delete a user
				message = new Envelope("DUSER");
				message.addObject(username); //Add user name
				message.addObject(token);  //Add requester's token

				// Compute HMAC
				byte[] hmac = hmac(message);

				// Add hmac to object
				message.addObject(hmac);
				
				// Encrypt message and write to server
				encryptedMessage = encryptEnvelope(message, sessionKey);
				output.writeObject(encryptedMessage);
				output.reset();
			
				// Get server response and decrypt
				encryptedResponse = (SealedObject)input.readObject();
				response = (Envelope) decryptEnvelope(encryptedResponse, sessionKey);

				// Increment session number
				sessionNumber = sessionNumber.add(BigInteger.ONE);
				
				// takes hmac of envelope without hmac on the end
				hmac = hmac(recreateEnv(response));

				if(response.getObjContents().size() < 1) {
					System.out.println("Error: Server response too short.");
					return false;
				} else {
					if(response.getObjContents().get(0) != null) {
						byte[] serverHmac = (byte[]) response.getObjContents().get(0);
						if(!MessageDigest.isEqual(serverHmac, hmac)) {
							System.out.println("Error performing request: HMACs don't match.");
							return false;
						} else {
							//If server indicates success, return true
							if(response.getMessage().equals("OK"))
							{
								return true;
							}
						}
					}
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean createGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				SealedObject encryptedMessage, encryptedResponse;

				//Tell group server to expect encrypted message
				message = new Envelope("ENC");
				output.writeObject(message);
				output.reset();

				// Increment session number
				sessionNumber = sessionNumber.add(BigInteger.ONE);

				//Tell the server to create a group
				message = new Envelope("CGROUP");
				message.addObject(groupname); //Add the group name string
				message.addObject(token); //Add the requester's token

				// Compute HMAC
				byte[] hmac = hmac(message);

				// Add hmac to object
				message.addObject(hmac);
				
				// Encrypt message and write to server
				encryptedMessage = encryptEnvelope(message, sessionKey);
				output.writeObject(encryptedMessage);
				output.reset();
			
				// Get server response and decrypt
				encryptedResponse = (SealedObject)input.readObject();
				response = (Envelope) decryptEnvelope(encryptedResponse, sessionKey);

				// Increment session number
				sessionNumber = sessionNumber.add(BigInteger.ONE);

				// takes hmac of envelope without hmac on the end
				hmac = hmac(recreateEnv(response));
				
				if(response.getObjContents().size() < 1) {
					System.out.println("Error: Server response too short.");
					return false;
				} else {
					if(response.getObjContents().get(0) != null) {
						byte[] serverHmac = (byte[]) response.getObjContents().get(0);
						if(!MessageDigest.isEqual(serverHmac, hmac)) {
							System.out.println("Error performing request: HMACs don't match.");
							return false;
						} else {
							//If server indicates success, return true
							if(response.getMessage().equals("OK"))
							{
								return true;
							}
						}
					}
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				SealedObject encryptedMessage, encryptedResponse;

				//Tell group server to expect encrypted message
				message = new Envelope("ENC");
				output.writeObject(message);
				output.reset();

				// Increment session number
				sessionNumber = sessionNumber.add(BigInteger.ONE);

				//Tell the server to delete a group
				message = new Envelope("DGROUP");
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token

				// Compute HMAC
				byte[] hmac = hmac(message);

				// Add hmac to object
				message.addObject(hmac);
				
				// Encrypt message and write to server
				encryptedMessage = encryptEnvelope(message, sessionKey);
				output.writeObject(encryptedMessage);
				output.reset();
			
				// Get server response and decrypt
				encryptedResponse = (SealedObject)input.readObject();
				response = (Envelope) decryptEnvelope(encryptedResponse, sessionKey);

				// Increment session number
				sessionNumber = sessionNumber.add(BigInteger.ONE);

				// takes hmac of envelope without hmac on the end
				hmac = hmac(recreateEnv(response));

				if(response.getObjContents().size() < 1) {
					System.out.println("Error: Server response too short.");
					return false;
				} else {
					if(response.getObjContents().get(0) != null) {
						byte[] serverHmac = (byte[]) response.getObjContents().get(0);
						if(!MessageDigest.isEqual(serverHmac, hmac)) {
							System.out.println("Error performing request: HMACs don't match.");
							return false;
						} else {
							//If server indicates success, return true
							if(response.getMessage().equals("OK"))
							{
								return true;
							}
						}
					}
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 @SuppressWarnings("unchecked")
	public List<String> listMembers(String group, UserToken token)
	 {
		 try
		 {
			 Envelope message = null, response = null;
			 SealedObject encryptedMessage, encryptedResponse;

			 //Tell group server to expect encrypted message
			message = new Envelope("ENC");
			output.writeObject(message);
			output.reset();

			// Increment session number
			sessionNumber = sessionNumber.add(BigInteger.ONE);

			 //Tell the server to return the member list
			 message = new Envelope("LMEMBERS");
			 message.addObject(group); //Add group name string
			 message.addObject(token); //Add requester's token

			 // Compute HMAC
			byte[] hmac = hmac(message);

			// Add hmac to object
			message.addObject(hmac);
			 
			 // Encrypt message and write to server
			encryptedMessage = encryptEnvelope(message, sessionKey);
			output.writeObject(encryptedMessage);
			output.reset();
			 
			 // Get server response and decrypt
			encryptedResponse = (SealedObject)input.readObject();
			response = (Envelope) decryptEnvelope(encryptedResponse, sessionKey);

			// Increment session number
			sessionNumber = sessionNumber.add(BigInteger.ONE);

			// takes hmac of envelope without hmac on the end
			hmac = hmac(recreateEnv(response));

			if(response.getObjContents().size() < 2) {
				System.out.println("Error: Server response too short.");
				return null;
			} else {
				if(response.getObjContents().get(0) != null) {
					if(response.getObjContents().get(1) != null) {
						byte[] serverHmac = (byte[]) response.getObjContents().get(1);
						if(!MessageDigest.isEqual(serverHmac, hmac)) {
							System.out.println("Error performing request: HMACs don't match.");
							return null;
						} else {
							//If server indicates success, return true
							if(response.getMessage().equals("OK"))
							{
								return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
							}
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
	 
	 public boolean addUserToGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				SealedObject encryptedMessage, encryptedResponse;

				//Tell group server to expect encrypted message
				message = new Envelope("ENC");
				output.writeObject(message);
				output.reset();

				// Increment session number
				sessionNumber = sessionNumber.add(BigInteger.ONE);

				//Tell the server to add a user to the group
				message = new Envelope("AUSERTOGROUP");
				message.addObject(username); //Add user name string
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token

				// Compute HMAC
				byte[] hmac = hmac(message);

				// Add hmac to object
				message.addObject(hmac);
				
				// Encrypt message and write to server
				encryptedMessage = encryptEnvelope(message, sessionKey);
				output.writeObject(encryptedMessage);
				output.reset();
			
				// Get server response and decrypt
				encryptedResponse = (SealedObject)input.readObject();
				response = (Envelope) decryptEnvelope(encryptedResponse, sessionKey);

				// Increment session number
				sessionNumber = sessionNumber.add(BigInteger.ONE);

				// takes hmac of envelope without hmac on the end
				hmac = hmac(recreateEnv(response));

				if(response.getObjContents().size() < 1) {
					System.out.println("Error: Server response too short.");
					return false;
				} else {
					if(response.getObjContents().get(0) != null) {
						byte[] serverHmac = (byte[]) response.getObjContents().get(0);
						if(!MessageDigest.isEqual(serverHmac, hmac)) {
							System.out.println("Error performing request: HMACs don't match.");
							return false;
						} else {
							//If server indicates success, return true
							if(response.getMessage().equals("OK"))
							{
								return true;
							}
						}
					}
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteUserFromGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				SealedObject encryptedMessage, encryptedResponse;

				//Tell group server to expect encrypted message
				message = new Envelope("ENC");
				output.writeObject(message);
				output.reset();

				// Increment session number
				sessionNumber = sessionNumber.add(BigInteger.ONE);

				//Tell the server to remove a user from the group
				message = new Envelope("RUSERFROMGROUP");
				message.addObject(username); //Add user name string
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token

				// Compute HMAC
				byte[] hmac = hmac(message);

				// Add hmac to object
				message.addObject(hmac);
				
				// Encrypt message and write to server
				encryptedMessage = encryptEnvelope(message, sessionKey);
				output.writeObject(encryptedMessage);
				output.reset();
			
				// Get server response and decrypt
				encryptedResponse = (SealedObject)input.readObject();
				response = (Envelope) decryptEnvelope(encryptedResponse, sessionKey);

				// Increment session number
				sessionNumber = sessionNumber.add(BigInteger.ONE);

				// takes hmac of envelope without hmac on the end
				hmac = hmac(recreateEnv(response));

				if(response.getObjContents().size() < 1) {
					System.out.println("Error: Server response too short.");
					return false;
				} else {
					if(response.getObjContents().get(0) != null) {
						byte[] serverHmac = (byte[]) response.getObjContents().get(0);
						if(!MessageDigest.isEqual(serverHmac, hmac)) {
							System.out.println("Error performing request: HMACs don't match.");
							return false;
						} else {
							//If server indicates success, return true
							if(response.getMessage().equals("OK"))
							{
								return true;
							}
						}
					}
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
     public byte[][] retrieveFileEncryptKey(ArrayList<String> groups, String filename, String fileserver, String keyType, UserToken token)
     {
         try
            {
                Envelope message = null, response = null;
                SealedObject encryptedMessage, encryptedResponse;

                //Tell group server to expect encrypted message
                message = new Envelope("ENC");
                output.writeObject(message);
                output.reset();

                // Increment session number
                sessionNumber = sessionNumber.add(BigInteger.ONE);

                //Tell the server to delete a group
                message = new Envelope("USERGETFILEKEY");
                message.addObject(groups); //Add group name string
                message.addObject(filename);//Add file name to string
                message.addObject(fileserver);//Add file server to string
                message.addObject(keyType);//Add type of key wanted
                message.addObject(token); //Add requester's token

                // Compute HMAC
                byte[] hmac = hmac(message);

                // Add hmac to object
                message.addObject(hmac);
                
                // Encrypt message and write to server
                encryptedMessage = encryptEnvelope(message, sessionKey);
                output.writeObject(encryptedMessage);
                output.reset();
            
                // Get server response and decrypt
                encryptedResponse = (SealedObject)input.readObject();
                response = (Envelope) decryptEnvelope(encryptedResponse, sessionKey);

                // Increment session number
                sessionNumber = sessionNumber.add(BigInteger.ONE);

                // takes hmac of envelope without hmac on the end
                hmac = hmac(recreateEnv(response));

                if(response.getObjContents().size() < 3) {
                    System.out.println("Error: Server response too short.");
                    return null;
                } else {
                    if(response.getObjContents().get(2) != null) {
                        byte[] serverHmac = (byte[]) response.getObjContents().get(2);
                        if(!MessageDigest.isEqual(serverHmac, hmac)) {
                            System.out.println("Error performing request: HMACs don't match.");
                            return null;
                        } else {
                            //If server indicates success, return true
                            if(response.getMessage().equals("OK"))
                            {
                                //System.out.println("USER GOT OK FOR SECRET KEY: GROUPCLIENT");
                                if(response.getObjContents().get(0) == null || response.getObjContents().get(1) == null)
                                {
                                    return null;
                                }
                                else
                                {
                                    //System.out.println("USER SHOULD DEFINITELY HAVE SECRET KEY: GROUPCLIENT");
                                    SecretKey key = (SecretKey)response.getObjContents().get(0);
                                    byte[] iv = (byte[])response.getObjContents().get(1);
                                    try
                                    {
                                        byte[][] keyInfo = new byte[2][];
                                        keyInfo[0] = key.getEncoded();
                                        keyInfo[1] = iv;
                                        return keyInfo;
                                    }
                                    catch(Exception ee)
                                    {
                                        System.out.println("Failed to retrieve file encryption keys.");
                                        return null;
                                    }
                                    //return (SecretKey)response.getObjContents().get(0);
                                }
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

	public UserToken getFileServerToken( UserToken groupToken, PublicKey fileServerPubKey )	//create a token that is specific to the file server public key
	{
		try
		{
			Envelope message = null, response = null;
			SealedObject encryptedMessage, encryptedResponse;

			//Tell group server to expect encrypted message
			message = new Envelope("ENC");
			output.writeObject(message);
			output.reset();

			// Increment session number
			sessionNumber = sessionNumber.add(BigInteger.ONE);

			//Tell the server to remove a user from the group
			message = new Envelope("OBTAINFILETOKEN");
			message.addObject( groupToken ); //Add the default token
			message.addObject( fileServerPubKey ); //Add the file server public key

			// Compute HMAC
			byte[] hmac = hmac(message);

			// Add hmac to object
			message.addObject(hmac);
				
			// Encrypt message and write to server
			encryptedMessage = encryptEnvelope(message, sessionKey);
			output.writeObject(encryptedMessage);
			output.reset();
			
			// Get server response and decrypt
			encryptedResponse = (SealedObject)input.readObject();
			response = (Envelope) decryptEnvelope(encryptedResponse, sessionKey);

			// Increment session number
			sessionNumber = sessionNumber.add(BigInteger.ONE);

			// takes hmac of envelope without hmac on the end
			hmac = hmac(recreateEnv(response));

			if(response.getObjContents().size() < 2) {
				System.out.println("Error: Server response too short.");
				return null;
			} else {
				if(response.getObjContents().get(0) != null) {
					if(response.getObjContents().get(1) != null) {
						byte[] serverHmac = (byte[]) response.getObjContents().get(1);
						if(!MessageDigest.isEqual(serverHmac, hmac)) {
							System.out.println("Error performing request: HMACs don't match.");
							return null;
						} else {
							//If server indicates success, return true
							if(response.getMessage().equals("OK"))
							{
								UserToken fileToken = (UserToken)response.getObjContents().get(0);	//get the specific file token from the message
								return fileToken;
							}
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

	// Overriding disconnect method in client.java
	public void disconnect()	 {
		if (isConnected()) {
			try
			{
				Envelope message = null, response = null;
				SealedObject encryptedMessage, encryptedResponse;

				//Tell group server to expect encrypted message
				message = new Envelope("ENC");
				output.writeObject(message);
				output.reset();

				// Increment session number
				sessionNumber = sessionNumber.add(BigInteger.ONE);

				message = new Envelope("DISCONNECT");

				// Compute HMAC
				byte[] hmac = hmac(message);

				// Add hmac to object
				message.addObject(hmac);

				// Encrypt message and write to server
				encryptedMessage = encryptEnvelope(message, sessionKey);
				output.writeObject(encryptedMessage);
				output.reset();
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}
	
}
