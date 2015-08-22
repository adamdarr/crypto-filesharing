import java.util.*;
/* cryptography libraries */
import java.security.*;
import javax.crypto.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.spec.X509EncodedKeySpec;

public class Token implements UserToken, java.io.Serializable {

	private static final long serialVersionUID = 2094384630323093542L;

	private String gsName;
	private String username;
	private ArrayList<String> groupList;
	private byte[] fileServerPubKey;
	private byte[] groupSignature;
	
	public Token(String gsName, String username, ArrayList<String> groupList ) {
		this.gsName = gsName;
		this.username = username;
		this.groupList = groupList;
	}

	public String getIssuer() {
		return gsName;
	}

	public String getSubject() {
		return username;
	}

	public ArrayList<String> getGroups() {
		return groupList;
	}
	
	public String toString()	//toString method for signatures does not add publicKey and has delimeters for extra security
	{
		if( fileServerPubKey != null )	//will fall through here if this token is for a specific file token
		{
			return getIssuer() + "%" + getSubject() + "^" + getGroups().toString() + "&" + new String( fileServerPubKey );
		}
		
		else	//will fall through here if the token is for the group server(default token)
		{
			return getIssuer() + "%" + getSubject() + "^" + getGroups().toString();
		}
	}
	
	public void setPublicKey( byte[] publicKey )	//sets public key for the file server
	{
		fileServerPubKey = publicKey;
	}
	
	public PublicKey getPublicKey()
	{
		try
		{
			return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec( fileServerPubKey ));
		}
		catch(Exception e)
		{
			return null;	//error happened
		}
	}

	public void setSignature( byte[] signature )	//sets the signature
	{
		groupSignature = signature;
	}
	
	public byte[] getSignature()
	{
		return groupSignature;
	}
	
	//NOTE: this method is static and therefore it must be Token.verify()
	public static boolean verify( UserToken token, PublicKey publicKey )	//this will check if the token has been changed by using the signature
	{
		boolean verified = false;	//guilty until proven innocent 
		
		try
		{
			Signature rsaSignature = Signature.getInstance("SHA256withRSA", "BC");	//use SHA256 with RSA as the rsa signature compenents
			rsaSignature.initVerify( publicKey );	//initialized the verify with the correct public key for the thread
			rsaSignature.update( token.toString().getBytes() );	//get ready to verify	
			
			if( rsaSignature.verify( token.getSignature() ) )	//the token was not tampered with
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