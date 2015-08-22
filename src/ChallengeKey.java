
import java.security.*;
import javax.crypto.*;
import java.math.BigInteger;

/* Class: ChallengeKey
 * 
 * A two part container for holding a large integer to be 
 * used as a challenge and for holding an AES key for a 
 * particular file server.
 * 
 */
public class ChallengeKey implements java.io.Serializable
{
    //private BigInteger challenge;       //Large integer
    private byte[] encodedSessionKey;   //Byte encoded AES session key
    private byte[] encodedChallenge;
    
    public ChallengeKey(byte[] c, byte[] s) {
        encodedChallenge = c;
        encodedSessionKey = s;
    }
    
    public byte[] getByteChallenge()
    {
        return encodedChallenge;
    }
    
    public byte[] getByteSessionKey()
    {
        return encodedSessionKey;
    }
}