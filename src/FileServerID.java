import java.security.*;
import java.io.Serializable;
import java.util.Arrays;
import java.util.ArrayList;

/* Class: FileServerID
 * 
 * A three part container for holding a file servers IP address,
 * the port to connect to and the File Servers public key.
 * 
 * Houses methods for checking if a file server is a part of 
 * a collection of file servers.
 * 
 */
public class FileServerID implements Serializable
{
    private String address;
    private int port;
    private PublicKey key;
    
    public FileServerID(String a, int p, PublicKey k)
    {
        address = a;
        port = p;
        key = k;        
    }
    
    public String getAddress()
    {
        return address;
    }
    
    public int getPort()
    {
        return port;
    }
    
    public PublicKey getKey()
    {
        return key;
    }
    
    //Check if this file server is equal to another file server
    public boolean equals(FileServerID checkFS)
    {
        if(this.address.equals(checkFS.getAddress()) &&
           this.port == checkFS.getPort() &&
           Arrays.equals(this.key.getEncoded(), checkFS.getKey().getEncoded()))
        {
            return true;
        }
        
        return false;        
    }
    
    //Check if this file server is in a FileServerID list
    //Or rather, check if this file server is a trusted file server
    public boolean isTrustedServer(ArrayList<FileServerID> fsList)
    {
        boolean toReturn = false;
        for(FileServerID fs : fsList)
        {
            if(this.equals(fs)) { toReturn = true; }
        }
        
        return toReturn;
    }
    
}