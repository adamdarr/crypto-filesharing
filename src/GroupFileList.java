import java.util.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.*;
import java.security.*;
import javax.crypto.spec.IvParameterSpec;

public class GroupFileList implements java.io.Serializable
{
    private static final long serialVersionUID = 848732666483746652L;
    private Hashtable<String, ArrayList<FileEncrypt>> groupFileList = new Hashtable<String, ArrayList<FileEncrypt>>();
    
    public synchronized void addGroupToTable(String groupname)
    {
        ArrayList<FileEncrypt> keyList = new ArrayList<FileEncrypt>();
        groupFileList.put(groupname, keyList);        
    }
    
    public synchronized void removeGroupFromTable(String groupname)
    {
        groupFileList.remove(groupname);
    }
    
    public synchronized boolean addKey(String groupname, String filename, String fileserver)
    {
        if(isFileInListing(groupname, filename, fileserver))
        {
            return false;
        }
        else
        {
            ArrayList<FileEncrypt> files = groupFileList.get(groupname);
            FileEncrypt file = new FileEncrypt(filename, fileserver);
            files.add(file);
            groupFileList.put(groupname, files);
            return true;
        }
    }
    
    public synchronized boolean removeKey(String groupname, String filename, String fileserver)
    {
        ArrayList<FileEncrypt> files = groupFileList.get(groupname);
        if(files == null)
        {
            return false;
        }
        else
        {
            for(FileEncrypt file : files)
            {
                if(filename.equals(file.getName()) && fileserver.equals(file.getServer()))
                {
                    files.remove(file);
                    groupFileList.put(groupname, files);
                    return true;
                }
            }
        }
        return false;
    }
    
    public synchronized ArrayList<FileEncrypt> retrieveKeyRing(String groupname)
    {
        return groupFileList.get(groupname);
    }
    
    //Retrieve the IV padding for the provided AES key
    public synchronized byte[] retrieveIV(ArrayList<String> groups, SecretKey aKey)
    {
        SecretKey key = null;
        
        //System.out.println(toString());
        for(String group : groups)
        {
            //System.out.println("FOUND:" + group);
            ArrayList<FileEncrypt> files = groupFileList.get(group);
            if(files.size() > 0)
            {
                for(FileEncrypt file : files)
                {
                    if(aKey.equals(file.getKey()))
                    {
                        //System.out.println("SHOULD HAVE SUCCESSFULLY FOUND IV GROUPFILELIST");
                        return file.getIV();
                    }
                }
            }
        }
        //System.out.println("IT GOT HERE");
        return null;
        
    }
    
    //Retrieve an AES key for the particular file
    public synchronized SecretKey retrieveKey(String groupname, String filename, String fileserver)
    {
        SecretKey key = null;
        ArrayList<FileEncrypt> files = groupFileList.get(groupname);
        for(FileEncrypt file : files)
        {
            if(filename.equals(file.getName()) && fileserver.equals(file.getServer()))
            {
                return file.getKey();
            }
        }
        
        return null;
    }
    
    //Retrieve an AES key for the particular file
    public synchronized SecretKey retrieveKey(ArrayList<String> groups, String filename, String fileserver)
    {
        SecretKey key = null;
        
        //System.out.println(toString());
        for(String group : groups)
        {
            System.out.println("FOUND group:" + group);
            ArrayList<FileEncrypt> files = groupFileList.get(group);
            if(files.size() > 0)
            {
                for(FileEncrypt file : files)
                {
                    String foundFile = file.getName().substring(1);
                    //System.out.println("FOUND file: "+ foundFile);
                    if(filename.equals(foundFile) && fileserver.equals(file.getServer()))
                    {
                        //System.out.println("FOUND a matching key for downloader...");
                        return file.getKey();
                    }
                }
            }
        }
        //System.out.println("IT GOT HERE");
        return null;
    }
    
    public synchronized boolean isFileInListing(String groupname, String filename, String fileserver)
    {
        ArrayList<FileEncrypt> files = groupFileList.get(groupname);
        if(files == null)
        {
            return false;
        }
        else
        {
            for(FileEncrypt file : files)
            {
                if(filename.equals(file.getName()) && fileserver.equals(file.getServer()))
                {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    public synchronized int getSize()
    {
        return groupFileList.size();
    }
    
    public synchronized String toString()
    {
        StringBuilder s = new StringBuilder("");
        
        Iterator it = groupFileList.entrySet().iterator();
        while(it.hasNext())
        {
            Map.Entry pair = (Map.Entry)it.next();
            s.append(pair.getKey()).append(":\n");
            
            for(FileEncrypt file : (ArrayList<FileEncrypt>)pair.getValue())
            {
                s.append("    (").append(file.getName()).append(",").append(file.getServer()).append(")\n");
            }
        }
        
        return s.toString();
    }
    
    class FileEncrypt implements java.io.Serializable
    {
        private static final long serialVersionUID = -4837773729288463893L;
        private String name;
        private String fileServer;
        private SecretKey encryptKey;
        private byte[] IV;
        
        public FileEncrypt(String n, String fs)
        {
            name = n;
            fileServer = fs;
            encryptKey = null;
            generateKey();  //Generate an AES key
            generateIV();   //Generate IV for padding
System.out.println("GENERATED IV: "+IV);
        }
        
        public String getName()
        {
            return name;
        }
        
        public String getServer()
        {
            return fileServer;
        }
        
        public SecretKey getKey()
        {
            return encryptKey;
        }
        
        public byte[] getIV()
        {
            return IV;
        }
        
        //Generates an AES key for the FileEncrypt object
        private boolean generateKey()
        {
            Security.addProvider(new BouncyCastleProvider());
            try{
                KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
                keyGen.init(128);
                encryptKey = keyGen.generateKey();
                return true;
            }
            catch(Exception e)
            {
                return false;
            }
        }
        
        private boolean generateIV()
        {
            try
            {
                SecureRandom random = new SecureRandom();
                byte[] iv = new byte[16];
                random.nextBytes(iv);
                IV = iv;
                return true;
            }
            catch(Exception e)
            {
                return false;
            }
        }
    }  
}//END class GroupFileList