import java.net.Socket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.*;
import javax.crypto.*;
import java.util.*;
import java.math.BigInteger;

public abstract class Client {

	/* protected keyword is like private but subclasses have access
	 * Socket and input/output streams
	 */
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;

	public boolean connect(final String server, final int port) {

		System.out.println("attempting to connect");

		try {
			// Connect to server
			sock = new Socket(server, port);

			// Intialize input / output streams
			output = new ObjectOutputStream(sock.getOutputStream());
			output.flush();
			input = new ObjectInputStream(sock.getInputStream());
			
		//ONCE CONNECTION IS ESTABLISHED: CLIENT MUST EXPECT PUZZLE
			Envelope puzzle = (Envelope)input.readObject();
			if(puzzle.getMessage().equals("PUZZLE"))
			{
			    //Get the number of digits
			    int N = (int)puzzle.getObjContents().get(0);
			    
			    //Get the hashed number
			    byte[] h_of_R = (byte [])puzzle.getObjContents().get(1);
			    
			    //Build the starting value
	            StringBuilder sb = new StringBuilder();
	            for(int i = 0; i < N; i++)
	            {
	                if(i == 0)
	                {
	                    sb.append(1);
	                }
	                else
	                {
	                    sb.append(0);
	                }
	            }
			    
	            //Initialize the number and byte array to hold each hash
			    BigInteger X = new BigInteger(sb.toString());
	            byte[] h_of_X = new byte[0];
	            
	            try
	            {
                    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
	                while(true)
	                {
	                    //Generate new hash of X
	                    sha256.update(X.toByteArray());
	                    h_of_X = sha256.digest();
	                    //System.out.println(X);
	                    
	                    //Check if H(X) == H(R)
	                    if(Arrays.equals(h_of_X, h_of_R))
	                    {
	                        break;
	                    }
	                    
	                    //ADD one to the number if hash incorrect
	                    X = X.add(BigInteger.ONE);
	                }
	                
	                //Once hash correct send the number found
	                Envelope answer = new Envelope("ANSWER");
	                answer.addObject(X);
	                output.writeObject(answer);
	                output.reset();
	            }
	            catch(Exception e)
	            {
	                System.out.println("FAIL to hash.");
	                return false;
	            }
	            
			}
			else
			{
			    return false;
			}
			
			//Verify that the Server gave SUCCESS on the number
			Envelope answerResponse = (Envelope)input.readObject();
			if(answerResponse.getMessage().equals("SUCCESS"))
			{
			    return true;
			}
			else
			{
			    return false;
			}

			//return true;
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);

			return false;
		}

	}

	public boolean isConnected() {
		if (sock == null || !sock.isConnected()) {
			return false;
		}
		else {
			return true;
		}
	}

	public void disconnect()	 {
		if (isConnected()) {
			try
			{
				Envelope message = new Envelope("DISCONNECT");
				output.writeObject(message);
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}
}
