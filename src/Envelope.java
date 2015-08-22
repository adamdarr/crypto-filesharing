import java.util.ArrayList;
import java.util.Arrays;
import java.lang.StringBuilder;

public class Envelope implements java.io.Serializable {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -7726335089122193103L;
	private String msg;
	private ArrayList<Object> objContents = new ArrayList<Object>();
	
	public Envelope(String text)
	{
		msg = text;
	}
	
	public String getMessage()
	{
		return msg;
	}
	
	public ArrayList<Object> getObjContents()
	{
		return objContents;
	}
	
	public void addObject(Object object)
	{
		objContents.add(object);
	}

	// convert envelope to string
	public String toString() {
		StringBuilder sb = new StringBuilder();

		for(int i = 0; i < objContents.size(); i++) {
			sb.append("\n");
			if(objContents.get(i) instanceof byte[]) {
				sb.append(new String((byte[]) objContents.get(i)));
			} else {
				sb.append(objContents.get(i));
			}
		}

		return sb.toString();

	}

	// convert envelope to byte array
	public byte[] toByteArray() {
		return toString().getBytes();
	}

}
