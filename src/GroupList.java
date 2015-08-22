/* This list represents the users on the server */
import java.util.*;


	public class GroupList implements java.io.Serializable {
	
		/**
		 * 
		 */
		private static final long serialVersionUID = 4014746912878115063L;
		private Hashtable<String, Group> list = new Hashtable<String, Group>();
		
		public synchronized void addGroup(String groupname)
		{
			Group newGroup = new Group();
			list.put(groupname, newGroup);
		}
		
		public synchronized void deleteGroup(String groupname)
		{
			list.remove(groupname);
		}
		
		public synchronized boolean checkGroup(String groupname)
		{
			if(list.containsKey(groupname))
			{
				return true;
			}
			else
			{
				return false;
			}
		}
		
		public synchronized ArrayList<String> getMembers(String groupname)
		{
			return list.get(groupname).getUsers();
		}
		
		public synchronized ArrayList<String> getGroupOwnership(String groupname)
		{
			return list.get(groupname).getOwnership();
		}
		
		public synchronized void addMember(String user, String groupname)
		{
			list.get(groupname).addUser(user);
		}
		
		public synchronized void removeMember(String user, String groupname)
		{
			list.get(groupname).removeUser(user);
		}
		
		public synchronized void addOwnership(String user, String groupname)
		{
			list.get(groupname).addOwnership(user);
		}
		
		public synchronized void removeOwnership(String user, String groupname)
		{
			list.get(groupname).removeOwnership(user);
		}

		// additional method to return the list of groups
		public synchronized Hashtable<String, Group> getGroups() {
			return list;
		}
		
	
	class Group implements java.io.Serializable {

		/**
		 * 
		 */
		private static final long serialVersionUID = -5468331312495876031L;	
		private ArrayList<String> users;
		private ArrayList<String> ownership;
		
		public Group()
		{
			users = new ArrayList<String>();
			ownership = new ArrayList<String>();
		}
		
		public ArrayList<String> getUsers()
		{
			return users;
		}
		
		public ArrayList<String> getOwnership()
		{
			return ownership;
		}
		
		public void addUser(String user)
		{
			users.add(user);
		}
		
		public void removeUser(String user)
		{
			if(!users.isEmpty())
			{
				if(users.contains(user))
				{
					users.remove(users.indexOf(user));
				}
			}
		}
		
		public void addOwnership(String user)
		{
			ownership.add(user);
		}
		
		public void removeOwnership(String user)
		{
			if(!ownership.isEmpty())
			{
				if(ownership.contains(user))
				{
					ownership.remove(ownership.indexOf(user));
				}
			}
		}
		
	}
	
}	
