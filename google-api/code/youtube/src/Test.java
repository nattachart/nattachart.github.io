import com.google.api.client.auth.oauth2.Credential;

import java.io.IOException;
import java.util.*;

public class Test {
	public static void main(String[] args){
		List<String> scopes = new ArrayList<String>();
		scopes.add(Auth.VIEW_SCOPE);
//		scopes.add(Auth.MANAGE_SCOPE);
//		scopes.add(Auth.UPLOAD_SCOPE);
//		scopes.add(Auth.CHANNEL_AUDIT_SCOPE);
		
		/*
		 *  Create an object of Auth with a fixed local port. 
		 *  This port can be any number that works.
		 *  If a number does not work, try another one.
		 *  A suggested starting number is 8080.
		 */
		Auth auth = new Auth(scopes, "test", 8889);
		Credential crd;
		
		/*
		 * This is the code to ask the user for granting permissions to this application (authorization, assuming that he/she has logged into his/her Google account already; if not, the Google will ask for authentication automatically)
		 */
		try {
			//Request for authorization (it will open a web browser for the user to grant permissions)
			crd = auth.authorize();
			
		} catch (IOException e) {
			//e.printStackTrace();
			System.out.println("Access Denied");
		}
		
		/*
		 * This is the code to revoke all permissions granted previously. It may be put at the end of the program.
		 */
		try{
			//Revoke all permissions granted in authorization phase. If the method revoke() returns 200,200, it's fine.
			System.out.println(auth.revoke());
		} catch(Exception e){
			System.out.println("The credential file does not exist.");
		}
		
		System.out.println("== Program Terminated ==");
	}
}
