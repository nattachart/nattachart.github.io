import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.oauth2.StoredCredential;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.store.DataStore;
import com.google.api.client.util.store.FileDataStoreFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.InputStream;
import java.io.Reader;
import java.net.URL;
import java.nio.file.Files;
import java.util.List;
import java.util.Set;

import javax.net.ssl.HttpsURLConnection;

/**
 * Shared class used by every sample. Contains methods for authorizing a user and caching credentials.
 */
public class Auth {
	/**
	 * Scope that allows managing a YouTube account
	 * @see	<a href="https://developers.google.com/youtube/v3/guides/authentication#installed-apps">https://developers.google.com/youtube/v3/guides/authentication#installed-apps</a>
	 */
	public static final String MANAGE_SCOPE = "https://www.googleapis.com/auth/youtube";
	
	/**
	 * Scope that allows only viewing a YouTube account
	 * @see	<a href="https://developers.google.com/youtube/v3/guides/authentication#installed-apps">https://developers.google.com/youtube/v3/guides/authentication#installed-apps</a>
	 */
	public static final String VIEW_SCOPE = "https://www.googleapis.com/auth/youtube.readonly";
	
	/**
	 * Scope that allows uploading and managing YouTube videos of a YouTube account
	 * @see	<a href="https://developers.google.com/youtube/v3/guides/authentication#installed-apps">https://developers.google.com/youtube/v3/guides/authentication#installed-apps</a>
	 */
	public static final String UPLOAD_SCOPE = "https://www.googleapis.com/auth/youtube.upload";
	
	/**
	 * Scope that allows retrieving the 'auditDetails' part in a 'channel' resource
	 * @see	<a href="https://developers.google.com/youtube/v3/guides/authentication#installed-apps">https://developers.google.com/youtube/v3/guides/authentication#installed-apps</a>
	 */
	public static final String CHANNEL_AUDIT_SCOPE = "https://www.googleapis.com/auth/youtubepartner-channel-audit";
	
    /**
     * Global instance of the HTTP transport.
     */
    public static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();

    /**
     * Global instance of the JSON factory.
     */
    public static final JsonFactory JSON_FACTORY = new JacksonFactory();

    /**
     * This is the directory that will be used under the user's home directory where OAuth tokens will be stored.
     */
    private static final String CREDENTIALS_DIRECTORY = ".oauth-credentials";
    
    /**
     * File name for the credential datastore
     */
    private String credentialDatastore;
    
    /**
     * List of scopes needed to use/modify YouTube data
     */
    private List<String> scopes;
    
    /**
     * Local port
     */
    private int port;
    
    /**
     * Constructor
     * @param scopes	List of scopes needed to use/modify YouTube data
     * @param credentialDatastore	File name for the credential datastore
     */
    public Auth(List<String> scopes, String credentialDatastore, int localPort){
    	this.credentialDatastore = credentialDatastore;
    	this.scopes = scopes;
    	this.port = localPort;
    }
    
    /**
     * Set a new list of scopes
     * @param scopes	List of scopes needed to use/modify YouTube data
     */
    public void setScopes(List<String> scopes){
    	this.scopes = scopes;
    }
    
    /**
     * Revoke all authorized tokens and remove the credential file, so that the next authorization is going to ask the user for permissions again. 
     * @return	HTTP response codes from requests for revoking tokens
     * @throws IOException
     * @throws ArrayIndexOutOfBoundsException
     */
    public String revoke() throws IOException, ArrayIndexOutOfBoundsException {
    	// This gets the credentials datastore at ~/.oauth-credentials/${credentialDatastore}
        FileDataStoreFactory fileDataStoreFactory = new FileDataStoreFactory(new File(System.getProperty("user.home") + "/" + CREDENTIALS_DIRECTORY));
        DataStore<StoredCredential> datastore = fileDataStoreFactory.getDataStore(credentialDatastore);
        String credentialPath = System.getProperty("user.home") + "/" + CREDENTIALS_DIRECTORY + "/" + credentialDatastore;
        Set<String> ks = datastore.keySet();
        //Get the key (there will be only one key in the set)
        String[] kss = ks.toArray(new String[0]);
        //Get the only item (StoredCredential) from the data store. This can raise ArrayIndexOutOfBoundsException if there is no credential file.
        StoredCredential sc = datastore.get(kss[0]);
        String accessToken = sc.getAccessToken();
        String refreshToken = sc.getRefreshToken();
        
        System.out.println("access token: "+accessToken);
        System.out.println("refresh token: "+refreshToken);
        
        //Send requests to revoke tokens, according to the description in https://developers.google.com/youtube/v3/guides/authentication#installed-apps
        String responseCodes = "";
        String baseUrl = "https://accounts.google.com/o/oauth2/revoke?token=";
        String url = baseUrl + accessToken;
        URL obj = new URL(url);
        HttpsURLConnection con = (HttpsURLConnection)obj.openConnection();
        con.setRequestMethod("GET");
        responseCodes += con.getResponseCode();
        
        //According to the document, this is not necessary, but just for a backup.
        url = baseUrl + refreshToken;
        obj = new URL(url);
        con = (HttpsURLConnection)obj.openConnection();
        con.setRequestMethod("GET");
        responseCodes += "," + con.getResponseCode();
        
        Files.delete(new File(credentialPath).toPath());	//Delete the credential file
        
        return responseCodes;
    }

    /**
     * Authorizes the installed application to access user's protected data.
     */
    public Credential authorize() throws IOException {

        // Load client secrets from the JSON file.
    	URL url = Auth.class.getProtectionDomain().getCodeSource().getLocation();
    	InputStream is = new FileInputStream(new File(url.getPath() + "../resources/client_secrets.json"));
        Reader clientSecretReader = new InputStreamReader(is);
        GoogleClientSecrets clientSecrets = GoogleClientSecrets.load(JSON_FACTORY, clientSecretReader);

        // Checks that the defaults have been replaced (Default = "Enter X here").
        if (clientSecrets.getDetails().getClientId().startsWith("Enter")
                || clientSecrets.getDetails().getClientSecret().startsWith("Enter ")) {
            System.out.println(
                    "Enter Client ID and Secret from https://code.google.com/apis/console/?api=youtube"
                            + "into src/main/resources/client_secrets.json");
            System.exit(1);
        }

        // This creates the credentials datastore at ~/.oauth-credentials/${credentialDatastore}
        FileDataStoreFactory fileDataStoreFactory = new FileDataStoreFactory(new File(System.getProperty("user.home") + "/" + CREDENTIALS_DIRECTORY));
        DataStore<StoredCredential> datastore = fileDataStoreFactory.getDataStore(credentialDatastore); //Get a data store (that contains the credentials) specified by the key credentialDatastore 
        
        // Redirect to an authorization page
        GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
                HTTP_TRANSPORT, JSON_FACTORY, clientSecrets, scopes).setCredentialDataStore(datastore)
                .build();

        // Build the local server and bind it to port 8889
        LocalServerReceiver localReceiver = new LocalServerReceiver.Builder().setPort(port).build();

        // Authorize.
        return new AuthorizationCodeInstalledApp(flow, localReceiver).authorize("user");
    }
}
