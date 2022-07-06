package com.iamse.service;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.net.ssl.HttpsURLConnection;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.MediaType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONObject;


@Path("/PasswordMigration")
public class PasswordMigration
{
  public PasswordMigration() {}
  
  private static final Logger logger = LogManager.getLogger(PasswordMigration.class.getName());
  private static final String PROP_FILE = "iamse.properties";
  private Properties props = new Properties();
  
  @POST
  @Path("/verify")
  @Consumes({"application/json"})
  public Response verify(String message) {
    logger.debug("PasswordMigration/verify Service called via POST ...");
    logger.debug("Passed body=" + message);
    URL endpoint = null;
    HttpsURLConnection connection = null;
	int responseCode = 0;
	JSONObject responseObject = null;
	byte[] postData = null;
	int postDataLength = 0;
	// Default the response to UNVERIFIED and only overwrite once correctly authenticated
	String jsonResponse = "{\"commands\": [{\"type\": \"com.okta.action.update\", \"value\": {\"credential\": \"UNVERIFIED\"}}]}";
	
    // Load iamse.properties file
    loadProperties();
    
    // Load request parameters, including the passed username and password
    JSONObject jsonObject = new JSONObject(message);
    HashMap<String, String> params = new HashMap<String, String>();
    params.put("grant_type", "password");
    params.put("username", jsonObject.getJSONObject("data").getJSONObject("context").getJSONObject("credential").getString("username"));
    params.put("client_id", props.getProperty("client_id"));
    params.put("password", jsonObject.getJSONObject("data").getJSONObject("context").getJSONObject("credential").getString("password"));
    params.put("scope", "openid");
    
	// Encode the request parameters
	try {
		String data = getDataString(params);
		postData = data.getBytes(StandardCharsets.UTF_8);
		postDataLength = postData.length;
	} 
	catch (UnsupportedEncodingException e) {
		return Response.serverError().build();
	}
    
    try {
    	// Open connection to token endpoint
    	endpoint = new URL(props.getProperty("token_endpoint"));
		logger.debug("About to establish connection to server ...");
		connection = (HttpsURLConnection) endpoint.openConnection();
		connection.setRequestMethod("POST");
		connection.setRequestProperty("Content-type", "application/x-www-form-urlencoded");
		connection.setDoOutput(true);		
		connection.setInstanceFollowRedirects(false);
		connection.setRequestProperty("charset", "utf-8");
		connection.setRequestProperty("Content-Length", Integer.toString(postDataLength ));
		connection.setUseCaches(false);
		
		// Send encoded data
		DataOutputStream wr = new DataOutputStream(connection.getOutputStream());
		wr.write(postData);
		wr.flush();
		wr.close();
		responseCode = connection.getResponseCode();
		logger.debug("POST completed ...");	

		// Ensure we have a 200 response, otherwise UNVERIFIED will be returned
		if (responseCode == 200) {
			// Extract response payload
			BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
			String inputLine;
			StringBuffer getResponse = new StringBuffer();
			while ((inputLine = in.readLine()) != null) {
				getResponse.append(inputLine);
			}
			in.close();
			
			// Parse the response
			responseObject = new JSONObject(getResponse.toString());
			
			// Ensure the response contains an access token
			try {
				responseObject.getString("access_token");
				logger.debug("Found access_token ...");	
				// Change response to VERIFIED
				jsonResponse = "{\"commands\": [{\"type\": \"com.okta.action.update\", \"value\": {\"credential\": \"VERIFIED\"}}]}";
			} catch (Exception e) {} // Ignore exception if not found
		}
	} 
    catch (Exception e) {
    	  return Response.serverError().build();
	}

    logger.debug("JSON Response=" + jsonResponse);
    return Response.ok(jsonResponse, MediaType.APPLICATION_JSON).build();

  }
  
	/**
	 * Encode params
	 * @param params
	 * @return
	 * @throws UnsupportedEncodingException
	 */
	private String getDataString(HashMap<String, String> params) throws UnsupportedEncodingException{
	    StringBuilder result = new StringBuilder();
	    boolean first = true;
	    for(Map.Entry<String, String> entry : params.entrySet()){
	        if (first)
	            first = false;
	        else
	            result.append("&");    
	        result.append(URLEncoder.encode(entry.getKey(), "UTF-8"));
	        result.append("=");
	        result.append(URLEncoder.encode(entry.getValue(), "UTF-8"));
	    }    
	    return result.toString();
	}

	/**
	 * Load property file into property object
	 */
	private void loadProperties() {
		
		FileInputStream fis;
		String absolutePath = this.getClass().getClassLoader().getResource("").getPath();

		try {
			fis = new FileInputStream(absolutePath + PROP_FILE);
			props.load(fis);
		} 
		// Client properties file not found, so use the default property file
		catch (FileNotFoundException e) {}
		catch (IOException e) {}
	}

}
