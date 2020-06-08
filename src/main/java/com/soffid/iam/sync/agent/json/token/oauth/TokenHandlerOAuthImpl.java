package com.soffid.iam.sync.agent.json.token.oauth;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.ws.rs.core.MediaType;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.wink.client.ClientAuthenticationException;
import org.apache.wink.client.ClientRequest;
import org.apache.wink.client.ClientResponse;
import org.apache.wink.client.Resource;
import org.apache.wink.client.RestClient;
import org.apache.wink.client.handlers.HandlerContext;
import org.apache.wink.common.http.HttpStatus;
import org.json.JSONException;
import org.json.JSONObject;

import es.caib.seycon.ng.comu.Password;

public class TokenHandlerOAuthImpl extends TokenHandlerOAuth {

	Log log = LogFactory.getLog(getClass());

	public TokenHandlerOAuthImpl(String tokenURL, String user, Password password, String tokenAttribute,
			Map<String, String> oauthParams) {
		setTokenURL(tokenURL);
		setUser(user);
		setPassword(password);
		setTokenAttribute(tokenAttribute);
		setOauthParams(oauthParams);
	}

	public ClientResponse handle(ClientRequest request, HandlerContext context) throws Exception {
		if (getAuthToken() == null || checkExpiredToken())
			requestAuthToken();
		if (getAuthToken() != null) {
			String auth = ("Bearer "+getAuthToken());
			if (request.getHeaders().containsKey("Authorization")) {
				List<String> list = request.getHeaders().get("Authorization");
				list.add(auth);
				request.getHeaders().put("Authorization", list);
			} else {
				request.getHeaders().putSingle("Authorization", auth);
			}
		}
		System.out.println("TokenHandlerOAuthCC.handle() - doChain()");
		return context.doChain(request);
	}

	/**
	 * Obtains a token to be used in upcoming requests
	 * @throws JSONException
	 * @throws UnsupportedEncodingException 
	 */
	private void requestAuthToken() throws JSONException, UnsupportedEncodingException {		
		if (getRefreshToken() != null && checkExpiredToken()) {
			requestWithToken();
		} else { 
			requestNewToken();
		}
	}

	/**
	 * Request a new token
	 * @param config
	 * @throws JSONException
	 * @throws UnsupportedEncodingException 
	 */
	private void requestNewToken() throws JSONException, UnsupportedEncodingException {
		RestClient client = new RestClient();
		Resource rsc = client.resource(getTokenURL());
		boolean authBasicRequired = isBasicAuthRequired();
		if (authBasicRequired) {
			rsc.header("Authorization", getEncodedString(getOauthParams().get(CLIENT_ID), getOauthParams().get(CLIENT_SECRET)));
		}
		ClientResponse response = rsc
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.accept(MediaType.APPLICATION_JSON)
				.post(getBodyOAuthParams(getOauthParams(), authBasicRequired));
		System.out.println("TokenHandlerOAuthCC.requestNewToken() - response="+response);
		System.out.println("TokenHandlerOAuthCC.requestNewToken() - response.getStatusCode()="+response.getStatusCode());

		if (response.getStatusCode() == HttpStatus.OK.getCode()) {
			String result = response.getEntity(String.class);	
			fillResponseData(result);
			if (getAuthToken() == null)
				throw new ClientAuthenticationException("Unable to get auth token. Server returned "+response.getMessage());
		} else {
			System.out.println("TokenHandlerOAuthCC.requestNewToken() - response.getMessage()="+response.getMessage());
			throw new ClientAuthenticationException("Unable to get auth token. Server returned "+response.getMessage());
		}
	}
	
	private boolean isBasicAuthRequired() {
		if(PASSWORD.equals(getOauthParams().get(GRANT_TYPE)) && getOauthParams().get(CLIENT_ID) != null 
				&& !"".equals(getOauthParams().get(CLIENT_ID)) && getOauthParams().get(CLIENT_SECRET) != null 
				&& !"".equals(getOauthParams().get(CLIENT_SECRET)))
			return true;
		return false;				
	}

	/**
	 * Refresh a token
	 * @param config
	 * @throws JSONException
	 * @throws UnsupportedEncodingException 
	 */
	private void requestWithToken() throws JSONException, UnsupportedEncodingException {
		RestClient client = new RestClient();
		Resource rsc = client.resource(getTokenURL());
		ClientResponse response = rsc
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.accept(MediaType.APPLICATION_JSON)
				.post(getRefreshParams());
		System.out.println("TokenHandlerOAuthCC.requestNewToken() - response="+response);
		System.out.println("TokenHandlerOAuthCC.requestNewToken() - response.getStatusCode()="+response.getStatusCode());

		if (response.getStatusCode() == HttpStatus.OK.getCode()) {
			String result = response.getEntity(String.class);	
			fillResponseData(result);
			if (getAuthToken() == null)
				throw new ClientAuthenticationException("Unable to get auth token. Server returned "+response.getMessage());
		} else {
			System.out.println("TokenHandlerOAuthCC.requestNewToken() - couldn't obtanin a token, retrying");
			requestNewToken();
		}
	}

	/**
	 * Fills the class attributes with the data obtained in the response  
	 * @param result
	 * @throws JSONException
	 */
	private void fillResponseData(String result) throws JSONException {
		JSONObject jsonResult = new JSONObject(result);
		Date now = new Date();
		setRequestedTime(now.getTime());
		
		if (getTokenAttribute().isEmpty())
			setAuthToken(jsonResult.getString(ACCESS_TOKEN));
		else
			setAuthToken(jsonResult.getString(getTokenAttribute()));
		
		if (jsonResult.has(EXPIRES_IN))
			setExpiresIn(Long.valueOf(jsonResult.getInt(EXPIRES_IN)));
		
		if (jsonResult.has(REFRESH_TOKEN))
			setRefreshToken(jsonResult.getString(REFRESH_TOKEN));
	}
	
	/**
	 * Gets the submitted-view oauth params to build the body request
	 * @param oauthParams
	 * @param authBasicRequired 
	 * @return
	 * @throws UnsupportedEncodingException 
	 */
	private String getBodyOAuthParams(Map<String, String> oauthParams, boolean authBasicRequired) throws UnsupportedEncodingException {
		
		if (getUser() != null && !"".equals(getUser()) 
				&& getPassword() != null && !"".equals(getPassword().getPassword())) {
			oauthParams.put(USERNAME, getUser());
			oauthParams.put(PASSWORD, getPassword().getPassword());
		}
		
		List<String> params = new ArrayList<String>();	
		for (Map.Entry<String,String> entry : oauthParams.entrySet()) {
			if (entry.getValue() != null && !"".equals(entry.getValue())) {
				if ((CLIENT_ID.equals(entry.getKey()) || CLIENT_SECRET.equals(entry.getKey())) && authBasicRequired) {
					continue;
				}
				params.add(URLEncoder.encode(entry.getKey(), "UTF-8").concat("=")
						.concat(URLEncoder.encode(entry.getValue(), "UTF-8")));
			}
				
		}
		
		Collections.sort(params, new TokenOAuthSorter());
		return params.stream().collect(Collectors.joining("&"));
	}
	
	/**
	 * Gets the params to be used into the refresh_token request
	 * @return
	 * 	the map with the results
	 * @throws UnsupportedEncodingException 
	 */
	private String getRefreshParams() throws UnsupportedEncodingException {
		Map<String, String> oauthParams = getOauthParams();
		Map<String, String> refreshParams = new HashMap<String,String>();
		
		refreshParams.put(GRANT_TYPE, REFRESH_TOKEN);
		refreshParams.put(REFRESH_TOKEN, getRefreshToken());
		if (oauthParams.containsKey(CLIENT_ID)) {
			refreshParams.put(CLIENT_ID, oauthParams.get(CLIENT_ID));
		}
		
		if (oauthParams.containsKey(CLIENT_SECRET)) {
			refreshParams.put(CLIENT_SECRET, oauthParams.get(CLIENT_SECRET));
		}
		
		List<String> params = new ArrayList<String>();
		for (Map.Entry<String,String> entry : refreshParams.entrySet()) {
			if (entry.getValue() != null && !"".equals(entry.getValue())) {
				params.add(URLEncoder.encode(entry.getKey(), "UTF-8").concat("=")
						.concat(URLEncoder.encode(entry.getValue(), "UTF-8")));
			}
		}
		
		Collections.sort(params, new TokenOAuthSorter());
		return params.stream().collect(Collectors.joining("&"));
	}
	
	/**
	 * Checks if a token has expired
	 * @return
	 * 	boolean
	 */
	private boolean checkExpiredToken() {
		Date now = new Date();
		if (getExpiresIn() != 0L) {
			return now.getTime() > (getRequestedTime() + getExpiresIn());  
		}
		return true;
	}
}
