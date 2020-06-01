package com.soffid.iam.sync.agent.json.token.oauth;

import java.util.HashMap;
import java.util.Map;

import org.apache.wink.client.handlers.AbstractAuthSecurityHandler;
import org.apache.wink.client.handlers.ClientHandler;

import es.caib.seycon.ng.comu.Password;

public abstract class TokenHandlerOAuth extends AbstractAuthSecurityHandler implements ClientHandler{

	protected final String ACCESS_TOKEN = "access_token";
	protected final String CLIENT_CREDENTIALS = "client_credentials";
	protected final String CLIENT_ID = "client_id";
	protected final String CLIENT_SECRET = "client_secret";
	protected final String EXPIRES_IN = "expires_in";
	protected final String GRANT_TYPE = "grant_type";
	protected final String REFRESH_TOKEN = "refresh_token";
	protected final String PASSWORD = "password";
	protected final String USERNAME = "username";
	
	private String tokenURL;
	private String tokenAttribute;
	private String authToken;
	private String user;
	private Password password;
	private String refreshToken;
	private long expiresIn = 0L;
	private long requestedTime = 0L;
	private Map<String, String> oauthParams = new HashMap<String, String>();

	public String getTokenURL() {
		return tokenURL;
	}

	public void setTokenURL(String tokenURL) {
		this.tokenURL = tokenURL;
	}

	public String getTokenAttribute() {
		return tokenAttribute;
	}

	public void setTokenAttribute(String tokenAttribute) {
		this.tokenAttribute = tokenAttribute;
	}

	public String getAuthToken() {
		return authToken;
	}

	public void setAuthToken(String authToken) {
		this.authToken = authToken;
	}

	public String getUser() {
		return user;
	}

	public void setUser(String user) {
		this.user = user;
	}

	public Password getPassword() {
		return password;
	}

	public void setPassword(Password password) {
		this.password = password;
	}

	public Map<String, String> getOauthParams() {
		return oauthParams;
	}

	public void setOauthParams(Map<String, String> oauthParams) {
		this.oauthParams = oauthParams;
	}

	public long getExpiresIn() {
		return expiresIn;
	}

	public void setExpiresIn(long expiresIn) {
		this.expiresIn = expiresIn;
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}

	public long getRequestedTime() {
		return requestedTime;
	}

	public void setRequestedTime(long currentRequest) {
		this.requestedTime = currentRequest;
	}
	
}
