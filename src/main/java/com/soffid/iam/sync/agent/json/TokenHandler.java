package com.soffid.iam.sync.agent.json;

import java.net.URLEncoder;
import java.util.List;

import javax.ws.rs.core.MediaType;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.wink.client.ClientAuthenticationException;
import org.apache.wink.client.ClientConfig;
import org.apache.wink.client.ClientRequest;
import org.apache.wink.client.ClientResponse;
import org.apache.wink.client.Resource;
import org.apache.wink.client.RestClient;
import org.apache.wink.client.handlers.AbstractAuthSecurityHandler;
import org.apache.wink.client.handlers.BasicAuthSecurityHandler;
import org.apache.wink.client.handlers.ClientHandler;
import org.apache.wink.client.handlers.HandlerContext;
import org.apache.wink.client.httpclient.ApacheHttpClientConfig;
import org.apache.wink.common.http.HttpStatus;
import org.json.JSONException;
import org.json.JSONObject;

public class TokenHandler extends AbstractAuthSecurityHandler implements ClientHandler {

	Log logger = LogFactory.getLog(getClass());

	private String password;
	private String user;
	private String basicUser;
	private String basicPassword;
	private String authURL;
	private String authToken;
	private ApacheHttpClientConfig config;

	public String getBasicUser() {
		return basicUser;
	}

	public void setBasicUser(String basicUser) {
		this.basicUser = basicUser;
	}

	public String getBasicPassword() {
		return basicPassword;
	}

	public void setBasicPassword(String basicPassword) {
		this.basicPassword = basicPassword;
	}

	public TokenHandler ( String authURL, String user, String password, ApacheHttpClientConfig config2)
	{
		this.authURL = authURL;
		this.user = user;
		this.password = password;
		this.config =  config2;
	}
	
	private void getAuthToken () throws JSONException
	{
		if (basicUser != null && basicPassword != null)
			config.handlers(new BasicAuthSecurityHandler(basicUser, basicPassword));
		
		RestClient client = new RestClient(config);
		Resource rsc = client.resource(authURL);
		@SuppressWarnings("deprecation")
		ClientResponse response = rsc
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.accept(MediaType.APPLICATION_JSON)
				.post("username="+URLEncoder.encode(user)+"&password="+URLEncoder.encode(password));
		if (response.getStatusCode() == HttpStatus.OK.getCode())
		{
			JSONObject result = response.getEntity(JSONObject.class);
			authToken = result.getString("token");
			if (authToken == null)
				throw new ClientAuthenticationException("Unable to get auth token. Server returned "+response.getMessage());
		}
		else
			throw new ClientAuthenticationException("Unable to get auth token. Server returned "+response.getMessage());
	}
	
	public ClientResponse handle(ClientRequest request, HandlerContext context)
			throws Exception {
		if (authToken == null)
			getAuthToken();
		if (authToken != null)
		{
			String auth = ("Token "+authToken);
			if (request.getHeaders().containsKey("Authorization"))
			{
				List<String> list = request.getHeaders().get("Authorization");
				list.add(auth);
				request.getHeaders().put("Authorization", list);
			}
			else
				request.getHeaders().putSingle("Authorization", "Token "+authToken);
		}
		logger.trace("Entering BasicAuthSecurityHandler.doChain()"); //$NON-NLS-1$
		return  context.doChain(request);
	}

}
