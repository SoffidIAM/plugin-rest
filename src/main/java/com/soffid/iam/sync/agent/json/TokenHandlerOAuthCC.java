package com.soffid.iam.sync.agent.json;

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
import org.apache.wink.client.handlers.ClientHandler;
import org.apache.wink.client.handlers.HandlerContext;
import org.apache.wink.client.httpclient.ApacheHttpClientConfig;
import org.apache.wink.common.http.HttpStatus;
import org.json.JSONException;
import org.json.JSONObject;

public class TokenHandlerOAuthCC extends AbstractAuthSecurityHandler implements ClientHandler {

	Log log = LogFactory.getLog(getClass());

	private String tokenURL;
	private String body;
	private String tokenAttribute;
	private String authToken;
	private DefaultHttpClient httpClient;

	public TokenHandlerOAuthCC(String tokenURL, String body, String tokenAttribute, DefaultHttpClient httpClient) {
		this.tokenURL = tokenURL;
		this.body = body;
		this.tokenAttribute = tokenAttribute;
		this.authToken = null;
		this.httpClient = httpClient;
	}

	public ClientResponse handle(ClientRequest request, HandlerContext context) throws Exception {
		if (authToken == null)
			getAuthToken();
		if (authToken != null) {
			String auth = ("Bearer "+authToken);
			if (request.getHeaders().containsKey("Authorization")) {
				List<String> list = request.getHeaders().get("Authorization");
				list.add(auth);
				request.getHeaders().put("Authorization", list);
			} else {
				request.getHeaders().putSingle("Authorization", auth);
			}
		}
		System.out.println("TokenHandlerPOSTBody.handle() - doChain()");
		return context.doChain(request);
	}

	private void getAuthToken() throws JSONException {

		System.out.println("TokenHandlerPOSTBody.getAuthToken()");
		ClientConfig config = new ApacheHttpClientConfig(httpClient);
		RestClient client = new RestClient(config);
		Resource rsc = client.resource(tokenURL);
		ClientResponse response = rsc
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.accept(MediaType.APPLICATION_JSON)
				.post(body);
		System.out.println("TokenHandlerPOSTBody.getAuthToken() - response="+response);
		System.out.println("TokenHandlerPOSTBody.getAuthToken() - response.getStatusCode()="+response.getStatusCode());

		if (response.getStatusCode() == HttpStatus.OK.getCode()) {
			String result = response.getEntity(String.class);
			System.out.println("TokenHandlerPOSTBody.getAuthToken() - result="+result);
			JSONObject jsonResult = new JSONObject(result);
			authToken = (String) jsonResult.get(tokenAttribute);
			System.out.println("TokenHandlerPOSTBody.getAuthToken() - authToken="+authToken);
			if (authToken == null)
				throw new ClientAuthenticationException("Unable to get auth token. Server returned "+response.getMessage());
		} else {
			System.out.println("TokenHandlerPOSTBody.getAuthToken() - response.getMessage()="+response.getMessage());
			throw new ClientAuthenticationException("Unable to get auth token. Server returned "+response.getMessage());
		}
	}
}
