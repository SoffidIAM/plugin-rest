package com.soffid.iam.sync.agent.json.token.oauth;

import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

public class TokenOAuthSorter implements Comparator<String> {

	  private static final List<String> OAUTH_PARAMS = Arrays.asList(
	      "grant_type", "refresh_token", "username", "password", "client_id", "client_secret", "scope");
	  
	  /**
	   * Compares order within params, to assure its correctness 
	   */
	  public int compare(String o1, String o2) {
		String param1 = o1.substring(0, o1.indexOf("="));
		String param2 = o2.substring(0, o2.indexOf("="));
		
	    if (OAUTH_PARAMS.contains(param1) && OAUTH_PARAMS.contains(param2)) {
	      return OAUTH_PARAMS.indexOf(param1) - OAUTH_PARAMS.indexOf(param2);
	    }

	    if (OAUTH_PARAMS.contains(param1)) {
	      return -1;
	    }

	    if (OAUTH_PARAMS.contains(param2)) {
	      return 1;
	    }

	    return param1.toString().compareTo(param2.toString());
	  }

	}