package com.soffid.iam.sync.agent.json;

import java.io.IOException;
import java.net.Proxy;
import java.net.SocketAddress;
import java.net.URI;
import java.util.Collections;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class ProxySelector extends java.net.ProxySelector {

	Log log = LogFactory.getLog(getClass());

	private List<Proxy> list;

	public ProxySelector(Proxy proxy) {
		list = Collections.singletonList(proxy);
	}

	@Override
	public List<Proxy> select(URI uri) {
		log.info("Setting proxy for "+uri);
		return list;
	}

	@Override
	public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
		log.warn("Error connecting to proxy address "+sa+" for "+uri, ioe);
	}
}
