package com.soffid.iam.sync.agent.json;

import es.caib.seycon.ng.sync.intf.ExtensibleObject;

public class PaginationStatus {
	boolean auto;
	boolean hasMore;
	public String nextPath;
	public ExtensibleObject nextObject;
	
	public boolean isAuto() {
		return auto;
	}
	public void setAuto(boolean auto) {
		this.auto = auto;
	}
	public boolean isHasMore() {
		return hasMore;
	}
	public void setHasMore(boolean hasMore) {
		this.hasMore = hasMore;
	}
	public String getNextPath() {
		return nextPath;
	}
	public void setNextPath(String nextPath) {
		this.nextPath = nextPath;
	}
	public ExtensibleObject getNextObject() {
		return nextObject;
	}
	public void setNextObject(ExtensibleObject nextObject) {
		this.nextObject = nextObject;
	}
}
