package com.soffid.iam.sync.agent.json;

public class PaginationStatus {
	boolean auto;
	boolean hasMore;
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
}
