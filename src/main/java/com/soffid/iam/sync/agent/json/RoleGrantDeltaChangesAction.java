package com.soffid.iam.sync.agent.json;

import com.soffid.iam.api.RoleGrant;

import es.caib.seycon.ng.comu.RolGrant;

public interface RoleGrantDeltaChangesAction {
	void add(RolGrant rg) throws Exception;
	void remove(RolGrant rg) throws Exception;
}
