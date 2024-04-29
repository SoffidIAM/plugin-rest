package com.soffid.iam.sync.agent2.json;

import java.rmi.RemoteException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.json.JSONException;

import com.soffid.iam.api.CustomObject;
import com.soffid.iam.sync.agent.json.InvocationMethod;
import com.soffid.iam.sync.agent.json.PaginationStatus;
import com.soffid.iam.sync.intf.CustomObjectMgr;

import es.caib.seycon.ng.comu.SoffidObjectType;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.engine.extobj.CustomExtensibleObject;
import es.caib.seycon.ng.sync.intf.AuthoritativeChange;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;
import es.caib.seycon.ng.sync.intf.ExtensibleObjects;

public class JSONAgent extends com.soffid.iam.sync.agent.json.JSONAgent 
	implements CustomObjectMgr
{

	public JSONAgent() throws RemoteException {
	}


	public ExtensibleObject getNativeObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		try {
			ExtensibleObject sourceObject = getExtensibleObject(type, object1, object2);
			
			for (ExtensibleObjectMapping map : objectMappings) {
				if (map.appliesToSoffidObject(sourceObject))
				{
					ExtensibleObject target = objectTranslator.generateObject(sourceObject, map, true);
					ExtensibleObject target2 = searchJsonObject(target, sourceObject);
					if (target2 != null && !target2.isEmpty())
						return target2;						
				}
			}
			return null;
		} catch (Exception e) {
			throw new InternalErrorException("Error searching for native object", e);
		}
	}

	public ExtensibleObject getSoffidObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		try {
			ExtensibleObject sourceObject = getExtensibleObject(type, object1, object2);
			
			for (ExtensibleObjectMapping map : objectMappings) {
				if (map.getSoffidObject().toString().equals(sourceObject.getObjectType()))
				{
					if (! type.equals(SoffidObjectType.OBJECT_CUSTOM) ||
							object1.equals(map.getSoffidCustomObject()))
					{
						ExtensibleObject target = objectTranslator.generateObject(sourceObject, map, true);
						ExtensibleObject target2 = searchJsonObject(target, sourceObject);
						if (target2 != null && ! target2.isEmpty())
						{
							ExtensibleObject src2 = objectTranslator.parseInputObject(target2, map);
							if (src2 != null)
								return src2;
						}
					}
				}
			}
			return null;
		} catch (Exception e) {
			throw new InternalErrorException("Error searching for native object", e);
		}
	}


	public void updateCustomObject(CustomObject obj) throws RemoteException, InternalErrorException {
		try {
			CustomExtensibleObject sourceObject = new CustomExtensibleObject(obj, 
					getServer());
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.appliesToSoffidObject(sourceObject) )
				{
					if (objectTranslator.evalCondition(sourceObject, mapping))
					{
		    			ExtensibleObject target = objectTranslator.generateObject(sourceObject, mapping);
		    			if (obj != null)
		    				updateObject(null, sourceObject, target);
					}
					else
					{
						removeCustomObject(obj);
					}
				}
			}
		}
		catch (InternalErrorException e)
		{
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		}
	}


	public void removeCustomObject(CustomObject obj) throws RemoteException, InternalErrorException {
		CustomExtensibleObject sourceObject = new CustomExtensibleObject(obj, 
				getServer());
		try {
			for (ExtensibleObjectMapping eom: objectMappings)
			{
				if (! "true".equals( eom.getProperties().get("preventDeletion")))
				{
					String condition = eom.getCondition();
					eom.setCondition(null);
					try {
						ExtensibleObject target = objectTranslator.generateObject(sourceObject, eom);
						if (obj != null)
							removeObject(sourceObject, target);
					} finally { 
						eom.setCondition(condition);
					}
				}
			}
		}
		catch (InternalErrorException e)
		{
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		}
	}

	class SearchItem {
		ExtensibleObjectMapping mapping;
		ExtensibleObject srcObject;
		ExtensibleObject target;
		boolean started;
		boolean finished;
		public InvocationMethod method;
		PaginationStatus paginationStatus = new PaginationStatus();
	}
	List<SearchItem> searchItems = null;
	boolean moreData = false;
	String nextChange = null;
	
	@SuppressWarnings("unchecked")
	public Collection<AuthoritativeChange> getChanges(String lastChange)
			throws InternalErrorException {
		if (searchItems == null)
		{
			populateSearchItems(lastChange);
		}
		LinkedList<AuthoritativeChange> changes = new LinkedList<AuthoritativeChange>();
		
		try {
			for (SearchItem searchItem: searchItems)
			{
				if (! searchItem.finished)
				{
					searchItem.paginationStatus.setAuto(false);
					ExtensibleObjects objects = invoke (searchItem.method, searchItem.target, searchItem.srcObject, searchItem.paginationStatus);
					if (objects != null)
					{
						for (ExtensibleObject eo: objects.getObjects())
						{
							ExtensibleObject soffidUser = objectTranslator.parseInputObject(eo, searchItem.mapping);
							AuthoritativeChange ch = vom.parseAuthoritativeChange(soffidUser);
							if (ch != null)
								changes.add(ch);
						}
						if ( ! searchItem.paginationStatus.isHasMore())
							searchItem.finished = true;
						if ( ! changes.isEmpty())
						{
							moreData = true;
							return changes;
						}
					}
				}
			}
			moreData = false;
			return changes;
		} catch (JSONException e) {
			throw new InternalErrorException ("Error processing request", e);
		}
	}

	private void populateSearchItems(String lastChange) throws InternalErrorException {
		searchItems = new LinkedList<JSONAgent.SearchItem>();
		for (ExtensibleObjectMapping mapping: objectMappings)
		{
			if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_CUSTOM) ||
					mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_USER) ||
					mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_AUTHORITATIVE_CHANGE) ||
					mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_GROUP)
					)
			{
				for (InvocationMethod m: getMethods(mapping.getSystemObject(), "load"))
				{
					SearchItem searchItem = new SearchItem();
					searchItem.started = false;
					searchItem.finished = false;
					searchItem.mapping = mapping;
					searchItem.method = m;
					searchItem.srcObject = new ExtensibleObject();
					searchItem.srcObject.put("lastChange", lastChange);
					searchItem.srcObject.setObjectType(mapping.getSoffidObject().toString());
					searchItem.target = objectTranslator.generateObject(searchItem.srcObject, mapping);
					searchItems.add(searchItem);
				}
			}
		}
	}


	public String getNextChange() throws InternalErrorException {
		return nextChange;
	}

	public boolean hasMoreData() throws InternalErrorException {
		return moreData;
	}
}
