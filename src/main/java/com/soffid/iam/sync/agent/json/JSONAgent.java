package com.soffid.iam.sync.agent.json;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.rmi.RemoteException;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import javax.ws.rs.core.MediaType;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.wink.client.ClientResponse;
import org.apache.wink.client.ClientRuntimeException;
import org.apache.wink.client.ClientWebException;
import org.apache.wink.client.Resource;
import org.apache.wink.client.RestClient;
import org.apache.wink.client.httpclient.ApacheHttpClientConfig;
import org.apache.wink.common.http.HttpStatus;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONStringer;
import org.json.JSONTokener;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import es.caib.seycon.ng.comu.Account;
import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.ObjectMappingTrigger;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.SoffidObjectTrigger;
import es.caib.seycon.ng.comu.SoffidObjectType;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownRoleException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.ng.sync.agent.Agent;
import es.caib.seycon.ng.sync.engine.extobj.AccountExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.ExtensibleObjectFinder;
import es.caib.seycon.ng.sync.engine.extobj.GrantExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.GroupExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.ObjectTranslator;
import es.caib.seycon.ng.sync.engine.extobj.RoleExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.UserExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.ValueObjectMapper;
import es.caib.seycon.ng.sync.intf.AuthoritativeChange;
import es.caib.seycon.ng.sync.intf.AuthoritativeIdentitySource2;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMgr;
import es.caib.seycon.ng.sync.intf.ExtensibleObjects;
import es.caib.seycon.ng.sync.intf.GroupMgr;
import es.caib.seycon.ng.sync.intf.ReconcileMgr2;
import es.caib.seycon.ng.sync.intf.RoleMgr;
import es.caib.seycon.ng.sync.intf.UserMgr;

/**
 * Agente que gestiona los usuarios y contraseñas del LDAP Hace uso de las
 * librerias jldap de Novell
 * <P>
 * 
 * @author $Author: u88683 $
 * @version $Revision: 1.5 $
 */

public class JSONAgent extends Agent implements ExtensibleObjectMgr, UserMgr, ReconcileMgr2, GroupMgr, RoleMgr,
	AuthoritativeIdentitySource2 {

	protected ValueObjectMapper vom = new ValueObjectMapper();
	protected ObjectTranslator objectTranslator = null;
	protected boolean debug;
	
	String loginDN;
	Password password;
	String serverUrl;
	String authMethod;
	String authUrl;
	String scimVersion;
	String contentType;

	protected Collection<ExtensibleObjectMapping> objectMappings;
	private ApacheHttpClientConfig config;
	protected RestClient client;
	private static final int MAX_LOG = 1000;
	boolean grantsInRole = false;
	Map<String,Set<String>> userRoles = new HashMap<String, Set<String>>();

	/**
	 * Constructor
	 * 
	 * @param params
	 *            Parámetros de configuración: <li>0 = código de usuario LDAP</li>
	 *            <li>1 = contraseña de acceso LDAP</li> <li>2 = host</li> <li>3
	 *            = Nombre del attribute password</li> <li>4 = Algoritmo de hash
	 *            </li>
	 */
	public JSONAgent() throws RemoteException {
	}

	Map<String, String> templates = new HashMap<String, String>();
	@Override
	public void init() throws InternalErrorException {
		log.info("Starting REST agent on {}", getDispatcher().getCodi(), null);
		loginDN = getDispatcher().getParam0();
		if (getDispatcher().getParam1()!=null) {
			try {
				password = Password.decode(getDispatcher().getParam1());
				log.info(">>> password decoded");
			} catch (Exception e) {
				password = null;
				log.info(">>> error decoding password");
			}
		}
		authMethod = getDispatcher().getParam2();
		authUrl = getDispatcher().getParam3();
		serverUrl = getDispatcher().getParam4();
		debug = "true".equals(getDispatcher().getParam8());

		try {
			if ( getDispatcher().getBlobParam() != null && getDispatcher().getBlobParam().length > 0)
			{
				String t = new String ( getDispatcher().getBlobParam(),"UTF-8"); 
				org.json.JSONTokener tokener = new org.json.JSONTokener( t);
				org.json.JSONObject json = new org.json.JSONObject(tokener);
				org.json.JSONArray templatesJson = json.optJSONArray("templates");
				for ( int i = 0; i < templatesJson.length(); i++)
				{
					org.json.JSONObject s = templatesJson.getJSONObject(i);
					String name = s.optString("name");
					String template = s.optString("template");
					if (name != null && !name.isEmpty() &&
						template != null && !template.isEmpty())
					{
						templates.put(name, template);
					}
				}
			}
		} catch (UnsupportedEncodingException e) {
			throw new InternalErrorException("Error parsing templates", e);
		} catch (JSONException e) {
			throw new InternalErrorException("Error parsing templates", e);
		}
		
		createClient();
	}

	protected void createClient() {
		// create a client to send the user/group crud requests
		config = new ApacheHttpClientConfig(new DefaultHttpClient());
		if ("token".equals(authMethod))
		{
			TokenHandler handler = new TokenHandler (authUrl, loginDN, password.getPassword());
			config.handlers(handler);
		}
		if ("basic".equals(authMethod))
		{
			BasicAuthSecurityHandler handler = new BasicAuthSecurityHandler(loginDN, password.getPassword());
			config.handlers(handler);
		}
		config.setChunked(false);
		client = new RestClient(config);
	}

	boolean moreData = false;
	String nextChange = null;
	@SuppressWarnings("unchecked")
	public Collection<AuthoritativeChange> getChanges(String lastChange)
			throws InternalErrorException {
		LinkedList<AuthoritativeChange> changes = new LinkedList<AuthoritativeChange>();
		
		try {
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_USER))
				{
					for (InvocationMethod m: getMethods(mapping.getSystemObject(), "select"))
					{
						ExtensibleObject object = new ExtensibleObject();
						ExtensibleObjects objects = invoke (m, object, null);
						if (objects != null)
						{
							for (ExtensibleObject eo: objects.getObjects())
							{
								ExtensibleObject soffidUser = objectTranslator.parseInputObject(eo, mapping);
								Usuari u = vom.parseUsuari(soffidUser);
								if (u != null)
								{
									AuthoritativeChange ch = new AuthoritativeChange();
									ch.setUser(u);
									ch.setAttributes((Map<String, Object>) soffidUser.getAttribute("attributes"));
									changes.add(ch);
								}
									
							}
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

	public String getNextChange() throws InternalErrorException {
		return nextChange;
	}

	public boolean hasMoreData() throws InternalErrorException {
		return moreData;
	}

	public void removeRole(String name, String system) throws RemoteException,
			InternalErrorException {
		Rol rol = new Rol();
		rol.setNom(name);
		if (getCodi().equals(system))
		{
			rol.setBaseDeDades(system);
			
			ExtensibleObject roleObject = new RoleExtensibleObject(rol,
							getServer());
			try {
				for (ExtensibleObjectMapping eom: objectMappings)
				{
					if (eom.getSoffidObject().equals (SoffidObjectType.OBJECT_ROLE))
					{
						if (! "true".equals( eom.getProperties().get("preventDeletion")))
						{
							String condition = eom.getCondition();
							eom.setCondition(null);
							try {
								ExtensibleObject obj = objectTranslator.generateObject(roleObject, eom);
								if (obj != null)
									removeObject(roleObject, obj);
							} finally { 
								eom.setCondition(condition);
							}
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
	}

	protected void removeObject(ExtensibleObject soffidObject, ExtensibleObject object) throws InternalErrorException {
		try
		{
			debugObject("Removing object", object, "");
			
			ExtensibleObject existingObject = searchJsonObject(object, soffidObject);
		
			if (existingObject != null)
			{
				boolean triggerRan = false;
				for (InvocationMethod m: getMethods(object.getObjectType(), "delete"))
				{
					if (triggerRan || runTrigger(SoffidObjectTrigger.PRE_DELETE, soffidObject, object, existingObject))
					{
						triggerRan = true;
						invoke (m, object, soffidObject);
					}
				}
				if (triggerRan)
					runTrigger(SoffidObjectTrigger.POST_DELETE, soffidObject, object, existingObject);
			}
		}
		catch (Exception e)
		{
			String error = (object.toString().length()>MAX_LOG) ? object.toString().substring(0, MAX_LOG) : object.toString();
			String msg = "removing object : " + error + " (log truncated) ...";
			log.warn(msg, e);
			throw new InternalErrorException(msg, e);
		}
	}

	public void updateRole(Rol rol) throws RemoteException,
			InternalErrorException {
		if (rol.getBaseDeDades().equals(getDispatcher().getCodi()))
		{
			try
			{
				RoleExtensibleObject sourceObject = new RoleExtensibleObject(rol,
						getServer());
				debugObject("Updating role",sourceObject, "");
	
				for (ExtensibleObjectMapping mapping: objectMappings)
				{
					if (mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_ROLE))
					{
						if (objectTranslator.evalCondition(sourceObject, mapping))
						{
			    			ExtensibleObject obj = objectTranslator.generateObject(sourceObject, mapping);
			    			if (obj != null)
			    				updateObject(sourceObject, obj);
						}
						else
						{
							removeRole(rol.getNom(), rol.getBaseDeDades());
						}
						if (rol.getId() != null)
							updateRoleGrants(rol.getNom(), rol.getId());
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
	}

	public void removeGroup(String name) throws RemoteException,
			InternalErrorException {
		Grup grup = new Grup();
		grup.setCodi(name);
		GroupExtensibleObject groupObject = new GroupExtensibleObject(grup,
				getDispatcher().getCodi(), getServer());
		try {
			for (ExtensibleObjectMapping eom: objectMappings)
			{
				if (! "true".equals( eom.getProperties().get("preventDeletion")))
				{
					String condition = eom.getCondition();
					eom.setCondition(null);
					try {
						ExtensibleObject obj = objectTranslator.generateObject(groupObject, eom);
						if (obj != null)
							removeObject(groupObject, obj);
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

	public void updateGroup(String name, Grup group) throws RemoteException,
			InternalErrorException {

		try {
			GroupExtensibleObject sourceObject = new GroupExtensibleObject(group, getCodi(), 
					getServer());
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_GROUP))
				{
					if (objectTranslator.evalCondition(sourceObject, mapping))
					{
		    			ExtensibleObject obj = objectTranslator.generateObject(sourceObject, mapping);
		    			if (obj != null)
		    				updateObject(sourceObject, obj);
					}
					else
					{
						removeGroup(name);
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

	public List<RolGrant> getAccountGrants(String accountName) throws RemoteException,
			InternalErrorException {
		Account account = new Account();
		account.setName(accountName);
		account.setDispatcher(getCodi());
		account.setDisabled(false);
	
		List<RolGrant> grants = new LinkedList<RolGrant>();
		
		if (!tryGrantFetch (accountName, grants))
			tryAccountFetch (accountName, grants);
		
		log.info("Getting user roles from group mapping");
		Set<String> r = userRoles.get(accountName);
		
		if (r != null)
		{
			for (String roleName: r)
			{
				log.info("Inspecting role "+roleName);
				if (roleName != null && ! roleName.isEmpty())
				{
					RolGrant rg = new RolGrant();
					rg.setDispatcher(getCodi());
					rg.setRolName(roleName);
					rg.setOwnerAccountName(accountName);
					rg.setOwnerDispatcher(getCodi());
					grants.add(rg);
				}
			}
		}
		
		return grants;
	}

	@SuppressWarnings({ "unchecked", "unused" })
	private boolean tryRoleFetch(String roleName, List<RolGrant> grants) throws InternalErrorException {
		try {
			boolean found = false;
			for (ExtensibleObjectMapping mapping : objectMappings) {
				if (mapping.getSoffidObject().equals(
						SoffidObjectType.OBJECT_ROLE)) {
					Rol rol2 = null;
					try {
						rol2 = getServer().getRoleInfo(roleName, getCodi());
					} catch (UnknownRoleException e) {
					}
					if (rol2 == null)
					{
						rol2 = new Rol();
						rol2.setNom(roleName);
						rol2.setBaseDeDades(getCodi());
					}
					RoleExtensibleObject srcObject = new RoleExtensibleObject(rol2, getServer());
					ExtensibleObject obj = objectTranslator.generateObject(
							srcObject, mapping);
					if (obj != null) {
						obj = searchJsonObject(obj, srcObject);
						if (obj != null) {
							ExtensibleObject soffidObject = objectTranslator
									.parseInputObject(obj, mapping);
							if (soffidObject != null) {
								List<Map<String, Object>> grantedAccounts = (List<Map<String, Object>>) soffidObject
										.get("grantedAccounts");
								if (grantedAccounts != null) {
									for (Map<String, Object> grantedAccount: grantedAccounts) {
										RolGrant grant = new RolGrant();
										grant.setDispatcher(getCodi());
										grant.setRolName(roleName);
										grant.setOwnerAccountName((String) grantedAccount.get("accountName"));
										grant.setOwnerDispatcher(getCodi());
										grants.add(grant);
									}
									found = true;
								}
								List<Map<String, Object>> allGrantedAccounts = (List<Map<String, Object>>) soffidObject
										.get("allGrantedAccounts");
								if (grantedAccounts != null) {
									for (Map<String, Object> grantedAccount: grantedAccounts) {
										RolGrant grant = new RolGrant();
										grant.setDispatcher(getCodi());
										grant.setRolName(roleName);
										grant.setOwnerAccountName((String) grantedAccount.get("accountName"));
										grant.setOwnerDispatcher(getCodi());
										grants.add(grant);
									}
									found = true;
								}
								List<String> granted = (List<String>) soffidObject
										.get("grantedAccountNames");
								if (granted != null) {
									for (String grantedAccount : granted) {
										RolGrant grant = new RolGrant();
										grant.setDispatcher(getCodi());
										grant.setRolName(roleName);
										grant.setOwnerAccountName((String) grantedAccount);
										grant.setOwnerDispatcher(getCodi());
										grants.add(grant);
									}
									found = true;
								}
								granted = (List<String>) soffidObject
										.get("allGrantedAccountNames");
								if (granted != null) {
									for (String grantedAccount : granted) {
										RolGrant grant = new RolGrant();
										grant.setDispatcher(getCodi());
										grant.setRolName(roleName);
										grant.setOwnerAccountName((String) grantedAccount);
										grant.setOwnerDispatcher(getCodi());
										grants.add(grant);
									}
									found = true;
								}
							}
						}
					}
				}
			}
			return found;
		} catch (JSONException e) {
			throw new InternalErrorException ("Error parsing json object", e);
		} catch (UnsupportedEncodingException e) {
			throw new InternalErrorException ("Error parsing json object", e);
		}
	}

	@SuppressWarnings("unchecked")
	private boolean tryAccountFetch(String accountName, List<RolGrant> grants) throws InternalErrorException {
		try {
			boolean found = false;
			for (ExtensibleObjectMapping mapping : objectMappings) {
				if (mapping.getSoffidObject().equals(
						SoffidObjectType.OBJECT_ACCOUNT)) {
					Account acc = getServer()
							.getAccountInfo(accountName, getCodi());
					if (acc != null)
					{
						AccountExtensibleObject srcObject = new AccountExtensibleObject(acc, getServer());
						ExtensibleObject obj = objectTranslator.generateObject(
								srcObject, mapping);
						if (obj != null) {
							obj = searchJsonObject(obj, srcObject);
							if (obj != null) {
								ExtensibleObject soffidObject = objectTranslator
										.parseInputObject(obj, mapping);
								if (soffidObject != null) {
									List<Map<String, Object>> grantedRoles = (List<Map<String, Object>>) soffidObject
											.get("grantedRoles");
									if (grantedRoles != null) {
										for (Map<String, Object> grantedRole : grantedRoles) {
											RolGrant grant = vom
													.parseGrant(grantedRole);
											grants.add(grant);
										}
										found = true;
									}
									List<String> granted = (List<String>) soffidObject
											.get("granted");
									if (granted != null) {
										for (String grantedRole : granted) {
											RolGrant grant = new RolGrant();
											grant.setDispatcher(getCodi());
											grant.setRolName(grantedRole);
											grant.setOwnerAccountName(accountName);
											grant.setOwnerDispatcher(getCodi());
											grants.add(grant);
										}
										found = true;
									}
	
								}
							}
						}
					}
				}
			}
			return found;
		} catch (JSONException e) {
			throw new InternalErrorException ("Error parsing json object", e);
		} catch (UnsupportedEncodingException e) {
			throw new InternalErrorException ("Error parsing json object", e);
		}
	}

	private boolean tryGrantByGroupFetch(String roleName, List<RolGrant> grants) throws InternalErrorException {
		try {
			boolean found = false;
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				String prop = mapping.getProperties().get("drivenByRole");
				if ( prop != null &&
						(mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_GRANT) ||
						mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_ALL_GRANTED_ROLES) ||
						mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_GRANTED_ROLE)))
				{
					found = true;
					
					RolGrant rg = new RolGrant();
					rg.setDispatcher(getCodi());
					rg.setRolName(roleName);
					rg.setOwnerDispatcher(getCodi());
					GrantExtensibleObject geo = new GrantExtensibleObject(rg, getServer());
					String condition = mapping.getCondition();
					try {
						mapping.setCondition(null);
						ExtensibleObject jsonObj = objectTranslator.generateObject(geo, mapping);
						if (jsonObj != null)
						{
							ExtensibleObjects jsonStoredObjects = searchJsonObjects(jsonObj, geo);
							if (jsonStoredObjects != null)
							{
								for (ExtensibleObject jsonObject: jsonStoredObjects.getObjects())
								{
									jsonObject.setObjectType(mapping.getSystemObject());
									ExtensibleObject grantObject = objectTranslator.parseInputObject(jsonObject, mapping);
									if (grantObject != null)
									{
										if (debug)
											debugObject("Parsed Soffid grant:", grantObject, "");
										RolGrant grant = vom.parseGrant(grantObject);
										if (grant != null)
										{
											if (debug)
												log.info("Soffid grant: "+grant.toString());
											grants.add(grant);
										}
									}
								}
							}
						}
					} finally {
						mapping.setCondition(condition);
					}
				}
			}
			return found;
		} catch (JSONException e) {
			throw new InternalErrorException ("Error parsing json object", e);
		} catch (UnsupportedEncodingException e) {
			throw new InternalErrorException ("Error parsing json object", e);
		}
	}

	private boolean tryGrantFetch(String accountName, List<RolGrant> grants) throws InternalErrorException {
		try {
			boolean found = false;
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				String prop = mapping.getProperties().get("drivenByRole");
				if ( prop == null &&
						(mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_GRANT) ||
						mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_ALL_GRANTED_ROLES) ||
						mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_GRANTED_ROLE)))
				{
					found = true;
					
					RolGrant rg = new RolGrant();
					rg.setDispatcher(getCodi());
					rg.setOwnerAccountName(accountName);
					rg.setOwnerDispatcher(getCodi());
					GrantExtensibleObject geo = new GrantExtensibleObject(rg, getServer());
					String condition = mapping.getCondition();
					try {
						mapping.setCondition(null);
						ExtensibleObject jsonObj = objectTranslator.generateObject(geo, mapping);
						if (jsonObj != null)
						{
							ExtensibleObjects jsonStoredObjects = searchJsonObjects(jsonObj, geo);
							if (jsonStoredObjects != null)
							{
								for (ExtensibleObject jsonObject: jsonStoredObjects.getObjects())
								{
									jsonObject.setObjectType(mapping.getSystemObject());
									ExtensibleObject grantObject = objectTranslator.parseInputObject(jsonObject, mapping);
									if (grantObject != null)
									{
										if (debug)
											debugObject("Parsed Soffid grant:", grantObject, "");
										RolGrant grant = vom.parseGrant(grantObject);
										if (grant != null)
										{
											if (debug)
												log.info("Soffid grant: "+grant.toString());
											grants.add(grant);
										}
									}
								}
							}
						}
					} finally {
						mapping.setCondition(condition);
					}
				}
			}
			return found;
		} catch (JSONException e) {
			throw new InternalErrorException ("Error parsing json object", e);
		} catch (UnsupportedEncodingException e) {
			throw new InternalErrorException ("Error parsing json object", e);
		}
	}


	private void updateAccountGrants(String accountName) throws InternalErrorException {
		try {
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				String prop = mapping.getProperties().get("drivenByRole");
				if (prop == null && (
						mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_GRANT) ||
						mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_ALL_GRANTED_ROLES) ||
						mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_GRANTED_ROLE)))
				{
					if (debug)
						log.info("Using "+mapping.getSystemObject()+" mapping to update "+accountName+" roles");
					Collection<RolGrant> grants = getServer().getAccountRoles(accountName, getCodi());
					
					RolGrant rg = new RolGrant();
					rg.setDispatcher(getCodi());
					rg.setOwnerAccountName(accountName);
					rg.setOwnerDispatcher(getCodi());
					GrantExtensibleObject geo = new GrantExtensibleObject(rg, getServer());
					geo.setObjectType(mapping.getSoffidObject().toString());
					String condition = mapping.getCondition();
					try {
						mapping.setCondition(null);
						ExtensibleObject jsonObj = objectTranslator.generateObject(geo, mapping);
						if (jsonObj != null)
						{
							ExtensibleObjects jsonStoredObjects = searchJsonObjects(jsonObj, geo);
							if (jsonStoredObjects != null)
							{
								for (ExtensibleObject jsonObject: jsonStoredObjects.getObjects())
								{
									ExtensibleObject grantObject = objectTranslator.parseInputObject(jsonObject, mapping);
									if (grantObject != null)
									{
										RolGrant grant = vom.parseGrant(grantObject);
										
										if (grant != null)
										{
											boolean found = false;
											for (RolGrant grant2: new LinkedList<RolGrant> (grants))
											{
												if (grant2.getRolName() .equals(grant.getRolName()))
												{
													if (grant.getDomainValue() == null ||
															grant.getDomainValue().equals(grant2.getDomainValue()))
													{
														found = true;
														grants.remove(grant2);
														break;
													}
												}
											}
											if (! found)
											{
												if (debug)
												{
													log.info("Removing grant "+grantObject);
												}
												boolean triggerRan = false;
												for (InvocationMethod m: getMethods(jsonObject.getObjectType(), "delete"))
												{
													if (triggerRan || runTrigger(SoffidObjectTrigger.PRE_DELETE, geo, jsonObject, jsonObject))
													{
														triggerRan = true;
														invoke (m, jsonObject, grantObject);
													}
												}
												if (triggerRan)
													runTrigger(SoffidObjectTrigger.POST_DELETE, geo, jsonObject, jsonObject);
											}
										}
									}
								}
							}
							if (debug)
								log.info("Adding new grants");
							for (RolGrant grant: grants)
							{
								grant.setOwnerAccountName(accountName);
								GrantExtensibleObject sourceObject = new GrantExtensibleObject(grant, getServer());
								ExtensibleObject targetObject = objectTranslator.generateObject( sourceObject, mapping);
								boolean triggerRan = false;
								for (InvocationMethod m: getMethods(targetObject.getObjectType(), "insert"))
								{
									if (triggerRan || runTrigger(SoffidObjectTrigger.PRE_INSERT, sourceObject, targetObject, null))
									{
										invoke (m, targetObject, sourceObject);
									}
								}
								if (triggerRan)
									runTrigger(SoffidObjectTrigger.POST_INSERT, sourceObject, targetObject, null);
							}
						}
					} finally {
						mapping.setCondition(condition);
					}
				}
			}
		} catch (JSONException e) {
			throw new InternalErrorException ("Error parsing json object", e);
		} catch (UnsupportedEncodingException e) {
			throw new InternalErrorException ("Error parsing json object", e);
		}
	}


	private void updateRoleGrants(String roleName, Long roleId) throws InternalErrorException, UnknownRoleException {
		try {
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				String prop = mapping.getProperties().get("drivenByRole");
				if ( prop != null &&
						(mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_GRANT) ||
						mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_ALL_GRANTED_ROLES) ||
						mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_GRANTED_ROLE)))
				{
					if (debug)
						log.info("Using "+mapping.getSystemObject()+" mapping to update "+roleName+" users");
					Collection<Account> accounts = getServer().getRoleActiveAccounts(roleId, getCodi());
					
					RolGrant rg = new RolGrant();
					rg.setDispatcher(getCodi());
					rg.setRolName(roleName);
					rg.setOwnerDispatcher(getCodi());
					GrantExtensibleObject geo = new GrantExtensibleObject(rg, getServer());
					geo.setObjectType(mapping.getSoffidObject().toString());
					String condition = mapping.getCondition();
					try {
						mapping.setCondition(null);
						ExtensibleObject jsonObj = objectTranslator.generateObject(geo, mapping);
						if (jsonObj != null)
						{
							ExtensibleObjects jsonStoredObjects = searchJsonObjects(jsonObj, geo);
							if (jsonStoredObjects != null)
							{
								for (ExtensibleObject jsonObject: jsonStoredObjects.getObjects())
								{
									ExtensibleObject grantObject = objectTranslator.parseInputObject(jsonObject, mapping);
									if (grantObject != null)
									{
										RolGrant grant = vom.parseGrant(grantObject);
										
										if (grant != null)
										{
											boolean found = false;
											for (Account account: new LinkedList<Account>(accounts))
											{
												if (account.getName() .equals(grant.getOwnerAccountName()))
												{
													found = true;
													accounts.remove(account);
												}
											}
											if (! found)
											{
												if (debug)
												{
													log.info("Removing grant "+grantObject+" object type = "+jsonObject.getObjectType());
												}
												boolean triggerRan = false;
												for (InvocationMethod m: getMethods(jsonObject.getObjectType(), "delete"))
												{
													if (triggerRan || runTrigger(SoffidObjectTrigger.PRE_DELETE, geo, jsonObject, jsonObject))
													{
														triggerRan = true;
														invoke (m, jsonObject, grantObject);
													}
												}
												if (triggerRan)
													runTrigger(SoffidObjectTrigger.POST_DELETE, geo, jsonObject, jsonObject);
											}
										}
									}
								}
							}
							if (debug)
								log.info("Adding new grants");
							for (Account account: accounts)
							{
								RolGrant grant = new RolGrant();
								grant.setDispatcher(getCodi());
								grant.setRolName(roleName);
								grant.setOwnerDispatcher(getCodi());
								grant.setOwnerAccountName(account.getName());
								GrantExtensibleObject sourceObject = new GrantExtensibleObject(grant, getServer());
								ExtensibleObject targetObject = objectTranslator.generateObject( sourceObject, mapping);
								boolean triggerRan = false;
								for (InvocationMethod m: getMethods(targetObject.getObjectType(), "insert"))
								{
									if (triggerRan || runTrigger(SoffidObjectTrigger.PRE_INSERT, sourceObject, targetObject, null))
									{
										triggerRan = true;
										invoke (m, targetObject, sourceObject);
									}
								}
								if (triggerRan)
									runTrigger(SoffidObjectTrigger.POST_INSERT, sourceObject, targetObject, null);
							}
						}
					} finally {
						mapping.setCondition(condition);
					}
				}
			}
		} catch (JSONException e) {
			throw new InternalErrorException ("Error parsing json object", e);
		} catch (UnsupportedEncodingException e) {
			throw new InternalErrorException ("Error parsing json object", e);
		}
	}


	public Account getAccountInfo(String accountName) throws RemoteException,
			InternalErrorException {
		try {
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_ACCOUNT))
				{
					Account acc = new Account ();
					acc.setName(accountName);
					acc.setDispatcher(getCodi());
					acc.setDisabled(false);
					String condition = mapping.getCondition();
					try {
						mapping.setCondition(null);
						AccountExtensibleObject sourceObject = new AccountExtensibleObject(acc, getServer());
						ExtensibleObject scimObj = objectTranslator.generateObject(sourceObject, mapping);
						if (scimObj != null)
						{
							if (debug)
								debugObject("Looking for object", scimObj, "");
							ExtensibleObject scimStoredObject = searchJsonObject(scimObj, sourceObject);
							if (scimStoredObject != null)
							{
								debugObject("got object", scimStoredObject, "");
								
								acc = vom.parseAccount( objectTranslator.parseInputObject(scimStoredObject, mapping));
								if (acc != null)
								{
									if (debug)
										log.info("Parsed account: "+acc.toString());
									return acc;
								}
							}
						}
					} finally {
						mapping.setCondition(condition);
					}
				}
			}
		} catch (JSONException e) {
			throw new InternalErrorException ("Error parsing json object", e);
		} catch (UnsupportedEncodingException e) {
			throw new InternalErrorException ("Error parsing json object", e);
		}
		return null;
	}

	public List<String> getAccountsList() throws RemoteException,
			InternalErrorException {
		LinkedList<String> accounts = new LinkedList<String>();
		
		try {
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ACCOUNT))
				{
					ExtensibleObject s = new ExtensibleObject();
					s.setObjectType(mapping.getSoffidObject().toString());
					ExtensibleObject eo = objectTranslator.generateObject(s, mapping, true);
					
					ExtensibleObjects objects = loadJsonObjects(eo, s);
					
					if (objects == null)
						throw new InternalErrorException("No accounts found");
					for ( ExtensibleObject object : objects.getObjects())
					{
						String name = vom.toSingleString(objectTranslator.parseInputAttribute("accountName", object, mapping));
						if (name != null)
						{
							accounts.add(name);
						}
					}
				}
			}
			return accounts;
		} catch (JSONException e) {
			throw new InternalErrorException ("Error processing request", e);
		} catch (UnsupportedEncodingException e) {
			throw new InternalErrorException ("Error processing request", e);
		}
	}

	public Rol getRoleFullInfo(String roleName) throws RemoteException,
			InternalErrorException {
		try {
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_ROLE))
				{
					Rol role = new Rol();
					role.setNom(roleName);
					role.setBaseDeDades(getCodi());
					String condition = mapping.getCondition();
					try {
						mapping.setCondition(null);
						RoleExtensibleObject sourceObject = new RoleExtensibleObject(role, getServer());
						ExtensibleObject jsonObj = objectTranslator.generateObject(sourceObject, mapping);
						if (jsonObj != null)
						{
							ExtensibleObject jsonStoredObject = searchJsonObject(jsonObj, sourceObject);
							if (jsonStoredObject != null)
							{
								role  = vom.parseRol(objectTranslator.parseInputObject(jsonStoredObject, mapping));
								List<RolGrant> grants = new LinkedList<RolGrant>();
								if ( tryRoleFetch(roleName, grants) ||
										tryGrantByGroupFetch(roleName, grants))
								{
									for (RolGrant grant: grants) 
									{
										if (grant.getOwnerAccountName() != null)
										{
											log.info("Keeping grant of role "+roleName+" to "+grant.getOwnerAccountName());
											Set<String> r = userRoles.get(grant.getOwnerAccountName());
											if (r == null)
											{
												r = new HashSet<String>();
												userRoles.put(grant.getOwnerAccountName(), r);
											}
											r.add (roleName);									
										}
									}
								}
								if (role != null)
									return role;
							}
						}
					} finally {
						mapping.setCondition(condition);
					}
				}
			}
		} catch (JSONException e) {
			throw new InternalErrorException ("Error parsing json object", e);
		} catch (UnsupportedEncodingException e) {
			throw new InternalErrorException ("Error parsing json object", e);
		}
		return null;
	}

	public List<String> getRolesList() throws RemoteException,
			InternalErrorException {
		LinkedList<String> accounts = new LinkedList<String>();
		
		try {
			userRoles.clear();
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ROLE))
				{
					ExtensibleObject s = new ExtensibleObject();
					s.setObjectType(mapping.getSoffidObject().toString());
					ExtensibleObject eo = objectTranslator.generateObject(s, mapping, true);

					ExtensibleObjects objects = loadJsonObjects(eo, null);
					
					if (objects == null)
						throw new InternalErrorException("No roles found");
					for ( ExtensibleObject object : objects.getObjects())
					{
						String name = vom.toSingleString(objectTranslator.parseInputAttribute("name", object, mapping));
						if (name != null)
						{
							accounts.add(name);
						}
					}
				}
			}
			return accounts;
		} catch (JSONException e) {
			throw new InternalErrorException ("Error processing request", e);
		} catch (UnsupportedEncodingException e) {
			throw new InternalErrorException ("Error processing request", e);
		}
	}

	public void removeUser(String accountName) throws RemoteException,
			InternalErrorException {
		Account acc = getServer().getAccountInfo(accountName, getCodi());
		if (acc == null)
			removeScimUser(accountName);
		else
		{
			try {
				Usuari u = getServer().getUserInfo(accountName, getCodi());
				updateUser (acc, u);
			} catch (UnknownUserException e) {
				updateUser (acc);
			}
		}
	}
		
	public void removeScimUser(String accountName) throws RemoteException,
		InternalErrorException {
		Account acc = new Account();
		acc.setName(accountName);
		acc.setDispatcher(getCodi());
		ExtensibleObject userObject = new AccountExtensibleObject(acc,
						getServer());
		try {
			for (ExtensibleObjectMapping eom: objectMappings)
			{
				if (eom.getSoffidObject().equals(SoffidObjectType.OBJECT_ACCOUNT)  &&
						! "true".equals( eom.getProperties().get("preventDeletion")))
				{
					String condition = eom.getCondition();
					eom.setCondition(null);
					try {
						ExtensibleObject obj = objectTranslator.generateObject(userObject, eom);
						if (obj != null)
							removeObject(userObject, obj);
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

	public void updateUser(Account acc, Usuari user) throws RemoteException,
			InternalErrorException {
		ExtensibleObject sourceObject = new UserExtensibleObject(acc, user, getServer());
		sourceObject.setAttribute("password", getPassword(acc).getPassword());
		try {
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_USER) )
				{
					if (objectTranslator.evalCondition(sourceObject, mapping))
					{
		    			ExtensibleObject obj = objectTranslator.generateObject(sourceObject, mapping);
		    			if (obj != null)
		    				updateObject(sourceObject, obj);
					}
					else
					{
						removeScimUser(acc.getName());
					}
					updateAccountGrants(acc.getName());
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

	private Password getPassword(Account acc) throws InternalErrorException {
		Password p = getServer().getAccountPassword(acc.getName(), getCodi());
		if ( p == null)
			p = getServer().generateFakePassword(acc.getName(), getCodi());
		return p;
	}

	public void updateUser(Account acc) throws InternalErrorException {
		
		ExtensibleObject sourceObject = new AccountExtensibleObject(acc, getServer());
		sourceObject.setAttribute("password", getPassword(acc).getPassword());
		try {
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_ACCOUNT))
				{
					if (objectTranslator.evalCondition(sourceObject, mapping))
					{
		    			ExtensibleObject obj = objectTranslator.generateObject(sourceObject, mapping);
		    			if (obj != null)
		    				updateObject(sourceObject, obj);
					}
					else
					{
						removeScimUser(acc.getName());
					}
					updateAccountGrants(acc.getName());
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

	public void updateUserPassword(String accountName, Usuari user, Password password,
			boolean mustChange) throws RemoteException, InternalErrorException {
		Account acc = new Account ();
		acc.setName(accountName);
		if (user != null)
			acc.setDescription(user.getFullName());
		acc.setDispatcher(getCodi());
		ExtensibleObject object = user == null ?
				new AccountExtensibleObject(acc, getServer()) :
				new UserExtensibleObject(acc, user, getServer());
		object.setAttribute("password", password.getPassword());
		object.setAttribute("mustChange", mustChange);
		try {
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().toString().equals(object.getObjectType()))
				{
					if (objectTranslator.evalCondition(object, mapping))
					{
		    			ExtensibleObject obj = objectTranslator.generateObject(object, mapping);
		    			if (obj != null)
		    				updateObject(object, obj);
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

	public boolean validateUserPassword(String arg0, Password arg1)
			throws RemoteException, InternalErrorException {
		return false;
	}

	public void configureMappings(Collection<ExtensibleObjectMapping> mapping)
			throws RemoteException, InternalErrorException {
		this.objectMappings = mapping;
		this.objectTranslator = new ObjectTranslator(getDispatcher(), getServer(), mapping);
		final JSONAgent jsonAgent = this;
		objectTranslator.setObjectFinder(new ExtensibleObjectFinder() {
			
			public ExtensibleObject find(ExtensibleObject pattern) throws Exception {
				log.info("Searching for native object "+pattern.toString());
				return searchJsonObject(pattern, null);
			}

			@SuppressWarnings("unused")
			public Collection<Map<String,Object>> invoke (String verb, String command, Map<String, Object> params) throws InternalErrorException
			{
				if (debug)
				{
					log.info ("Invoking: "+verb+" on "+command);
				}
				if (verb.equalsIgnoreCase("invoke"))
				{
					List<Map<String,Object>> r = new LinkedList<Map<String,Object>>();
					String[] v = command.split("\\.");
					log.info("Searching for mapping "+v[0]);
					List<InvocationMethod> methods = getMethods(v[0], v[1]);
					if (methods.isEmpty())
					{
						log.info("Method "+v[1]+" does not exist for mapping "+v[0]);
						throw new InternalErrorException("Mapping "+v[0]+" does not exist");
					}
					for ( InvocationMethod m: methods)
					{
						ExtensibleObject o = new ExtensibleObject();
						o.setObjectType(v[0]);
						o.putAll(params);
						try {
							ExtensibleObjects objects = jsonAgent.invoke(m, o, null);
							for ( ExtensibleObject eo: objects.getObjects())
							{
								r.add(eo);
							}
						} catch (JSONException e) {
							throw new InternalErrorException("Error invoking method "+v[1]+" on object "+v[0]);
						}
					}
					return r;
				}
				else
				{
	
					Resource resource = client
							.resource(command)
							.contentType(MediaType.APPLICATION_JSON)
							.accept(MediaType.APPLICATION_JSON, MediaType.TEXT_XML);
	
					ClientResponse response = resource.invoke(verb, ClientResponse.class,
							params == null ? null : new JSONObject(params));
					
					String mimeType = response.getHeaders().getFirst("Content-Type");
					HashMap<String, Object> r = new HashMap<String, Object>();
					if (mimeType.contains("json"))
					{
						String txt = response.getEntity(String.class);
						parseJsonObject(null, command, txt, r);
						if (debug && txt != null)
						{
							log.info ("Result: "+txt);
						}
					} else if (mimeType.contains("xml")){
						byte[] data = response.getEntity(byte[].class);
						parseXmlObject(null, command, data, r);
					} else {
						throw new InternalErrorException("Unexpected response type " + mimeType);
					}
					LinkedList<Map<String,Object>> rl = new LinkedList<Map<String,Object>>();
					rl.add(r);
					return rl;
				}
			}

		});
	}


	protected ExtensibleObject searchJsonObject (ExtensibleObject object, ExtensibleObject sourceObject) throws InternalErrorException, JSONException, UnsupportedEncodingException
	{
		ExtensibleObjects objects = searchJsonObjects(object, sourceObject);
		if (objects != null && objects.getObjects().size() > 0)
		{
			if (objects.getObjects().size() > 1)
			{
				if (debug)
				{
					log.info("Search for "+object.getObjectType()+" object returned more than one result");
				}
				throw new InternalErrorException("Search for "+object.getObjectType()+" object returned more than one result");
			}
			return objects.getObjects().get(0);
		}
		return null;
	}

	private ExtensibleObjects searchJsonObjects (ExtensibleObject object, ExtensibleObject source) throws InternalErrorException, JSONException, UnsupportedEncodingException
	{
		for (InvocationMethod m: getMethods(object.getObjectType(), "select"))
		{
			ExtensibleObjects objects = invoke (m, object, source);
			if (objects != null && objects.getObjects().size() > 0)
			{
				return objects;
			}
		}
		return null;
	}

	private ExtensibleObjects loadJsonObjects (ExtensibleObject object, ExtensibleObject source) throws InternalErrorException, JSONException, UnsupportedEncodingException
	{
		for (InvocationMethod m: getMethods(object.getObjectType(), "load"))
		{
			ExtensibleObjects objects = invoke (m, object, source);
			if (objects != null && objects.getObjects().size() > 0)
			{
				return objects;
			}
		}
		return null;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	protected ExtensibleObjects invoke(InvocationMethod m, ExtensibleObject object, ExtensibleObject sourceObject) throws InternalErrorException, JSONException 
	{
		if ( sourceObject != null && m.condition != null && ! m.condition.trim().isEmpty())
		{
			if (! objectTranslator.evalExpression(sourceObject, m.condition))
			{
				log.info("Condition for method "+m.path+" did not return true. Skipping");
				return null;
			}
		}
		String path = translatePath (m, object);
		boolean repeat = false;
		boolean addParams = true;
		ExtensibleObjects eos = new ExtensibleObjects();
		do
		{
			repeat = false;
			try
			{
				ClientResponse response;
				if ( "GET".equalsIgnoreCase(m.method)) {
					if (m.encoding == null)
						m.encoding = MediaType.APPLICATION_FORM_URLENCODED;
					if (addParams)
					{
						String params = encode(m, object);
						if (params != null && ! params.isEmpty())
							path = path +"?"+params;
					}
					if (debug)
						log.info("Invoking GET on "+path);
					Resource request = client.resource(path)
							.accept(MediaType.APPLICATION_JSON, MediaType.TEXT_XML);
					addHeaders (request, m, object);
					response = request.get();
				} else {
					Resource request = client.resource(path)
							.contentType(m.encoding)
							.accept(MediaType.APPLICATION_JSON, MediaType.TEXT_XML);
					addHeaders (request, m, object);
					if ( "post".equalsIgnoreCase(m.method)) {
						if (m.encoding == null)
							m.encoding = MediaType.APPLICATION_FORM_URLENCODED;
						if (debug) debugObject("object: ",object,"  ");
						String params = encode(m, object);
						
						if (debug)
							log.info("Invoking POST on "+path+": "+params);
						
						response = request.post(params);
					} else if ( "put".equalsIgnoreCase(m.method))  {
						if (m.encoding == null)
							m.method = MediaType.APPLICATION_FORM_URLENCODED;
						String params = encode(m, object);

						if (debug)
							log.info("Invoking PUT on "+path+": "+params);

						response = request.put(params);
					} else if ( "delete".equalsIgnoreCase(m.method)) {
						if (m.encoding == null)
							m.method = MediaType.APPLICATION_FORM_URLENCODED;
						String params = encode(m, object);
						if (params != null && ! params.isEmpty())
							path = path +"?"+params;

						if (debug)
							log.info("Invoking DELETE on "+path);
						
						response = request.delete();
					} else {
						if (m.encoding == null)
							m.method = MediaType.APPLICATION_FORM_URLENCODED;
						String params = encode(m, object);

						if (debug)
							log.info("Invoking "+m.method+" on "+path+": "+params);

						response = request.invoke(m.method, ClientResponse.class, params);
					}
				}

				if (response.getStatusCode() == HttpStatus.NOT_FOUND.getCode())
				{
					response.consumeContent();
					return null;
				}
				if (response.getStatusCode() != HttpStatus.OK.getCode() &&
						response.getStatusCode() != HttpStatus.CREATED.getCode() &&
						response.getStatusCode() != HttpStatus.NO_CONTENT.getCode())
				{
					String text = response.getEntity(String.class);
					String message = response.getMessage();
					String UIMessage = "Error on invocation: "+message+"\n"+text;
					if (debug) log.info(UIMessage);
					int max = (UIMessage.length()>800) ? 800 : UIMessage.length();
					throw new InternalErrorException(UIMessage.substring(0, max));
				}
		
				if (response.getStatusCode() == HttpStatus.NO_CONTENT.getCode())
				{
					if (debug)
						log.info("No content received");
				}
				else
				{
					String mimeType = response.getHeaders().getFirst("Content-Type");
					ExtensibleObject resp = new ExtensibleObject();
					resp.setObjectType(object.getObjectType());
					if (mimeType.contains("json"))
					{
						String txt = response.getEntity(String.class);
						parseJsonObject(m, path, txt, resp);
					} else if (mimeType.contains("xml")){
						byte[] r = response.getEntity(byte[].class);
						parseXmlObject(m, path, r, resp);
					} else {
						throw new InternalErrorException("Unexpected response type " + mimeType);
					}
					
					
					if (debug)
					{
						debugObject("Received from "+path, resp, "  ");
					}
					
					if (m.check != null && !m.check.isEmpty())
					{
						objectTranslator.eval(m.check, resp);
					}
				
					if (m.results != null)
					{
						if (debug)
							log.info("Parsing results");
						Object result = objectTranslator.eval(m.results, resp);
						if (result instanceof Iterable)
						{
							for (Object o: ((Iterable) result))
							{
								ExtensibleObject eo = new ExtensibleObject();
								eo.setObjectType(object.getObjectType());
								if (o instanceof Map)
									eo.putAll((Map<? extends String, ? extends Object>) o);
								else
									eo.put("result", o);
								if (debug)
									debugObject("Parsed object:", eo, "  ");
								eos.getObjects().add(eo);
							}
						}
						else if (result.getClass().isArray())
						{
							for (Object o: ((Object[]) result))
							{
								ExtensibleObject eo = new ExtensibleObject();
								eo.setObjectType(object.getObjectType());
								if (o instanceof Map)
									eo.putAll((Map<? extends String, ? extends Object>) o);
								else
									eo.put("result", o);
								if (debug)
									debugObject("Parsed object:", eo, "  ");
								eos.getObjects().add(eo);
							}
						}
						else if (result != null)
						{
							ExtensibleObject eo = new ExtensibleObject();
							eo.setObjectType(object.getObjectType());
							if (result instanceof Map)
								eo.putAll((Map<? extends String, ? extends Object>) result);
							else
								eo.put("result", result);
							if (debug)
								debugObject("Parsed object:", eo, "  ");
							eos.getObjects().add(eo);
						} 
		
						if (m.next != null && !m.next.isEmpty())
						{
							path = (String) objectTranslator.eval(m.next, resp);
							if (path != null)
							{
								log.info("Jumping to next page: "+path);
								repeat = true;
								addParams = false;
							}
						}
					}
					else
					{
						eos.getObjects().add(resp);
					}
				}
			} catch (ClientWebException e) {
				createClient();
				throw new InternalErrorException ("Error "+e.getResponse().getStatusCode()+":"+e.getResponse().getMessage(),
						e);
			} catch (ClientRuntimeException e) {
				createClient();
				throw e;
			}
		} while (repeat);
		return eos;
	}

	private void parseXmlObject(InvocationMethod m, String path, byte[] r, Map<String, Object> resp) throws InternalErrorException {
		try {
			// Add header if needed
			DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
			builderFactory.setNamespaceAware(true);
			DocumentBuilder documentBuilder = builderFactory.newDocumentBuilder();
			Document doc = documentBuilder.parse( new ByteArrayInputStream(r) );
			if (debug)
			{
				log.info("Received XML document" + dumpXml(doc));
			}
			Element entity = doc.getDocumentElement();
			parseXmlEntity (entity, resp);
			fixupXmlObject(resp);
			if (m != null && m.results == null) 
				m.results = entity.getLocalName();
		} catch (Exception e) {
			throw new InternalErrorException("Error parsing document "+new String(r), e);
		}
	}

	@SuppressWarnings("unchecked")
	private void parseXmlEntity(Element entity, Map<String, Object> resp) {
		String tagName = entity.getLocalName();
		List<Object> o  = (List<Object>) resp.get(tagName);
		if (o == null)
		{
			o = new LinkedList<Object>();
			resp.put(tagName, o);
		}
		if (isComposed(entity))
		{
			Map<String,Object> r = new HashMap<String, Object>();
			o.add(r);
			Node child = entity.getFirstChild();
			while (child != null)
			{
				if (child instanceof Element)
					parseXmlEntity((Element) child, r);
				child = child.getNextSibling();
			}
			NamedNodeMap atts = entity.getAttributes();
			for (int i=0; i < atts.getLength(); i++)
			{
				Node att = atts.item(i);
				r.put(att.getNodeName(), att.getNodeValue());
			}
			fixupXmlObject(r);
		}
		else if (entity.getChildNodes().getLength() > 0)
		{
			o.add(entity.getTextContent());
		}
	}

	@SuppressWarnings("rawtypes")
	void fixupXmlObject (Map<String,Object> o )
	{
		for (String k: o.keySet())
		{
			Object v = o.get(k);
			if (v != null && v instanceof List)
			{
				v = ((List)v).toArray();
				o.put(k, v);
			}
		}
	}
	private boolean isComposed(Element entity) {
		if (entity.getAttributes().getLength() > 0)
			return true;
		Node child = entity.getFirstChild();
		while (child != null)
		{
			if (child instanceof Element)
				return true;
			child = child.getNextSibling();
		}
		return false;
	}

	private void parseJsonObject(InvocationMethod m, String path, String text, Map<String, Object> result)
			throws InternalErrorException {
		try {
			text = text.trim();
			if (text.startsWith("{"))
			{
				JSONObject respOb  = new JSONObject(text);
				Map<String, Object> map = new HashMap<String, Object>();
				json2map(respOb, map );
				result.putAll(map);
			} else if (text.startsWith("[")) {
				JSONArray respOb  = new JSONArray(text);
				Map<String, Object> map = new HashMap<String, Object>();
				map.put("result", json2java(respOb));
				result.putAll(map);
				if (m != null && m.results == null) 
					m.results = "result";
			} else
			{
				JSONTokener tokener = new JSONTokener(text);
				if (tokener.more())
					throw new InternalErrorException("Expecting JSON object from "+path+". Received:\n"+text);
				Object v = tokener.nextValue();
				result.put("result", v);
				if (tokener.more())
					throw new InternalErrorException("Expecting JSON object from "+path+". Received:\n"+text);
			}
		} catch (JSONException e) {
			throw new InternalErrorException("Expecting JSON object from "+path+". Received:\n"+text);
		}
	}

	protected void addHeaders(Resource request, InvocationMethod m, ExtensibleObject obj) throws InternalErrorException {
		if (m.headers != null)
			for (String[] header: m.headers)
				request.header(header[0],  translate(header[1], obj));
	}

	protected String translatePath(InvocationMethod m, ExtensibleObject object) throws InternalErrorException {
		String path = m.path;
		path = translate(path, object);
		return serverUrl+path;
	}

	private String translate(String path, ExtensibleObject object) throws InternalErrorException {
		int i = 0;
		while ( i < path.length() && ( i = path.indexOf("${", i)) >= 0)
		{
			int j = path.indexOf("}", i);
			if (j < 0)
			{
				break;
			}
			String expr = path.substring(i+2, j);
			String result = vom.toSingleString(objectTranslator.eval(expr, object));
			if (result == null)
				result = "";
			try {
				path = path.substring(0, i) + URLEncoder.encode(result, "UTF-8") + path.substring(j+1);
			} catch (UnsupportedEncodingException e) {
			}
			i++;
		}
		return path;
	}

	@SuppressWarnings("deprecation")
	protected String encode(InvocationMethod m, ExtensibleObject object) throws JSONException, InternalErrorException {
		if ("application/x-www-form-urlencoded".equalsIgnoreCase(m.encoding) ||
				"multipart/form-data".equalsIgnoreCase(m.encoding))
		{
			StringBuffer sb = new StringBuffer();
			if ( m.parameters == null )
			{
				for (String att: object.getAttributes())
				{
					if (object.getAttribute(att) != null)
					{
						if (sb.length() > 0)
							sb.append("&");
						sb.append(URLEncoder.encode(att))
							.append("=")
							.append(URLEncoder.encode(object.getAttribute(att).toString()));
					}
				}
			} else {
				for (String att: m.parameters)
				{
					if (object.getAttribute(att) != null)
					{
						if (sb.length() > 0)
							sb.append("&");
						sb.append(URLEncoder.encode(att))
							.append("=")
							.append(URLEncoder.encode(object.getAttribute(att).toString()));
					}
				}
			}
			return sb.toString();
		}
		else if ("text/xml".equalsIgnoreCase(m.encoding) )
		{
			if (m.template != null)
			{
				return encodeTemplate (m, object);
			}
			else 
			{
				return encodeDirect(m, object);
			}
		}
		else if  ( MediaType.APPLICATION_JSON.equalsIgnoreCase(m.encoding) )
		{
			HashMap<String, Object> hm = new HashMap<String, Object>();
			if ( m.parameters == null )
			{
				for (String att: object.getAttributes())
				{
					if (object.getAttribute(att) != null)
					{
						hm.put(att, object.getAttribute(att));
					}
				}
			} else {
				for (String att: m.parameters) {
					Object value = reviewObjectAndRemoveNulls(object.getAttribute(att));
					if (value != null) {
						hm.put(att, value);
					}
				}
			}
			if (debug) log.info("hm: "+hm);
			if (hm.isEmpty())
				return null;
			return java2json(hm).toString();
		} else {
			throw new InternalErrorException("Not supported encoding: "+m.encoding);
		}
	}

	private String encodeTemplate(InvocationMethod m, ExtensibleObject object) throws InternalErrorException {
		String template = templates.get(m.template);
		if (template == null)
			throw new InternalErrorException("Missing template " +m.template);
		try {
			// Add header if needed
			DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
			builderFactory.setNamespaceAware(true);
			DocumentBuilder documentBuilder = builderFactory.newDocumentBuilder();
			Document xslDocument = documentBuilder.parse(new ByteArrayInputStream(template.getBytes("UTF-8")));
			if (! xslDocument.getDocumentElement().getLocalName().equals("stylesheet"))
			{
				Document doc2 = documentBuilder.newDocument();
				Element e = doc2.createElementNS("http://www.w3.org/1999/XSL/Transform", "xsl:stylesheet");
				e.setAttribute("version", "1.0");
				doc2.appendChild(e);
				Element e2 = doc2.createElementNS("http://www.w3.org/1999/XSL/Transform", "template");
				e2.setAttribute("match", "/request");
				e.appendChild(e2);
				Node e3 = xslDocument.getDocumentElement().cloneNode(true);
				e2.appendChild(e3);
				xslDocument = doc2;
			}
			
			if (debug)
			{
				log.info("Using XSLT template" + dumpXml(xslDocument));
			}
			Document sourceDocument = documentBuilder.newDocument();
			Element root =  sourceDocument.createElement("request");
			sourceDocument.appendChild(root);
			fillXmlData (root, object);
			if (debug)
			{
				log.info("On source XML document:" + dumpXml(sourceDocument));
			}
			
			Source src = new DOMSource(sourceDocument);
			Source xslt = new DOMSource(xslDocument);
			StreamResult resultStream = new StreamResult();
			TransformerFactory factory = TransformerFactory
					.newInstance();
			StringWriter out = new StringWriter();
			resultStream.setWriter(out);
			Transformer trans = factory.newTransformer(xslt);
			trans.transform(src, resultStream);
			String result = out.getBuffer().toString();
			if (debug)
			{
				log.info("Transformed into XML document: "+result);
			}
			return result;
		} catch (Exception e) {
			throw new InternalErrorException(
					"Error transforming applying template "
							+ m.template, e);
		}
	}

	private String encodeDirect(InvocationMethod m, ExtensibleObject object) throws InternalErrorException {
		try 
		{
			DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
			builderFactory.setNamespaceAware(true);
			DocumentBuilder documentBuilder = builderFactory.newDocumentBuilder();
			Document sourceDocument = documentBuilder.newDocument();
			Map<String,Object> actualObject = null;
			String tagName;
			if (isSingleObject(object))
			{
				actualObject = object;
			}
			else
			{
				actualObject = new HashMap<String, Object>();
				actualObject.put("request", object);
			}
			tagName = actualObject.keySet().iterator().next();
			
			Element root =  sourceDocument.createElement(tagName);
			sourceDocument.appendChild(root);
			fillXmlData (root, actualObject);
			
			String result = dumpXml(sourceDocument);
			if (debug)
			{
				log.info("Transformed into XML document: "+result);
			}
			return result;
		} catch (Exception e) {
			throw new InternalErrorException(
					"Error transforming applying template "
							+ m.template, e);
		}
	}

	private String dumpXml(Document sourceDocument)
			throws TransformerFactoryConfigurationError, TransformerConfigurationException, TransformerException {
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer transformer = tf.newTransformer();
		transformer.setOutputProperty(OutputKeys.ENCODING, "utf-8");
		StringWriter writer = new StringWriter();
		transformer.transform(new DOMSource(sourceDocument), new StreamResult(writer));
		String result = writer.getBuffer().toString();
		return result;
	}

	private boolean isSingleObject(ExtensibleObject object) {
		Set<String> ks = object.keySet();
		if (ks.size() != 1)
			return false;
		Object v = object.get(ks.iterator().next());
		return v instanceof Map;
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private void fillXmlData(Element root, Object object) {
		if (object == null)
		{
			// Nothing to do
		}
		else if (object instanceof Map)
		{
			Map<String,Object> map = (Map<String, Object>) object;
			for (String k: map.keySet())
			{
				Object value = map.get(k);
				if (value == null)
				{
					Element e = root.getOwnerDocument().createElement(k);
					root.appendChild(e);
				}
				else if (value instanceof Collection)
				{
					for (Object v: (Collection) value)
					{
						Element e = root.getOwnerDocument().createElement(k);
						root.appendChild(e);
						fillXmlData (e, v);
					}
				}
				else if (value.getClass().isArray())
				{
					Object [] array = (Object[]) value;
					for (Object v: array)
					{
						Element e = root.getOwnerDocument().createElement(k);
						root.appendChild(e);
						fillXmlData (e, v);
					}
				}
				else
				{
					Element e = root.getOwnerDocument().createElement(k);
					root.appendChild(e);
					fillXmlData (e, value);					
				}
			}
		}
		else
		{
			Text tn = root.getOwnerDocument().createTextNode(object.toString());
			root.appendChild(tn);
		}
	}

	@SuppressWarnings("rawtypes")
	private Object reviewObjectAndRemoveNulls(Object obj) {
		if (debug) log.info(">>> obj: "+obj);
		if (obj==null) {
			return null;
		} else if (obj instanceof Map) {
			return reviewObjectAndRemoveNullsHashMap((HashMap) obj);
		} else {
			return obj;
		}
	}

	@SuppressWarnings("rawtypes")
	private Object reviewObjectAndRemoveNullsHashMap(HashMap hm) {
		if (debug) log.info(">>> hm: "+hm);
		HashMap newHm = (HashMap) hm.clone();
		String EMPTY = null;
		for (Object key: hm.keySet()) {
			if (debug) log.info(">>> key: "+key);
			Object value = hm.get(key);
			if (debug) log.info(">>> value: "+value);
			Object newValue = reviewObjectAndRemoveNulls(value);
			if (debug) log.info(">>> newValue: "+newValue);
			if (newValue==null || newValue.equals(EMPTY) || newValue.equals("null")) {
				newHm.remove(key);
				if (debug) log.info(">>>>>> remove from newHm the object: "+key);
			}
		}
		if (debug) log.info(">>> newHm.size(): "+newHm.size());
		if (!newHm.isEmpty()) {
			return newHm;
		} else {
			return null;
		}
	}

	@SuppressWarnings("rawtypes")
	protected void json2map(JSONObject jsonObject, Map<String,Object> map) throws JSONException 
	{
		for ( Iterator it = jsonObject.keys(); it.hasNext(); )
		{
			String key = (String) it.next();
			Object value = jsonObject.get(key);
			map.put(key, json2java(value));
		}
		
	}

	protected Object json2java(Object jsonObject) throws JSONException {
		if (jsonObject instanceof JSONObject)
		{
			Map<String,Object> map2 = new HashMap<String, Object>();
			json2map((JSONObject) jsonObject, map2);
			return map2;
		}
		else if (jsonObject instanceof JSONArray)
		{
			List<Object> list = new LinkedList<Object>();
			json2list((JSONArray) jsonObject, list);
			return list;
		}
		else
			return jsonObject;
	}

	private void json2list(JSONArray array, List<Object> list) throws JSONException {
		for (int i = 0;  i < array.length(); i ++)
		{
			Object value = array.get(i);
			list.add( json2java (value));
		}
	}

	@SuppressWarnings("rawtypes")
	private void map2json(Map<String,Object> map, JSONObject jsonObject) throws JSONException 
	{
		for ( Iterator it = map.keySet().iterator(); it.hasNext(); )
		{
			String key = (String) it.next();
			Object value = map.get(key);
			jsonObject.put(key, java2json(value));
		}
		
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private Object java2json(Object javaObject) throws JSONException {
		if (javaObject instanceof Map)
		{
			JSONObject jsonObject = new JSONObject();
			map2json((Map) javaObject, jsonObject);
			return jsonObject;
		}
		else if (javaObject instanceof JSONArray)
		{
			JSONArray jsonArray = new JSONArray();
			list2json ((List) javaObject, jsonArray);
			return jsonArray;
		}
		else
			return javaObject;
	}

	private void list2json(List<Object> list, JSONArray array) throws JSONException {
		for (Object javaObject: list)
		{
			array.put(java2json(javaObject));
		}
	}

	protected List<InvocationMethod> getMethods(String objectType, String phase) throws InternalErrorException {
		ExtensibleObjectMapping mapping = getMapping(objectType);
		Map<String, InvocationMethod> map = new HashMap<String, InvocationMethod>();
		
		for (String k: mapping.getProperties().keySet() )
		{
			if (k.startsWith(phase))
			{
				String tag = k.substring(phase.length());
				String number = "";
				while (! tag.isEmpty() && Character.isDigit(tag.charAt(0)))
				{
					number = number + tag.charAt(0);
					tag = tag.substring(1);
				}
				
				InvocationMethod im = map.get(number);
				if ( im == null)
				{
					im = new InvocationMethod();
					map.put(number, im);
					im.name = number;
				}
				if (tag.equalsIgnoreCase("Path"))
					im.path = mapping.getProperties().get(k);
				else if (tag.equalsIgnoreCase("Results"))
					im.results = mapping.getProperties().get(k);
				else if (tag.equalsIgnoreCase("Condition"))
					im.condition = mapping.getProperties().get(k);
				else if (tag.equalsIgnoreCase("Check"))
					im.check = mapping.getProperties().get(k);
				else if (tag.equalsIgnoreCase("Next"))
					im.next = mapping.getProperties().get(k);
				else if (tag.equalsIgnoreCase("Method"))
					im.method = mapping.getProperties().get(k);
				else if (tag.equalsIgnoreCase("Encoding"))
					im.encoding = mapping.getProperties().get(k);
				else if (tag.equalsIgnoreCase("Params"))
					im.parameters = mapping.getProperties().get(k).split("[, ]+");
				else if (tag.equalsIgnoreCase("Template"))
					im.template = mapping.getProperties().get(k);
				else if (tag.toLowerCase().startsWith("header"))
				{
					String v = mapping.getProperties().get(k);
					int i = v.indexOf(':');
					if (im.headers == null)
						im.headers = new LinkedList<String[]>();
					if (i > 0)
						im.headers.add(new String [] {
								v.substring(0, i).trim(),
								v.substring(i+1).trim()
						});
					else
						im.headers.add(new String [] {
								v.trim(),
								""
						});
				}
				else
					throw new InternalErrorException("Unexpected property "+k+" for object type "+objectType);
			}
		}
		List<InvocationMethod> methods = new LinkedList<InvocationMethod>(map.values());
		Collections.sort(methods, new Comparator<InvocationMethod>() {
			public int compare(InvocationMethod o1, InvocationMethod o2) {
				return o1.name.compareTo(o2.name);
			}
		});
		
		if (methods.size() == 0)
			log.info("Notice: No properties found for method "+phase);
		return methods;
	}

	protected void updateObject (ExtensibleObject soffidObject, ExtensibleObject targetObject)
			throws InternalErrorException
	{
		try
		{
			ExtensibleObject existingObject = searchJsonObject(targetObject, soffidObject);
		
			if (existingObject == null)
			{
				boolean triggerRan = false;
				ExtensibleObjects response = null;
				for (InvocationMethod m: getMethods(targetObject.getObjectType(), "insert"))
				{
					if (triggerRan || runTrigger(SoffidObjectTrigger.PRE_INSERT, soffidObject, targetObject, existingObject))
					{
						triggerRan = true;
						response = invoke (m, targetObject, soffidObject);
					}
					if (triggerRan)
						runTrigger(SoffidObjectTrigger.POST_INSERT, soffidObject, targetObject, existingObject, response);
				}
			}
			else
			{
				boolean triggerRan = false;
				ExtensibleObjects response = null;
				for (InvocationMethod m: getMethods(targetObject.getObjectType(), "update"))
				{
					if (triggerRan || runTrigger(SoffidObjectTrigger.PRE_UPDATE, soffidObject, targetObject, existingObject))
					{
						triggerRan = true;
						response = invoke (m, targetObject, soffidObject);
					}
					if (triggerRan)
						runTrigger(SoffidObjectTrigger.POST_UPDATE, soffidObject, targetObject, existingObject, response);
				}
			}
		}
		catch (Exception e)
		{
			String error = (targetObject.toString().length()>MAX_LOG) ? targetObject.toString().substring(0, MAX_LOG) : targetObject.toString();
			String msg = "updating object : " + error + " (log truncated) ...";
			log.warn(msg, e);
			throw new InternalErrorException(msg, e);
		}
	}

	private ExtensibleObjectMapping getMapping(String objectType) {
		for (ExtensibleObjectMapping map: objectMappings)
		{
			if ( map.getSystemObject().equals(objectType))
				return map;
		}
		return null;
	}
	
	protected void debugObject (String msg, Object obj, String indent)
	{
		debugObject(msg, obj, indent, "");
	}
	
	@SuppressWarnings({ "rawtypes", "unchecked" })
	void debugObject (String msg, Object obj, String indent, String attributeName)
	{
		if (debug)
		{
			if (msg != null)
				log.info(indent + msg);
			if (obj == null)
			{
				log.info (indent+attributeName.toString()+": null");
			}
			else if (obj instanceof Collection)
			{
				log.info (indent+attributeName+"Collection [");
				Iterable l = (Iterable) obj;
				int i = 0;
				for (Object subObj2: l)
				{
					debugObject (null, subObj2, indent+"   ", ""+(i++)+": ");
				}
				log.info (indent+"]");
				
			}
			else if (obj.getClass().isArray())
			{
				log.info (indent+attributeName+"Array [");
				int i = 0;
				for (Object subObj2: (Object[]) obj)
				{
					debugObject (null, subObj2, indent+"   ", ""+(i++)+": ");
				}
				log.info (indent+"]");
				
			}
			else if (obj instanceof Map)
			{
				log.info (indent+attributeName+" {");
				Map<String,Object> m = (Map<String, Object>) obj;
				for (String attribute: m.keySet())
				{
					Object subObj = m.get(attribute);
					debugObject(null, subObj, indent+"   ", attribute+": ");
				}
				log.info (indent+" }");
			}
			else
			{
				log.info (indent+attributeName.toString()+obj.toString());
			}
		}
	}
	
	/**
	 * Actualizar los datos del usuario. Crea el usuario en la base de datos y
	 * le asigna una contraseña aleatoria. <BR>
	 * Da de alta los roles<BR>
	 * Le asigna los roles oportuno.<BR>
	 * Le retira los no necesarios.
	 * 
	 * @param user
	 *            código de usuario
	 * @throws java.rmi.RemoteException
	 *             error de comunicaciones con el servidor
	 * @throws InternalErrorException
	 *             cualquier otro problema
	 */
	public void updateUser(String account, Usuari usu)
			throws java.rmi.RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		Account acc = getServer().getAccountInfo(account, getCodi());
		updateUser (acc, usu);
	}

	public void updateUser(String account, String descripcio)
			throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		Account acc = getServer().getAccountInfo(account, getCodi());
		if (acc == null)
			removeScimUser(account);
		else
			updateUser (acc);
	
	}

	protected boolean runTrigger (SoffidObjectTrigger triggerType,
			ExtensibleObject soffidObject,
			ExtensibleObject newObject,
			ExtensibleObject oldObject) throws InternalErrorException
	{
		return runTrigger (triggerType, soffidObject, newObject, oldObject, null);
	}

	protected boolean runTrigger (SoffidObjectTrigger triggerType,
			ExtensibleObject soffidObject,
			ExtensibleObject newObject,
			ExtensibleObject oldObject,
			ExtensibleObjects response) throws InternalErrorException
	{
		log.info("Testing trigger "+triggerType.toString());
		log.info("  oldObjectType "+(oldObject == null ? "null": oldObject.getObjectType()));
		log.info("  newObjectType "+(newObject == null ? "null": newObject.getObjectType()));
		log.info("  soffidType    "+(soffidObject == null ? "null": soffidObject.getObjectType()));
		log.info("  response      "+(response == null ? "null": response.toString()));
		SoffidObjectType sot = SoffidObjectType.fromString(soffidObject.getObjectType());
		for ( ExtensibleObjectMapping eom : objectTranslator.getObjectsBySoffidType(sot))
		{
			if (oldObject == null || oldObject.getObjectType().equals(eom.getSystemObject()))
			{
				if (newObject == null || newObject.getObjectType().equals(eom.getSystemObject()))
				{
					for ( ObjectMappingTrigger trigger: eom.getTriggers())
					{
						if (trigger.getTrigger().equals (triggerType))
						{
							log.info("  found "+trigger.getScript());
							ExtensibleObject eo = new ExtensibleObject();
							eo.setAttribute("source", soffidObject);
							eo.setAttribute("newObject", newObject);
							eo.setAttribute("oldObject", oldObject);
							eo.setAttribute("response", response);
							if ( ! objectTranslator.evalExpression(eo, trigger.getScript()) )
							{
								log.info("Trigger "+triggerType+" returned false");
								if (debug)
								{
									if (oldObject != null)
										debugObject("old object", oldObject, "  ");
									if (newObject != null)
										debugObject("new object", newObject, "  ");
								}
								return false;
							}
						}
					}
				}
			}
		}
		return true;
		
	}

	public ExtensibleObject getNativeObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		return null;
	}

	public ExtensibleObject getSoffidObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		return null;
	}
}
	