// Copyright (c) 2000 Govern  de les Illes Balears
package com.soffid.iam.agent.zarafa;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.rmi.RemoteException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import es.caib.seycon.ng.comu.Dispatcher;
import es.caib.seycon.ng.comu.DispatcherAccessControl;
//import es.caib.seycon.InternalErrorException;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.util.TimedOutException;
import es.caib.seycon.util.TimedProcess;
import es.caib.seycon.UnknownUserException;
import es.caib.seycon.ng.comu.ControlAcces;
import es.caib.seycon.ng.comu.DadaUsuari;
import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.UnknownRoleException;
import es.caib.seycon.ng.sync.agent.Agent;
import es.caib.seycon.ng.sync.intf.AccessControlMgr;
import es.caib.seycon.ng.sync.intf.AccessLogMgr;
import es.caib.seycon.ng.sync.intf.GroupMgr;
import es.caib.seycon.ng.sync.intf.LogEntry;
import es.caib.seycon.ng.sync.intf.RoleInfo;
import es.caib.seycon.ng.sync.intf.RoleMgr;
import es.caib.seycon.ng.sync.intf.UserInfo;
import es.caib.seycon.ng.sync.intf.UserMgr;
import es.caib.seycon.db.LogInfoConnection;

/**
 * Agente to manage Zarafa server
 * <P>
 * 
 */

public class ZarafaAgent extends Agent implements UserMgr, RoleMgr, GroupMgr {
	/** zarfa-admin program */
	transient String zarafaAdmin;
	transient String zarafaAdminRole;
	final static int TIMEOUT = 10000;

	/**
	 * Constructor
	 * 
	 * @param params
	 *            vector con parámetros de configuración: <LI>0 = usuario</LI>
	 *            <LI>1 = contraseña oracle</LI> <LI>2 = cadena de conexión a la
	 *            base de datos</LI> <LI>3 = contraseña con la que se protegerán
	 *            los roles</LI>
	 */
	public ZarafaAgent() throws java.rmi.RemoteException {
		super();
	}

	/**
	 * Inicializar el agente.
	 */
	public void init() throws InternalErrorException {
		zarafaAdmin = getDispatcher().getParam0();
		if (zarafaAdmin == null || zarafaAdmin.length() == 0) {
			zarafaAdmin = "zarafa-admin";
		}
		zarafaAdminRole = getDispatcher().getParam1();
		if (zarafaAdminRole == null || zarafaAdminRole.length() == 0) {
			zarafaAdminRole = "ZARAFA_ADMIN";
		}
		log.info("Starting Zarafa Agent {}", getDispatcher().getCodi(), null);
	}

	private ZarafaUserInfo getZarafaUser(String name) throws IOException,
			TimedOutException {
		TimedProcess p = new TimedProcess(TIMEOUT*2);
		if (p.exec( new String[] {zarafaAdmin, "--details", name}) == 0) {
			String out = p.getOutput();
			Pattern pattern = Pattern.compile("^Groups \\(\\d+\\).*$");
			Matcher m = pattern.matcher(out);
			LinkedList<String> groups = new LinkedList<String>();
			if (m.find()) {
				int next = m.regionEnd();
				Pattern pattern2 = Pattern.compile("^\\s+(.*)$");
				Matcher m2 = pattern.matcher(out);
				while (m2.find(next + 1)) {
					groups.add(m2.group(1));
					next = m2.end() + 1;
				}
			}
			ZarafaUserInfo zui = new ZarafaUserInfo();
			zui.user = name;
			zui.groups = groups;
			return zui;
		} else {
			if (p.getError().indexOf("not found") >= 0)
				return null;
			else
				throw new IOException("Error executing " + zarafaAdmin + " --details :"
						+ p.getError());
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
	public void updateUser(String codiCompte, Usuari usu)
			throws java.rmi.RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		try {
			// Obtener los datos del usuario
			Collection<RolGrant> roles = getServer().getAccountRoles(
					codiCompte, this.getDispatcher().getCodi());

			Collection<Grup> groups;
			if (getDispatcher().getBasRol()) {
				groups = null;
			} else {
				groups = getServer().getUserGroups(usu.getId());
			}
			LinkedList<String> groupsAndRoles = concatUserGroupsAndRoles(groups, roles);
			boolean isAdmin = containsAdminRole (roles);

			// Comprobar si el usuario existe
			ZarafaUserInfo zarafaUser = getZarafaUser(codiCompte);
			if (zarafaUser == null) {
				LinkedList<String> args = new LinkedList<String>();
				args.add(zarafaAdmin);
				args.add("-c");
				args.add(codiCompte);
				args.add("-p");
				Password pass = getServer().getOrGenerateUserPassword(codiCompte,
						getDispatcher().getCodi());
				args.add(pass.getPassword());
				String email = getEmail(usu);
				if (email != null)
				{
					args.add("-e");
					args.add(getEmail(usu));
				}
				args.add("-f");
				args.add(usu.getFullName());
				args.add("-a");
				args.add(isAdmin? "2": "0");
				args.add("-n");
				args.add("1");
				

//				String cmdLine = generateCommandLine(args.toArray(new String[args.size()]));
				TimedProcess p = new TimedProcess(TIMEOUT);
				if (p.exec(args.toArray(new String[args.size()])) != 0)
				{
					throw new InternalErrorException("Error executing "+zarafaAdmin+" -c : "+p.getError());
				}
				updateGroups (codiCompte, groupsAndRoles, new LinkedList<String>());
			}
			else
			{
				LinkedList<String> args = new LinkedList<String>();
				args.add(zarafaAdmin);
				args.add("-u");
				args.add(codiCompte);
				String email = getEmail(usu);
				if (email != null)
				{
					args.add("-e");
					args.add(getEmail(usu));
				}
				args.add("-f");
				args.add(usu.getFullName());
				args.add("-a");
				args.add(isAdmin? "2": "0");
				args.add("-n");
				args.add("1");
				

				
				TimedProcess p = new TimedProcess(TIMEOUT);
				if (p.exec(args.toArray(new String[args.size()])) != 0)
				{
					throw new InternalErrorException("Error executing zarafa-admin -c: "+p.getError());
				}
				updateGroups (codiCompte, groupsAndRoles, zarafaUser.groups);
			}
			
			
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException("Error processing task", e);
		}
	}

	private void updateGroups(final String codiCompte,
			Collection<String> groupsAndRoles, Collection<String> currentRoles) throws Exception {
		CollectionComparator<String, String> comparator = new CollectionComparator<String, String>(
			new CollectionUpdater<String, String>() {

			public boolean areEqual(String first, String second) {
				return first.equals(second);
			}

			public void onSecond(String obj) throws Exception {
				// Remove user from group
				TimedProcess p = new TimedProcess(TIMEOUT);
				p.exec (new String[] {zarafaAdmin, "-B", codiCompte, "-i", obj});
			}

			public void onFirst(String obj) throws Exception {
				// Add user from group
				TimedProcess p = new TimedProcess(TIMEOUT);
				p.exec (new String[] {zarafaAdmin, "-b", codiCompte, "-i", obj});
			}

			public void onBoth(String first, String second) {
				// Nothing to do
			}
		});
		comparator.compare(groupsAndRoles, currentRoles);
	}

	private String getEmail(Usuari usu) throws InternalErrorException, es.caib.seycon.ng.exception.UnknownUserException {
		if (usu.getNomCurt() != null)
			return usu.getNomCurt()+"@"+usu.getDominiCorreu();
		DadaUsuari data = getServer().getUserData(usu.getId(), "EMAIL");
		if (data != null)
			return data.getValorDada();
		else
			return usu.getCodi();
	}

	private boolean containsAdminRole(Collection<RolGrant> roles) {
		for (RolGrant role: roles)
		{
			if (role.getRolName().equals (zarafaAdminRole))
				return true;
		}
		return false;
	}

	/**
	 * Actualizar la contraseña del usuario. Asigna la contraseña si el usuario
	 * está activo y la contraseña no es temporal. En caso de contraseñas
	 * temporales, asigna un contraseña aleatoria.
	 * 
	 * @param user
	 *            código de usuario
	 * @param password
	 *            contraseña a asignar
	 * @param mustchange
	 *            es una contraseña temporal?
	 * @throws java.rmi.RemoteException
	 *             error de comunicaciones con el servidor
	 * @throws InternalErrorException
	 *             cualquier otro problema
	 */
	public void updateUserPassword(String user, Usuari usuari, Password password,
			boolean mustchange)
			throws es.caib.seycon.ng.exception.InternalErrorException {
		try {
			ZarafaUserInfo zui = getZarafaUser(user);
			if (zui == null)
				updateUser(user, usuari);
			
			LinkedList<String> args = new LinkedList<String>();
			args.add(zarafaAdmin);
			args.add("-u");
			args.add(user);
			args.add("-p");
			args.add(password.getPassword());
			TimedProcess p = new TimedProcess(TIMEOUT);
			if (p.exec(args.toArray(new String[args.size()])) != 0)
			{
				throw new InternalErrorException("Error executing zarafa-admin -c: "+p.getError());
			}
		} catch (RemoteException e) {
			throw new InternalErrorException("Error update password", e);
		} catch (IOException e) {
			throw new InternalErrorException("Error update password", e);
		} catch (TimedOutException e) {
			throw new InternalErrorException("Error update password", e);
		}
	}

	/**
	 * Validar contraseña.
	 * 
	 * @param user
	 *            código de usuario
	 * @param password
	 *            contraseña a asignar
	 * @return false
	 * @throws java.rmi.RemoteException
	 *             error de comunicaciones con el servidor
	 * @throws InternalErrorException
	 *             cualquier otro problema
	 */
	public boolean validateUserPassword(String user, Password password)
			throws java.rmi.RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		return false;
	}

	/**
	 * Concatenar los vectores de grupos y roles en uno solo. Si el agente está
	 * basado en roles y no tiene ninguno, retorna el valor null
	 * 
	 * @param groups
	 *            vector de grupos
	 * @param roles
	 *            vector de roles
	 * @return vector con nombres de grupo y role
	 */
	public LinkedList<String> concatUserGroupsAndRoles(Collection<Grup> groups,
			Collection<RolGrant> roles) {
		int i;
		int j;

		if (roles.isEmpty() && getDispatcher().getBasRol()) // roles.length == 0
															// && getRoleBased
															// ()
			return null;
		LinkedList<String> concat = new LinkedList<String>();
		if (groups != null) {
			for (Grup g : groups)
				concat.add(g.getCodi());
		}
		for (RolGrant rg : roles) {
			concat.add(rg.getRolName());
		}

		return concat;
	}

	public String[] concatRoleNames(Collection<RolGrant> roles) {
		if (roles.isEmpty() && getDispatcher().getBasRol())
			return null;

		LinkedList<String> concat = new LinkedList<String>();
		for (RolGrant rg : roles) {
			concat.add(rg.getRolName());
		}

		return concat.toArray(new String[concat.size()]);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see es.caib.seycon.RoleMgr#UpdateRole(java.lang.String,
	 * java.lang.String)
	 */
	public void updateRole(Rol ri) throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		if (ri.getBaseDeDades().equals (getDispatcher().getCodi()))
		{
			
			try {
				LinkedList<String> args = new LinkedList<String>();
				args.add(zarafaAdmin);
				args.add("-g");
				args.add(ri.getNom());
				TimedProcess p = new TimedProcess(TIMEOUT);
				if (p.exec(args.toArray(new String[args.size()])) != 0)
				{
					if (!p.getError().contains("already exists"))
						throw new InternalErrorException("Error executing zarafa-admin -g: "+p.getError());
				}
			} catch (RemoteException e) {
				throw new InternalErrorException("Error update password", e);
			} catch (IOException e) {
				throw new InternalErrorException("Error update password", e);
			} catch (TimedOutException e) {
				throw new InternalErrorException("Error update password", e);
			}
		}
	}


	public void removeRole(String nom, String bbdd) throws InternalErrorException {
		if (bbdd.equals (getCodi()))
		{
			try {
				LinkedList<String> args = new LinkedList<String>();
				args.add(zarafaAdmin);
				args.add("-G");
				args.add(nom);
				TimedProcess p = new TimedProcess(TIMEOUT);
				if (p.exec(args.toArray(new String[args.size()])) != 0)
				{
					if (!p.getError().contains("not found"))
						throw new InternalErrorException("Error executing zarafa-admin -g: "+p.getError());
				}
			} catch (RemoteException e) {
				throw new InternalErrorException("Error update password", e);
			} catch (IOException e) {
				throw new InternalErrorException("Error update password", e);
			} catch (TimedOutException e) {
				throw new InternalErrorException("Error update password", e);
			}
		}
	}

	public void removeUser(String user) throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		try {
			ZarafaUserInfo zui = getZarafaUser(user);
			if (zui != null)
			{
				LinkedList<String> args = new LinkedList<String>();
				args.add(zarafaAdmin);
				args.add("-d");
				args.add(user);
				TimedProcess p = new TimedProcess(TIMEOUT);
				if (p.exec(args.toArray(new String[args.size()])) != 0)
				{
					throw new InternalErrorException("Error executing zarafa-admin -c: "+p.getError());
				}
			}
		} catch (RemoteException e) {
			throw new InternalErrorException("Error update password", e);
		} catch (IOException e) {
			throw new InternalErrorException("Error update password", e);
		} catch (TimedOutException e) {
			throw new InternalErrorException("Error update password", e);
		}
	}

	public void updateUser(String account, String descripcio)
			throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		try {
			// Obtener los datos del usuario
			Collection<RolGrant> roles = getServer().getAccountRoles(
					account, this.getDispatcher().getCodi());

			Collection<Grup> groups;
			LinkedList<String> groupsAndRoles = concatUserGroupsAndRoles(null, roles);
			boolean isAdmin = containsAdminRole (roles);

			// Comprobar si el usuario existe
			ZarafaUserInfo zarafaUser = getZarafaUser(account);
			if (zarafaUser == null) {
				LinkedList<String> args = new LinkedList<String>();
				args.add(zarafaAdmin);
				args.add("-c");
				args.add(account);
				args.add("-p");
				Password pass = getServer().getOrGenerateUserPassword(account,
						getDispatcher().getCodi());
				args.add(pass.getPassword());
				args.add("-f");
				args.add(descripcio);
				args.add("-a");
				args.add(isAdmin? "2": "0");
				args.add("-n");
				args.add("1");
				args.add("-e");
				args.add(account);
				

				TimedProcess p = new TimedProcess(TIMEOUT);
				if (p.exec(args.toArray(new String[args.size()])) != 0)
				{
					throw new InternalErrorException("Error executing zarafa-admin -c: "+p.getError());
				}
				updateGroups (account, groupsAndRoles, new LinkedList<String>());
			}
			else
			{
				LinkedList<String> args = new LinkedList<String>();
				args.add(zarafaAdmin);
				args.add("-u");
				args.add(account);
				args.add("-f");
				args.add(descripcio);
				args.add("-a");
				args.add(isAdmin? "2": "0");
				args.add("-n");
				args.add("1");
				

				TimedProcess p = new TimedProcess(TIMEOUT);
				if (p.exec(args.toArray(new String[args.size()])) != 0)
				{
					throw new InternalErrorException("Error executing zarafa-admin -c: "+p.getError());
				}
				updateGroups (account, groupsAndRoles, zarafaUser.groups);
			}
			
			
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException("Error processing task", e);
		}
	}

	public void updateGroup(String nom, Grup grup) throws RemoteException,
			InternalErrorException {
		try {
			LinkedList<String> args = new LinkedList<String>();
			args.add(zarafaAdmin);
			args.add("-g");
			args.add(nom);
			TimedProcess p = new TimedProcess(TIMEOUT);
			if (p.exec(args.toArray(new String[args.size()])) != 0)
			{
				if (!p.getError().contains("already exists"))
					throw new InternalErrorException("Error executing zarafa-admin -G: "+p.getError());
			}
		} catch (RemoteException e) {
			throw new InternalErrorException("Error update password", e);
		} catch (IOException e) {
			throw new InternalErrorException("Error update password", e);
		} catch (TimedOutException e) {
			throw new InternalErrorException("Error update password", e);
		}
	}

	public void removeGroup(String nom) throws RemoteException,
			InternalErrorException {
		try {
			LinkedList<String> args = new LinkedList<String>();
			args.add(zarafaAdmin);
			args.add("-G");
			args.add(nom);
			TimedProcess p = new TimedProcess(TIMEOUT);
			if (p.exec(args.toArray(new String[args.size()])) != 0)
			{
				if (!p.getError().contains("not found"))
					throw new InternalErrorException("Error executing zarafa-admin -G: "+p.getError());
			}
		} catch (RemoteException e) {
			throw new InternalErrorException("Error update password", e);
		} catch (IOException e) {
			throw new InternalErrorException("Error update password", e);
		} catch (TimedOutException e) {
			throw new InternalErrorException("Error update password", e);
		}
	}
}

class ZarafaUserInfo {
	String user;
	Collection<String> groups = new LinkedList<String>();
}
