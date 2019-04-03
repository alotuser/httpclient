package qt.httpclients;

import java.io.Serializable;

/***
 * 简易HTTpClient
 * 
 * @author ChileQi
 * @since 2017年8月4日 17:15:43
 */
public class QtHttpProxy implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = -5856118710246797948L;

	public QtHttpProxy() {
	}

	public QtHttpProxy(String hostName) {
		super();
		this.hostName = hostName;
	}

	public QtHttpProxy(String hostName, int port) {
		super();
		this.hostName = hostName;
		this.port = port;
	}

	public QtHttpProxy(String hostName, int port, String userName, String password) {
		super();
		this.hostName = hostName;
		this.port = port;
		this.userName = userName;
		this.password = password;
	}

	private String hostName;
	private int port = 80;
	private String userName;
	private String password;

	public String getHostName() {
		return hostName;
	}

	public void setHostName(String hostName) {
		this.hostName = hostName;
	}

	public int getPort() {
		return port;
	}

	public void setPort(int port) {
		this.port = port;
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

}
