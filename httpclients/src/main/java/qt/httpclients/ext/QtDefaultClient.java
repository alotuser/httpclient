package qt.httpclients.ext;

import qt.httpclients.ext.enums.Referers;

public class QtDefaultClient {

	public Referers referers=Referers.DEFAULT;// 是否自动referer( 默认 DEFAULT ,自动重定向才启用)
	
	public static QtDefaultClient empty() {
		return new QtDefaultClient();
	}
	
	
	
}
