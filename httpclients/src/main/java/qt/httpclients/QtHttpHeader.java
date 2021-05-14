package qt.httpclients;

import java.util.HashMap;
import java.util.Map;

/***
 * 简易HttpClient
 * 
 * @author ChileQi
 * @since 2017年8月4日 17:15:43
 */
public class QtHttpHeader {

	private Map<String, String> headers;// 标头信息

	public QtHttpHeader put(String key, String value) {

		if (null == headers) {
			headers = new HashMap<String, String>();
		}
		headers.put(key, value);
		return this;
	}

	public Map<String, String> getHeaders() {
		if (null == headers) {
			headers = new HashMap<String, String>();
		}
		return headers;
	}

}
