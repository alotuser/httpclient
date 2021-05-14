package qt.httpclients;

import java.util.List;

import org.apache.http.Header;
import org.apache.http.client.CookieStore;

/***
 * 简易HttpClient
 * 
 * @author ChileQi
 * @since 2017年8月4日 17:15:43
 */
public class QtHttpResult {

	public String cookie;// Http请求返回的Cookie

	public CookieStore cookieStore;// Cookie对象集合

	public String html;// 返回的String类型数据 只有ResultType.String时才返回数据，其它情况为空

	public byte[] resultByte;/// 返回的Byte数组 只有ResultType.Byte时才返回数据，其它情况为空

	public Header[] header; /// header对象

	public String statusDescription;/// 返回状态说明

	public int statusCode;/// 返回状态码,默认为OK

	public String responseUri;/// 最后访问的URl

	public String redirectUrl;/// 获取重定向的URl

	public List<?> redirectLocations;

	public String getCookie() {
		return cookie;
	}

	public void setCookie(String cookie) {
		this.cookie = cookie;
	}

	public CookieStore getCookieStore() {
		return cookieStore;
	}

	public void setCookieStore(CookieStore cookieStore) {
		this.cookieStore = cookieStore;
	}

	public String getHtml() {
		return html;
	}

	public void setHtml(String html) {
		this.html = html;
	}

	public byte[] getResultByte() {
		return resultByte;
	}

	public void setResultByte(byte[] resultByte) {
		this.resultByte = resultByte;
	}

	public Header[] getHeader() {
		return header;
	}

	public void setHeader(Header[] header) {
		this.header = header;
	}

	public String getStatusDescription() {
		return statusDescription;
	}

	public void setStatusDescription(String statusDescription) {
		this.statusDescription = statusDescription;
	}

	public int getStatusCode() {
		return statusCode;
	}

	public void setStatusCode(int statusCode) {
		this.statusCode = statusCode;
	}

	public String getResponseUri() {
		return responseUri;
	}

	public void setResponseUri(String responseUri) {
		this.responseUri = responseUri;
	}

	public String getRedirectUrl() {
		return redirectUrl;
	}

	public void setRedirectUrl(String redirectUrl) {
		this.redirectUrl = redirectUrl;
	}

	public enum HttpStatusCode {
		OK, NO
	}
}
