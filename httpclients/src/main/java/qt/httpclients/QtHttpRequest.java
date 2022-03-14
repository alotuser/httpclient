package qt.httpclients;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.apache.http.NameValuePair;
import org.apache.http.client.CookieStore;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.message.BasicNameValuePair;

import qt.httpclients.ext.enums.ResultType;

/***
 * 简易HttpClient
 * 
 * @author ChileQi
 * @since 2017年8月4日 17:15:43
 */
public class QtHttpRequest {
	public String url;// 请求URL必须填写
	public int timeout;// 默认请求超时时间
	public int keepAlive;// 资源建立持久性连接时间
	public boolean redirectsEnabled;// 是否自动重定向 默认 false
	public QtHttpHeader headers;// 标头信息
	public String charset;// 默认UTF-8
	public ContentType contentType;
	public List<NameValuePair> formData;// 表单提交数据,etc:username=Jack&password=123456
	public String postData;// text json xml等数据
	public Collection<? extends File> postFile;// 文件
	public QtHttpProxy proxy;// ip代理
	public CookieStore cookieStore;
	public ResultType resultType;
	private int socketTimeout;// 默认请求超时时间
	private int connectTimeout;// 默认请求超时时间
	private int connectionRequestTimeout;// 默认请求超时时间

	public QtHttpRequest(String url) {
		this.url = url;
		timeout = 10000;
		keepAlive = -60000;// 如果服务器没有设置keep-alive这个参数，我们就把它设置成1分钟
		headers = new QtHttpHeader();
		formData = new ArrayList<NameValuePair>();
		charset = "UTF-8";
		cookieStore = new BasicCookieStore();
		if (null != contentType) {
			if (null != contentType.getCharset()) {
				contentType.withCharset(charset);// (Charset.forName("UTF-8"));
			}
		} else {
			contentType = ContentType.DEFAULT_TEXT;
			contentType.withCharset(charset);
		}
	}

	/**
	 * 填充提交参数
	 * 
	 * @param name  name
	 * @param value value
	 * @return QtHttpRequest
	 */
	public QtHttpRequest putFormData(String name, String value) {
		this.formData.add(new BasicNameValuePair(name, value));
		return this;
	}

	/**
	 * 填充提交参数
	 * 
	 * @param datas datas
	 * @return QtHttpRequest
	 */
	public QtHttpRequest putFormData(Map<String, String> datas) {
		if (null != datas) {
			datas.forEach((name, value) -> {
				this.formData.add(new BasicNameValuePair(name, value));
			});
		}
		return this;
	}

	/**
	 * 填充提交参数（等同putFormData）
	 * 
	 * @param name  name
	 * @param value value
	 * @return QtHttpRequest
	 */
	public QtHttpRequest putData(String name, String value) {
		return putFormData(name, value);
	}

	/**
	 * 填充提交参数（等同putFormDatas）
	 * 
	 * @param datas datas
	 * @return QtHttpRequest
	 */
	public QtHttpRequest putData(Map<String, String> datas) {
		return putFormData(datas);
	}

	/**
	 * 设置头
	 * 
	 * @param name  name
	 * @param value value
	 * @return QtHttpRequest
	 */
	public QtHttpRequest putHeader(String name, String value) {
		this.headers.getHeaders().put(name, value);
		return this;
	}

	/**
	 * 设置头
	 * 
	 * @param headers headers
	 * @return QtHttpRequest
	 */
	public QtHttpRequest putHeader(Map<String, String> headers) {
		this.headers.getHeaders().putAll(headers);
		return this;
	}

	/**
	 * putCookies
	 * 
	 * @param name  name
	 * @param value value
	 * @return QtHttpRequest
	 */
	public QtHttpRequest putCookie(String name, String value) {
		this.cookieStore.addCookie(new BasicClientCookie(name, value));
		return this;
	}

	/**
	 * putCookies
	 * 
	 * @param cookies cookies
	 * @return QtHttpRequest
	 */
	public QtHttpRequest putCookie(Map<String, String> cookies) {
		for (Map.Entry<String, String> entry : cookies.entrySet()) {
			this.cookieStore.addCookie(new BasicClientCookie(entry.getKey(), entry.getValue()));
		}
		return this;
	}

	/**
	 * 组合Cookie
	 * 
	 * @param cookies cookies
	 */
	public void putCookieStores(CookieStore cookies) {
		if (null != cookies) {
			cookies.getCookies().forEach(y -> {
				cookieStore.addCookie(y);
			});
		}
	}

	public void putCookieStores(String cookies) {
		if (null != cookies) {
			// BasicClientCookie cookie = new BasicClientCookie(name, value);
		}
	}

	// 超时
	private int getTimeout(int time) {
		return time == 0 ? timeout : time;
	}

	public int getSocketTimeout() {
		return getTimeout(socketTimeout);
	}

	public void setSocketTimeout(int socketTimeout) {
		this.socketTimeout = socketTimeout;
	}

	public int getConnectTimeout() {
		return getTimeout(connectTimeout);
	}

	public void setConnectTimeout(int connectTimeout) {
		this.connectTimeout = connectTimeout;
	}

	public int getConnectionRequestTimeout() {
		return getTimeout(connectionRequestTimeout);
	}

	public void setConnectionRequestTimeout(int connectionRequestTimeout) {
		this.connectionRequestTimeout = connectionRequestTimeout;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public int getTimeout() {
		return timeout;
	}

	public void setTimeout(int timeout) {
		this.timeout = timeout;
	}

	public int getKeepAlive() {
		return keepAlive;
	}

	public void setKeepAlive(int keepAlive) {
		this.keepAlive = keepAlive;
	}

	public boolean isRedirectsEnabled() {
		return redirectsEnabled;
	}

	public void setRedirectsEnabled(boolean redirectsEnabled) {
		this.redirectsEnabled = redirectsEnabled;
	}

	public QtHttpHeader getHeaders() {
		return headers;
	}

	public void setHeaders(QtHttpHeader headers) {
		this.headers = headers;
	}

	public String getCharset() {
		return charset;
	}

	public void setCharset(String charset) {
		this.charset = charset;
	}

	public ContentType getContentType() {
		return contentType;
	}

	public void setContentType(ContentType contentType) {
		this.contentType = contentType;
	}

	public List<NameValuePair> getFormData() {
		return formData;
	}

	public void setFormData(List<NameValuePair> formData) {
		this.formData = formData;
	}

	public String getPostData() {
		return postData;
	}

	public void setPostData(String postData) {
		this.postData = postData;
	}

	public Collection<? extends File> getPostFile() {
		return postFile;
	}

	public void setPostFile(Collection<? extends File> postFile) {
		this.postFile = postFile;
	}

	public QtHttpProxy getProxy() {
		return proxy;
	}

	public void setProxy(QtHttpProxy proxy) {
		this.proxy = proxy;
	}

	public CookieStore getCookieStore() {
		return cookieStore;
	}

	public void setCookieStore(CookieStore cookieStore) {
		this.cookieStore = cookieStore;
	}

	public ResultType getResultType() {
		return resultType;
	}

	public void setResultType(ResultType resultType) {
		this.resultType = resultType;
	}

}
