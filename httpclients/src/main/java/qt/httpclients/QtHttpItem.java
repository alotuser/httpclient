package qt.httpclients;

/***
 * 简易HTTpClient
 * 
 * @author ChileQi
 * @since 2017年8月4日 17:15:43
 */
public class QtHttpItem extends QtHttpRequest {

	public QtMethod mehtod;// 请求方式默认为GET方式

	public QtHttpItem(String url) {
		super(url);
		mehtod = QtMethod.GET;
	}

	public enum QtMethod {
		GET, POST
	}

}
