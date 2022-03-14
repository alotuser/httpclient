package qt.httpclients.ext.strategy;

import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.ProtocolException;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.DefaultRedirectStrategy;
import org.apache.http.protocol.HttpContext;

import qt.httpclients.ext.QtStr;

public class QtLinkedRedirectStrategy extends DefaultRedirectStrategy {

	@Override
	public HttpUriRequest getRedirect(HttpRequest request, HttpResponse response, HttpContext context) throws ProtocolException {

		HttpUriRequest redirect = super.getRedirect(request, response, context);
		if (!redirect.headerIterator().hasNext()) {
			redirect.setHeaders(request.getAllHeaders());
		}
		if (request.containsHeader(QtStr.REFERER))
			redirect.removeHeaders(QtStr.REFERER);
		redirect.addHeader(QtStr.REFERER, request.getRequestLine().getUri());
		return redirect;
	}

}
