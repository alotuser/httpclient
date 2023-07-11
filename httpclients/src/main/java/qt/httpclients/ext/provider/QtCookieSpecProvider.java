package qt.httpclients.ext.provider;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.apache.http.Header;
import org.apache.http.HeaderElement;
import org.apache.http.NameValuePair;
import org.apache.http.cookie.Cookie;
import org.apache.http.cookie.CookieAttributeHandler;
import org.apache.http.cookie.CookieOrigin;
import org.apache.http.cookie.CookieSpec;
import org.apache.http.cookie.CookieSpecProvider;
import org.apache.http.cookie.MalformedCookieException;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.impl.cookie.CookieSpecBase;
import org.apache.http.message.BasicHeaderElement;
import org.apache.http.message.BasicHeaderValueFormatter;
import org.apache.http.message.BufferedHeader;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.Args;
import org.apache.http.util.CharArrayBuffer;

public class QtCookieSpecProvider implements CookieSpecProvider{

	@Override
	public CookieSpec create(HttpContext context) {

		return new CookieSpecBase() {
			
			public List<Cookie> parse(Header header, CookieOrigin origin) throws MalformedCookieException {
				final HeaderElement[] elems=header.getElements();
				final List<Cookie> cookies = new ArrayList<Cookie>(elems.length);
                for (final HeaderElement headerelement : elems) {
                    final String name = headerelement.getName();
                    final String value = headerelement.getValue();
                    if (value == null) {
                        continue;
                    }
                    if (name == null || name.length() == 0) {
                        throw new MalformedCookieException("Cookie name may not be empty");
                    }

                    final BasicClientCookie cookie = new BasicClientCookie(name, value);
                    cookie.setPath(getDefaultPath(origin));
                    cookie.setDomain(getDefaultDomain(origin));

                    // cycle through the parameters
                    final NameValuePair[] attribs = headerelement.getParameters();
                    for (int j = attribs.length - 1; j >= 0; j--) {
                        final NameValuePair attrib = attribs[j];
                        final String s = attrib.getName().toLowerCase(Locale.ENGLISH);

                        cookie.setAttribute(s, attrib.getValue());

                        final CookieAttributeHandler handler = findAttribHandler(s);
                        if (handler != null) {
                            handler.parse(cookie, attrib.getValue());
                        }
                    }
                    cookies.add(cookie);
                }
                return cookies;
			
			}

			private boolean isQuoteEnclosed(String s) {
				return s != null && s.startsWith("\"") && s.endsWith("\"");
			}

			public List<Header> formatCookies(List<Cookie> cookies) {
				Args.notEmpty(cookies, "List of cookies");
				CharArrayBuffer buffer = new CharArrayBuffer(20 * cookies.size());
				buffer.append("Cookie");
				buffer.append(": ");
				for (int i = 0; i < cookies.size(); i++) {
					Cookie cookie = (Cookie) cookies.get(i);
					if (i > 0)
						buffer.append("; ");
					String cookieName = cookie.getName();
					String cookieValue = cookie.getValue();
					if (cookie.getVersion() > 0 && !isQuoteEnclosed(cookieValue)) {
						BasicHeaderValueFormatter.INSTANCE.formatHeaderElement(buffer, new BasicHeaderElement(cookieName, cookieValue), false);
						continue;
					}
					buffer.append(cookieName);
					buffer.append("=");
					if (cookieValue != null)
						buffer.append(cookieValue);
				}

				List<Header> headers = new ArrayList<Header>(1);
				headers.add(new BufferedHeader(buffer));
				return headers;
			}

			public int getVersion() {
				return 0;
			}

			public Header getVersionHeader() {
				return null;
			}

			public String toString() {
				return "compatibility";
			}
			
			
		}; 
	
	}

}
