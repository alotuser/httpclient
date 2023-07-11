package qt.httpclients;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.CodingErrorAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.apache.http.Consts;
import org.apache.http.Header;
import org.apache.http.HeaderElement;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.ParseException;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.CookieStore;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.config.ConnectionConfig;
import org.apache.http.config.MessageConstraints;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.config.SocketConfig;
import org.apache.http.conn.ConnectionKeepAliveStrategy;
import org.apache.http.conn.DnsResolver;
import org.apache.http.conn.HttpConnectionFactory;
import org.apache.http.conn.ManagedHttpClientConnection;
import org.apache.http.conn.routing.HttpRoute;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.conn.util.PublicSuffixMatcher;
import org.apache.http.conn.util.PublicSuffixMatcherLoader;
import org.apache.http.cookie.Cookie;
import org.apache.http.cookie.CookieAttributeHandler;
import org.apache.http.cookie.CookieOrigin;
import org.apache.http.cookie.CookieSpec;
import org.apache.http.cookie.CookieSpecProvider;
import org.apache.http.cookie.MalformedCookieException;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.impl.DefaultHttpResponseFactory;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultConnectionKeepAliveStrategy;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.DefaultHttpResponseParser;
import org.apache.http.impl.conn.DefaultHttpResponseParserFactory;
import org.apache.http.impl.conn.ManagedHttpClientConnectionFactory;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.impl.conn.SystemDefaultDnsResolver;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.impl.cookie.CookieSpecBase;
import org.apache.http.impl.cookie.DefaultCookieSpecProvider;
import org.apache.http.impl.cookie.RFC6265CookieSpecProvider;
import org.apache.http.impl.io.DefaultHttpRequestWriterFactory;
import org.apache.http.io.HttpMessageParser;
import org.apache.http.io.HttpMessageParserFactory;
import org.apache.http.io.HttpMessageWriterFactory;
import org.apache.http.io.SessionInputBuffer;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicHeaderElement;
import org.apache.http.message.BasicHeaderValueFormatter;
import org.apache.http.message.BasicLineParser;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.message.BufferedHeader;
import org.apache.http.message.LineParser;
import org.apache.http.protocol.HttpContext;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.Args;
import org.apache.http.util.CharArrayBuffer;
import org.apache.http.util.EntityUtils;

import qt.httpclients.ext.QtDefaultClient;
import qt.httpclients.ext.enums.ResultType;
import qt.httpclients.ext.strategy.QtLinkedRedirectStrategy;
import qt.httpclients.ext.strategy.QtDefaultRedirectStrategy;
import qt.httpclients.util.IOUtil;

/***
 * 简易HttpClient
 * 
 * @author ChileQi
 * @since 2017年8月4日 17:15:43
 */
public class QtHttpClient {

	public String defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36 QtHttpClient/1.1.0";
	public CookieStore defaultCookieStore = new BasicCookieStore();// Use custom cookie store if necessary.
	private PoolingHttpClientConnectionManager defaultConnManager;
	private ConnectionKeepAliveStrategy defaultKeepAliveStrategy;
	private CredentialsProvider defaultCredentialsProvider;
	private RequestConfig defaultRequestConfig;
	private QtHttpProxy defaultProxy;
	private String defaultCookieType="easy";
	private CloseableHttpClient httpclient;
	private QtHttpProxy qtProxy; 
	private boolean isRun = false;
	public boolean isIgnoeSSL=true;
	public int defaultMaxTotal = 1000;
	public int defaultMaxPerRoute = 10;
	public int maxPerRoute = 20;
	public int defaultSocketTimeout = 5000;
	public int defaultConnectTimeout = 5000;
	public int defaultConnectionRequestTimeout = 5000;
	public int defaultKeepAliveTimeout;

	private QtDefaultClient qtDefaultClient;
	
	public QtHttpClient() {
		httpclient=customHttpClient(null);
	}
	
	public QtHttpClient(QtDefaultClient defaultClient) {
		this.qtDefaultClient=defaultClient;
		httpclient=customHttpClient(null);
	}
	
	/**
	 * 初始化QtHttpClient
	 * @param qtProxy qtProxy
	 */
	public QtHttpClient(QtHttpProxy qtProxy) {
		this.qtProxy=qtProxy;
		HttpHost proxyHttpHost = null;
		if (null != qtProxy) {
			proxyHttpHost = (new HttpHost(qtProxy.getHostName(), qtProxy.getPort()));
		}
		httpclient=customHttpClient(proxyHttpHost);
		if (null != qtProxy) {
			addAuthProxy(qtProxy);
		}
	}
	
	public static QtHttpClient create() {
		return new QtHttpClient(QtDefaultClient.empty());
	}
	
	public QtHttpClient build() {
		HttpHost proxyHttpHost = null;
		if (null != qtProxy) {
			proxyHttpHost = (new HttpHost(qtProxy.getHostName(), qtProxy.getPort()));
		}
		httpclient=customHttpClient(proxyHttpHost);
		if (null != qtProxy) {
			addAuthProxy(qtProxy);
		}
		return this;
	}
	
	/**
	 * 自定义方法
	 * 
	 * @param proxyHttpHost 代理ip
	 */
	private CloseableHttpClient customHttpClient(final HttpHost defaultProxyHttpHost) {
		// Use custom message parser / writer to customize the way HTTP
		// messages are parsed from and written out to the data stream.
		HttpMessageParserFactory<HttpResponse> responseParserFactory = new DefaultHttpResponseParserFactory() {

			@Override
			public HttpMessageParser<HttpResponse> create(SessionInputBuffer buffer, MessageConstraints constraints) {
				LineParser lineParser = new BasicLineParser() {

					@Override
					public Header parseHeader(final CharArrayBuffer buffer) {
						try {
							return super.parseHeader(buffer);
						} catch (ParseException ex) {
							return new BasicHeader(buffer.toString(), null);
						}
					}

				};
				return new DefaultHttpResponseParser(buffer, lineParser, DefaultHttpResponseFactory.INSTANCE, constraints) {

					@Override
					protected boolean reject(final CharArrayBuffer line, int count) {
						// try to ignore all garbage preceding a status line infinitely
						return false;
					}

				};
			}

		};
		HttpMessageWriterFactory<HttpRequest> requestWriterFactory = new DefaultHttpRequestWriterFactory();

		// Use a custom connection factory to customize the process of
		// initialization of outgoing HTTP connections. Beside standard connection
		// configuration parameters HTTP connection factory can define message
		// parser / writer routines to be employed by individual connections.
		HttpConnectionFactory<HttpRoute, ManagedHttpClientConnection> connFactory = new ManagedHttpClientConnectionFactory(requestWriterFactory, responseParserFactory);

		// Client HTTP connection objects when fully initialized can be bound to
		// an arbitrary network socket. The process of network socket initialization,
		// its connection to a remote address and binding to a local one is controlled
		// by a connection socket factory.

		// SSL context for secure connections can be created either based on
		// system or application specific properties.
		SSLConnectionSocketFactory sslConnectionSocketFactorys;
		if(isIgnoeSSL) {
			try {
				//SSLContext sslcontext=SSLContextBuilder.create().loadTrustMaterial(null, new TrustAllStrategy()).build();
				sslConnectionSocketFactorys=new SSLConnectionSocketFactory(SSLContextBuilder.create().loadTrustMaterial(null, new TrustAllStrategy()).build(),NoopHostnameVerifier.INSTANCE);
			} catch (Exception e) {//注意：走默认方式
				sslConnectionSocketFactorys=new SSLConnectionSocketFactory(SSLContexts.createDefault());
			}
		}else {
			sslConnectionSocketFactorys=new SSLConnectionSocketFactory(SSLContexts.createDefault());
		}
		
		// Create a registry of custom connection socket factories for supported
		// protocol schemes.
		Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
																				 .register("http" , PlainConnectionSocketFactory.INSTANCE)
																				 .register("https", sslConnectionSocketFactorys)
																				 .build();
		//BrowserCompatSpec
		CookieSpecProvider easySpecProvider = new CookieSpecProvider() {
			public CookieSpec create(HttpContext httpcontext) {
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
			}};
		PublicSuffixMatcher publicSuffixMatcher = PublicSuffixMatcherLoader.getDefault();  
		// Create a registry of custom cookie for supported
		final Registry<CookieSpecProvider> defaultCookieSpecRegistry = RegistryBuilder.<CookieSpecProvider>create()
																		 .register(CookieSpecs.DEFAULT,(CookieSpecProvider) new DefaultCookieSpecProvider(publicSuffixMatcher))  
																		 .register(CookieSpecs.STANDARD,new RFC6265CookieSpecProvider(publicSuffixMatcher))  
																		 .register(defaultCookieType, easySpecProvider)  
																		 .build();  
		// Use custom DNS resolver to override the system DNS resolution.
		DnsResolver dnsResolver = new SystemDefaultDnsResolver() {
			@Override
			public InetAddress[] resolve(final String host) throws UnknownHostException {
				if (host.equalsIgnoreCase("myhost")) {
					return new InetAddress[] { InetAddress.getByAddress(new byte[] { 127, 0, 0, 1 }) };
				} else {
					return super.resolve(host);
				}
			}
		};

		// Create a connection manager with custom configuration.
		defaultConnManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry, connFactory, dnsResolver);
		// Create socket configuration
		SocketConfig socketConfig = SocketConfig.custom().setTcpNoDelay(true).setSoKeepAlive(true).setSoTimeout(defaultSocketTimeout).build();
		// Configure the connection manager to use socket configuration either
		// by default or for a specific host.
		defaultConnManager.setDefaultSocketConfig(socketConfig);
		defaultConnManager.setSocketConfig(new HttpHost("somehost", 80), socketConfig);// $$$
		// Validate connections after 1 sec of inactivity
		defaultConnManager.setValidateAfterInactivity(1000);
		// Create message constraints
		MessageConstraints messageConstraints = MessageConstraints.custom().setMaxHeaderCount(200).setMaxLineLength(2000).build();
		// Create connection configuration
		ConnectionConfig connectionConfig = ConnectionConfig.custom().setMalformedInputAction(CodingErrorAction.IGNORE).setUnmappableInputAction(CodingErrorAction.IGNORE).setCharset(Consts.UTF_8).setMessageConstraints(messageConstraints).build();
		// Configure the connection manager to use connection configuration either
		// by default or for a specific host.
		defaultConnManager.setDefaultConnectionConfig(connectionConfig);
		defaultConnManager.setConnectionConfig(new HttpHost("somehost", 80), ConnectionConfig.DEFAULT);// $$$
		// Configure total max or per route limits for persistent connections
		// that can be kept in the pool or leased by the connection manager.
		defaultConnManager.setMaxTotal(defaultMaxTotal);
		defaultConnManager.setDefaultMaxPerRoute(defaultMaxPerRoute);
		defaultConnManager.setMaxPerRoute(new HttpRoute(new HttpHost("somehost", 80)), maxPerRoute);// $$$
		// Use custom credentials provider if necessary.
		defaultCredentialsProvider = new BasicCredentialsProvider();

		// Create global request configuration
		defaultRequestConfig = RequestConfig.custom()
				.setCookieSpec(CookieSpecs.DEFAULT)
				.setExpectContinueEnabled(false)//ExpectContinueEnabled=false?解决 org.apache.http.NoHttpResponseException failed to respond问题
				.setTargetPreferredAuthSchemes(Arrays.asList(AuthSchemes.NTLM, AuthSchemes.DIGEST))
				.setProxyPreferredAuthSchemes(Arrays.asList(AuthSchemes.BASIC))
				.build();

		defaultKeepAliveStrategy = new DefaultConnectionKeepAliveStrategy() {
			@Override
			public long getKeepAliveDuration(HttpResponse response, HttpContext context) {
				long keepAlive = super.getKeepAliveDuration(response, context);
				// HttpHost target = (HttpHost) context.getAttribute(HttpClientContext.HTTP_TARGET_HOST);
				// target.getHostName()
				if (keepAlive == -1||defaultKeepAliveTimeout>0) {
					// 如果服务器没有设置keep-alive这个参数，我们就把它设置成1分钟
					keepAlive = defaultKeepAliveTimeout;
				}
				
				return keepAlive;
			}

		};
	
		
		//Lookup<CookieSpecProvider> cookieSpecRegistry=new Lookup<CookieSpecProvider>() {public CookieSpecProvider lookup(String s) {System.out.println(s);return null;}};
		//Create an HttpClient with the given custom dependencies and configuration.
		HttpClientBuilder defaultHttpClientBuilder=HttpClients.custom()
				.setConnectionManager(defaultConnManager)
				.setDefaultRequestConfig(defaultRequestConfig)
				.setDefaultCookieSpecRegistry(defaultCookieSpecRegistry)
				.setDefaultCookieStore(defaultCookieStore)
				.setDefaultCredentialsProvider(defaultCredentialsProvider)
				.setKeepAliveStrategy(defaultKeepAliveStrategy)
				.setUserAgent(defaultUserAgent)
				.setProxy(defaultProxyHttpHost);
		
		if(null!=qtDefaultClient&&qtDefaultClient.referers!=null) {
			switch (qtDefaultClient.referers) {
			case DEFAULT:
				defaultHttpClientBuilder.setRedirectStrategy(new QtDefaultRedirectStrategy());
				break;
			case LINKED:
			default:
				defaultHttpClientBuilder.setRedirectStrategy(new QtLinkedRedirectStrategy());
				break;
			}
		}
		return defaultHttpClientBuilder.build();
	}

	/**
	 * GET(Main)
	 * 
	 * @param request request
	 * @return QtHttpResult
	 * @throws ClientProtocolException ClientProtocolException
	 * @throws IOException IOException
	 */
	public QtHttpResult get(QtHttpRequest request) throws ClientProtocolException, IOException {
		
		QtHttpResult qhr = new QtHttpResult();
		defaultKeepAliveTimeout = request.keepAlive;
		String url = request.url;
		HttpHost otherProxyHttpHost = null;
		if (null != request.proxy) {
			otherProxyHttpHost = new HttpHost(request.proxy.getHostName(), request.proxy.getPort());
		}

		try {
			HttpGet httpget = new HttpGet(url);
			// Request configuration can be overridden at the request level.
			// They will take precedence over the one set at the client level.
			RequestConfig requestConfig = RequestConfig.copy(defaultRequestConfig)
					.setSocketTimeout(request.getSocketTimeout())
					.setConnectTimeout(request.getConnectTimeout())
					.setConnectionRequestTimeout(request.getConnectionRequestTimeout())
					.setProxy(otherProxyHttpHost)
					.setRedirectsEnabled(request.redirectsEnabled)
					.setCookieSpec(defaultCookieType).build();
			httpget.setConfig(requestConfig);
			request.headers.getHeaders().forEach((key, value) -> {
				httpget.addHeader(key, value);
			});
			// Execution context can be customized locally.
			HttpClientContext context = HttpClientContext.create();
			// Contextual attributes set the local context level will take
			// precedence over those set at the client level.
			if (null != request.cookieStore && !request.cookieStore.getCookies().isEmpty()) {
				context.setCookieStore(request.cookieStore);
			}
			context.setCredentialsProvider(defaultCredentialsProvider);
			
			CloseableHttpResponse response = httpclient.execute(httpget, context);
			try {
				qhr = getHttpResult(request,context, response);
				httpget.abort();
			} finally {
				response.close();
			}
		} finally {
			closeHttpClient();
		}
		return qhr;
	}

	/**
	 * GET
	 * 
	 * @param url url
	 * @param proxyIP proxyIP
	 * @param proxyPort proxyPort
	 * @return QtHttpResult
	 * @throws ClientProtocolException ClientProtocolException
	 * @throws IOException IOException
	 */
	public QtHttpResult get(String url, String proxyIP, int proxyPort) throws ClientProtocolException, IOException {

		QtHttpRequest request = new QtHttpRequest(url) {
			{
				proxy = new QtHttpProxy(proxyIP, proxyPort);
			}
		};

		
		return get(request);

	}

	/**
	 * GET
	 * 
	 * @param url url
	 * @return QtHttpResult
	 * @throws ClientProtocolException ClientProtocolException
	 * @throws IOException  IOException
	 */
	public QtHttpResult get(String url) throws ClientProtocolException, IOException {

		QtHttpRequest request = new QtHttpRequest(url) {
			{
				if (null != defaultProxy) {
					proxy = new QtHttpProxy(defaultProxy.getHostName(), defaultProxy.getPort());
				}
			}
		};
		return get(request);

	}

	/**
	 * POST(main)
	 * 
	 * @param request request
	 * @return QtHttpResult
	 * @throws ClientProtocolException ClientProtocolException
	 * @throws IOException IOException
	 */
	public QtHttpResult post(QtHttpRequest request) throws ClientProtocolException, IOException {
		defaultKeepAliveTimeout = request.keepAlive;
		String url = request.url;
		ContentType contentType = request.contentType;
		List<NameValuePair> nvps = request.formData;
		HttpHost otherProxyHttpHost = null;
		if (null != request.proxy) {
			otherProxyHttpHost = new HttpHost(request.proxy.getHostName(), request.proxy.getPort());
		}
		QtHttpResult qhr = new QtHttpResult();
		try {
			// List <NameValuePair> nvps = new ArrayList <NameValuePair>();
			// nvps.add(new BasicNameValuePair("username", "vip"));
			// nvps.add(new BasicNameValuePair("password", "secret"));

			// Request configuration can be overridden at the request level.
			// They will take precedence over the one set at the client level.
			RequestConfig requestConfig = RequestConfig.copy(defaultRequestConfig)
					.setSocketTimeout(request.getSocketTimeout())
					.setConnectTimeout(request.getConnectTimeout())
					.setConnectionRequestTimeout(request.getConnectionRequestTimeout())
					.setProxy(otherProxyHttpHost)
					.setRedirectsEnabled(request.redirectsEnabled)
					.setCookieSpec(defaultCookieType)
					.build();
			HttpPost httppost = new HttpPost(url);
			httppost.setConfig(requestConfig);
			// Header
			if (null != request.headers) {
				request.headers.getHeaders().forEach((key, value) -> {
					httppost.addHeader(key, value);
				});
			}
			
			//
			if (null != request.postFile&&!request.postFile.isEmpty()) {
				/*InputStreamEntity reqEntity = new InputStreamEntity(new FileInputStream(request.postFile), -1, ContentType.APPLICATION_OCTET_STREAM);
				reqEntity.setChunked(true);
				// It may be more appropriate to use FileEntity class in this particular
				// instance but we are using a more generic InputStreamEntity to demonstrate
				// the capability to stream out data from any arbitrary source
				//
				// FileEntity entity = new FileEntity(file, "binary/octet-stream");
				// FileEntity entity = new FileEntity(request.postFile, contentType.APPLICATION_OCTET_STREAM);
				httppost.setEntity(reqEntity);*/
				// Post files
				MultipartEntityBuilder multipartEntityBuilder=MultipartEntityBuilder.create();
				request.postFile.forEach(file->{multipartEntityBuilder.addBinaryBody(file.getName(), file);});
				if(null != nvps && !nvps.isEmpty()){
					nvps.forEach(nvp->{multipartEntityBuilder.addPart(nvp.getName(), new StringBody(nvp.getValue(), contentType));});
				}
				HttpEntity reqEntity = multipartEntityBuilder.build();
				httppost.setEntity(reqEntity);
			}else{
				// Post form
				if (null != nvps && !nvps.isEmpty()) {
					httppost.setEntity(new UrlEncodedFormEntity(nvps, request.charset));
				}
				// Post text,json,xml...
				if (null != request.postData && !request.postData.isEmpty()) {
					StringEntity reqEntity = new StringEntity(request.postData, contentType);
					httppost.setEntity(reqEntity);
				}
			}
			// Execution context can be customized locally.
			HttpClientContext context = HttpClientContext.create();
			// Contextual attributes set the local context level will take
			// precedence over those set at the client level.
			if (null != request.cookieStore && !request.cookieStore.getCookies().isEmpty()) {
				context.setCookieStore(request.cookieStore);
			}
			context.setCredentialsProvider(defaultCredentialsProvider);

			CloseableHttpResponse response = httpclient.execute(httppost);
			try {
				qhr = getHttpResult(request,context, response);
				httppost.abort();
			} finally {
				response.close();
			}
		} finally {
			closeHttpClient();
		}
		return qhr;
	}


	/**
	 * POST提交参数
	 * @param url url
	 * @param nameValues nameValues
	 * @return QtHttpResult
	 * @throws ClientProtocolException ClientProtocolException
	 * @throws IOException IOException
	 */
	public QtHttpResult post(String url,Map<String,String> nameValues) throws ClientProtocolException, IOException {
		
		QtHttpRequest request = new QtHttpRequest(url) {
			{
				timeout=200000;
				if (null != defaultProxy) {
					proxy = new QtHttpProxy(defaultProxy.getHostName(), defaultProxy.getPort());
				}
			}
		};
		if(null!=nameValues) {
			nameValues.forEach((name,value)->{
				request.formData.add(new BasicNameValuePair(name, value));
			});
		}
		return post(request);
	}
	
	/**
	 * POST提交参数
	 * @param url url
	 * @param bodyStr bodyStr
	 * @return QtHttpResult
	 * @throws ClientProtocolException ClientProtocolException
	 * @throws IOException IOException
	 */
	public QtHttpResult post(String url,String bodyStr) throws ClientProtocolException, IOException {
		
		QtHttpRequest request = new QtHttpRequest(url) {
			{
				timeout=200000;
				postData=bodyStr;
				if (null != defaultProxy) {
					proxy = new QtHttpProxy(defaultProxy.getHostName(), defaultProxy.getPort());
				}
			}
		};
		
		return post(request);
	}

	/**
	 * 根据文件路径提交
	 * @param url url
	 * @param filePaths filePaths
	 * @throws ClientProtocolException ClientProtocolException
	 * @throws IOException IOException
	 * @return QtHttpResult
	 */
	public QtHttpResult post(String url, String... filePaths) throws ClientProtocolException, IOException {
		return post(url,null,filePaths);
	}
	/**
	 * 根据文件路径和参数提交
	 * @param url url
	 * @param nameValues nameValues
	 * @param filePaths filePaths
	 * @return QtHttpResult
	 * @throws ClientProtocolException ClientProtocolException
	 * @throws IOException IOException
	 */
	public QtHttpResult post(String url,Map<String,String> nameValues,String... filePaths) throws ClientProtocolException, IOException {
		List<File> files =new ArrayList<File>();
		for (String filePath : filePaths) {
			files.add(new File(filePath));
		}
		return post(url,nameValues,files);
	}

	/**
	 * 根据文件路径和参数提交
	 * @param url url
	 * @param nameValues nameValues
	 * @param files files
	 * @return QtHttpResult
	 * @throws ClientProtocolException ClientProtocolException
	 * @throws IOException IOException
	 */
	public QtHttpResult post(String url,Map<String,String> nameValues,Collection<? extends File> files) throws ClientProtocolException, IOException {
		
		QtHttpRequest request = new QtHttpRequest(url) {
			{
				postFile =files;
				timeout=200000;
				if (null != defaultProxy) {
					proxy = new QtHttpProxy(defaultProxy.getHostName(), defaultProxy.getPort());
				}
			}
		};
		
		if(nameValues!=null)
			nameValues.forEach((name,value)->{request.formData.add(new BasicNameValuePair(name, value));});
		
		return post(request);
	}

	/**
	 * 根据文件路径和参数提交
	 * @param url url
	 * @param nameValues nameValues
	 * @param files files
	 * @return QtHttpResult
	 * @throws ClientProtocolException ClientProtocolException
	 * @throws IOException IOException
	 */
	public QtHttpResult post(String url,Map<String,String> nameValues,File... files) throws ClientProtocolException, IOException {
		return post(url,nameValues,files);
	}

	/**
	 * 只执行一次(注)
	 * 
	 * @param callBack callBack
	 * @throws IOException IOException
	 */
	public void runs(QtHttpCallBack callBack) throws IOException {
		try {
			isRun = true;
			callBack.completed(this);
		} finally {
			httpclient.close();
		}
	}

	
	public QtHttpProxy setAuthProxy(String hostName, int port) {
		defaultProxy = new QtHttpProxy(hostName, port);
		return addAuthProxy(defaultProxy);
	}
	
	/**
	 * 设置默认代理
	 * 
	 * @param hostName hostName
	 * @param port   port
	 * @param userName userName
	 * @param password password
	 * @return QtHttpProxy
	 */
	public QtHttpProxy setAuthProxy(String hostName, int port, String userName, String password) {
		defaultProxy = new QtHttpProxy(hostName, port, userName, password);
		return addAuthProxy(defaultProxy);
	}

	/**
	 * 设置代理（可以多个）
	 * 
	 * @param hostName host地址
	 * @param port 端口号
	 * @param userName 账号名称
	 * @param password 账号密码
	 * @return QtHttpProxy
	 */
	public QtHttpProxy addAuthProxy(String hostName, int port, String userName, String password) {
		QtHttpProxy qtProxy = new QtHttpProxy(hostName, port, userName, password);
		return addAuthProxy(qtProxy);
	}

	/**
	 * 设置代理（可以多个）
	 * @param qtProxy 代理
	 * @return QtHttpProxy
	 */
	public QtHttpProxy addAuthProxy(QtHttpProxy qtProxy) {
		if(null!=qtProxy.getUserName()&&qtProxy.getUserName().length()>0) {
			defaultCredentialsProvider.setCredentials(new AuthScope(qtProxy.getHostName(), qtProxy.getPort()), new UsernamePasswordCredentials(qtProxy.getUserName(), qtProxy.getPassword()));
		}
		return qtProxy;
	}

	/**
	 * 获取结果
	 * @param request request
	 * @param context context
	 * @param response response
	 * @throws ParseException ParseException
	 * @throws IOException IOException
	 * @return QtHttpResult
	 */
	private QtHttpResult getHttpResult(QtHttpRequest request,HttpClientContext context, CloseableHttpResponse response) throws ParseException, IOException {
		// Once the request has been executed the local context can
		// be used to examine updated state and various objects affected
		// by the request execution.
		// // Last executed request
		// HttpRequest lastReq= context.getRequest();
		// // Execution route
		// context.getHttpRoute();
		// // Target auth state
		// context.getTargetAuthState();
		// // Proxy auth state
		// context.getTargetAuthState();
		// // Cookie origin
		// context.getCookieOrigin();
		// // Cookie spec used
		// context.getCookieSpec();
		// // User security token
		// context.getUserToken();
		QtHttpResult qhr = new QtHttpResult();
		HttpEntity entity =response.getEntity();
		qhr.setStatusCode(response.getStatusLine().getStatusCode());
		qhr.setHeader(response.getAllHeaders());
		qhr.setCookieStore(context.getCookieStore());
		if(request.getResultType()==ResultType.Byte) {
			qhr.setResultByte(IOUtil.toByteArray(entity.getContent()));
		}else {
			qhr.setHtml(EntityUtils.toString(entity,request.charset));
		}
		if(response.getAllHeaders().length>0){
			List<Header> headers= Arrays.asList(response.getAllHeaders());
			Header locaHeader=headers.stream().filter(x->"Location".equalsIgnoreCase(x.getName())).findFirst().orElse(null);
			if(locaHeader!=null){
				qhr.redirectUrl=locaHeader.getValue();
			}
		}
		qhr.redirectLocations=context.getRedirectLocations();
		
		EntityUtils.consume(entity);
		return qhr;
	}

	/**
	 * 关闭httpclient客户端
	 * 
	 * @throws IOException IOException
	 */
	private void closeHttpClient() throws IOException {
		if (!isRun) {
			httpclient.close();
		}
	}

	
}
