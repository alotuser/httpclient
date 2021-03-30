# httpclient
简易httpclient
# 使用方法

    String testUri = "http://666.33.33.666/getIp.ashx";
		String proxyIP = "";//666.33.33.666
		int port = 10000;
		String proxyUsername = "";
		String proxyPassword = "";

		// 普通Get请求
		try {
			QtHttpClient qt = new QtHttpClient();
			QtHttpResult qhr = qt.get("http://www.xxx.com");
			qhr.getCookieStore().getCookies().forEach(x -> {
				System.out.println("cks:" + x.getName() + "\t" + x.getValue());
			});
			System.out.println("<0>:" + qhr.html);
		} catch (Exception e1) {
			e1.printStackTrace();
		}
		// 代理Get请求
		try {
			QtHttpClient qt = new QtHttpClient();
			qt.setAuthProxy(proxyIP, port, proxyUsername, proxyPassword);// 设置默认代理
			QtHttpResult qhr = qt.get(testUri);
			System.out.println("<1>:" + qhr.html);
		} catch (Exception e1) {
			e1.printStackTrace();
		}
		// 多个共用一个代理ip请求
		try {
			QtHttpClient qt = new QtHttpClient();
			qt.addAuthProxy(proxyIP, port, proxyUsername, proxyPassword);// 新增代理
			qt.runs(new QtHttpCallBack() {
				@Override
				public void completed(QtHttpClient qhc) {
					try {
						// <<请求1>>
						QtHttpResult qhr1 = qhc.get(testUri, proxyIP, port);
						System.out.println("<2.1>:" + qhr1.html);
						qhr1.getCookieStore().getCookies().forEach(x -> {
							System.out.println("cks:" + x.getName() + "\t" + x.getValue());
						});
						// <<请求2>>
						QtHttpResult qhr2 = qhc.get(testUri, proxyIP, port);
						System.out.println("<2.2>:" + qhr2.html);
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			});

		} catch (Exception e) {
			e.printStackTrace();
		}
		// 普通POST文件请求
		try {
			Map<String, String> nvs = new HashMap<String, String>();
			nvs.put("xx", "xxxxxxx");
			QtHttpClient qt = new QtHttpClient();
			// QtHttpResult qhr =
			// qt.post("http://localhost:8080/OPS/ImportShopAircomConfig.htm",
			// nvs,"D:\\shopAircomConfig.xls");
			// System.out.println("<3>:" + qhr.html);
		} catch (Exception e1) {
			e1.printStackTrace();
		}
