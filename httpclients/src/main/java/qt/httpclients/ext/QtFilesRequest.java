package qt.httpclients.ext;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.http.message.BasicNameValuePair;

import qt.httpclients.QtHttpRequest;

/**
 * 文件上传
 * 
 * @author I6view
 *
 */
public class QtFilesRequest extends QtHttpRequest {

	private Map<String, String> datas = new HashMap<String, String>();

	private List<File> files = new ArrayList<File>();

	public QtFilesRequest(String url) {
		super(url);
	}

	public QtFilesRequest(String url, Map<String, String> datas, File... files) {
		super(url);
		putData(datas).putFile(files);
	}

	public QtFilesRequest(String url, Map<String, String> datas, String... filePaths) {
		super(url);
		putData(datas).putFile(filePaths);
	}

	public QtFilesRequest putData(Map<String, String> datas) {
		this.datas.putAll(datas);
		return this;
	}

	public QtFilesRequest putFile(File... files) {
		return putFile(files);
	}

	public QtFilesRequest putFile(Collection<? extends File> files) {
		this.files.addAll(files);
		return this;
	}

	public QtFilesRequest putFile(String... filePaths) {
		for (String filePath : filePaths) {
			this.files.add(new File(filePath));
		}
		return this;
	}

	public QtFilesRequest create() {

		super.postFile = files;
		this.datas.forEach((name, value) -> {
			this.formData.add(new BasicNameValuePair(name, value));
		});
		return this;
	}

	public Map<String, String> getDatas() {
		return datas;
	}

	public void setDatas(Map<String, String> datas) {
		this.datas = datas;
	}

	public List<File> getFiles() {
		return files;
	}

	public void setFiles(List<File> files) {
		this.files = files;
	}

}
