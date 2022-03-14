package qt.httpclients.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;


public class FileUtil {

	public static File writeBytes(byte[] data, String path) throws IOException {
		return writeBytes(data, touch(path));
	}

	public static File writeBytes(byte[] data, File dest) throws IOException {
		writeByteArrayToFile(dest, data, 0, data.length, false);
		return dest;
	}

	public static void writeByteArrayToFile(final File file, final byte[] data) throws IOException {
		writeByteArrayToFile(file, data, false);
	}

	public static void writeByteArrayToFile(final File file, final byte[] data, final boolean append)
			throws IOException {
		writeByteArrayToFile(file, data, 0, data.length, append);
	}

	public static void writeByteArrayToFile(final File file, final byte[] data, final int off, final int len,
			final boolean append) throws IOException {
		try (OutputStream out = openOutputStream(file, append)) {
			out.write(data, off, len);
		}
	}

	public static FileOutputStream openOutputStream(final File file, final boolean append) throws IOException {
		if (file.exists()) {
			if (file.isDirectory()) {
				throw new IOException("File '" + file + "' exists but is a directory");
			}
			if (file.canWrite() == false) {
				throw new IOException("File '" + file + "' cannot be written to");
			}
		} else {
			final File parent = file.getParentFile();
			if (parent != null) {
				if (!parent.mkdirs() && !parent.isDirectory()) {
					throw new IOException("Directory '" + parent + "' could not be created");
				}
			}
		}
		return new FileOutputStream(file, append);
	}

	public static File touch(String fullFilePath) throws IOException {
		if (fullFilePath == null) {
			return null;
		}
		return (file(fullFilePath));
	}

	public static File file(String path) {
		if (null == path) {
			return null;
		}
		return new File((path));
	}
}
