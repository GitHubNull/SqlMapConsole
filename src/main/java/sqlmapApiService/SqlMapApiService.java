package sqlmapApiService;

import java.io.*;

public class SqlMapApiService {
    Process sqlmapApiSubProcess;


    String pythonExeFilePath;
    String sqlmapApiFilePath;
    int port;

    public SqlMapApiService(String pythonExeFilePath, String sqlmapApiFilePath, int port) {
        this.pythonExeFilePath = pythonExeFilePath;
        this.sqlmapApiFilePath = sqlmapApiFilePath;
        this.port = port;
        sqlmapApiSubProcess = null;
    }

    public void start() throws IOException {
        if (null != sqlmapApiSubProcess && sqlmapApiSubProcess.isAlive()) {
            return;
        }
        ProcessBuilder processBuilder = new ProcessBuilder(pythonExeFilePath, "-u", sqlmapApiFilePath, "-s", "-p", Integer.toString(port));
//        processBuilder.redirect
        sqlmapApiSubProcess = processBuilder.start();

    }

    public void stop() {
        if (null == sqlmapApiSubProcess) {
            return;
        }
        if (null != sqlmapApiSubProcess && !sqlmapApiSubProcess.isAlive()) {
            return;
        }

        sqlmapApiSubProcess.destroy();
    }

    public BufferedInputStream getBufferedInputStream() {
        if (null == sqlmapApiSubProcess || !sqlmapApiSubProcess.isAlive()) {
            return null;
        }
        return new BufferedInputStream(sqlmapApiSubProcess.getInputStream());
    }

    public BufferedReader getBufferedReader() {
        if (null == sqlmapApiSubProcess || !sqlmapApiSubProcess.isAlive()) {
            return null;
        }
        BufferedInputStream bufferedInputStream = new BufferedInputStream(sqlmapApiSubProcess.getInputStream());
        if (null == bufferedInputStream) {
            return null;
        }

        InputStreamReader inputStreamReader = new InputStreamReader(bufferedInputStream);
        if (null == inputStreamReader) {
            return null;
        }


        return new BufferedReader(inputStreamReader);
    }

    public OutputStream getOutputStream() {
        return sqlmapApiSubProcess.getOutputStream();
    }

    public InputStream getErrorStream() {
        return sqlmapApiSubProcess.getErrorStream();
    }

    public InputStream getInputStream() {
        return sqlmapApiSubProcess.getInputStream();
    }
}
