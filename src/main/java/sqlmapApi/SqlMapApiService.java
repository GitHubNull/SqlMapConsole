package sqlmapApi;

import burp.BurpExtender;
import utils.OSinfo;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import static utils.GlobalStaticVariables.*;

public class SqlMapApiService {
    Process sqlmapApiSubProcess;

    public SqlMapApiService() {
        sqlmapApiSubProcess = null;
    }

    public void start() throws IOException {
        if (null != sqlmapApiSubProcess && sqlmapApiSubProcess.isAlive()) {
            BurpExtender.stderr.println("SqlMapApiService.start(): null != sqlmapApiSubProcess && sqlmapApiSubProcess.isAlive()");
            return;
        }

        String[] cmdLine = new String[]{PYTHON_EXEC_PATH, "-u", SQLMAP_API_PATH, "-s", "-p", Integer.toString(SQLMAP_API_PORT)};
        if (OSinfo.isMacOS() || OSinfo.isLinux()) {
            cmdLine = new String[]{PYTHON_EXEC_PATH, "-u", SQLMAP_API_PATH, "-s", "-p", Integer.toString(SQLMAP_API_PORT)};
        }

        BurpExtender.debugInfo(String.format("SqlMapApiService.start()cmdLine: %s", String.join(" ", cmdLine)));

        ProcessBuilder processBuilder = new ProcessBuilder(cmdLine);
        sqlmapApiSubProcess = processBuilder.start();

    }

    public void stop() {
        if (null == sqlmapApiSubProcess) {
            return;
        }
        if (!sqlmapApiSubProcess.isAlive()) {
            return;
        }

        sqlmapApiSubProcess.destroy();
    }

    public BufferedReader getBufferedReader() {
        if (null == sqlmapApiSubProcess || !sqlmapApiSubProcess.isAlive()) {
            return null;
        }
        BufferedInputStream bufferedInputStream = new BufferedInputStream(sqlmapApiSubProcess.getInputStream());

        InputStreamReader inputStreamReader = new InputStreamReader(bufferedInputStream);


        return new BufferedReader(inputStreamReader);
    }

}
