package utils;

import burp.BurpExtender;
import org.apache.commons.lang.StringUtils;

import javax.swing.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static utils.GlobalStaticsVar.OLD_SQLMAPAPI_SUB_PROCESS_KILLED;

public class MacOSKiller {
    int port;

    public MacOSKiller(int port) {
        this.port = port;
    }

    private List<String> getSubProcessLines() {
        List<String> subProcessLines = new ArrayList<>();
        String cmdLine = "cmd /C netstat -ano | findstr /B /I /R /C:\".*" + port + ".*LISTENING.*/d{1,5}$\"";
        try {
            Process p = Runtime.getRuntime().exec(cmdLine);
            InputStream input = p.getInputStream();
            InputStreamReader ins = new InputStreamReader(input, "GBK");
            //InputStreamReader 字节流到字符流，并指定编码格式
            BufferedReader br = new BufferedReader(ins);
            //BufferedReader 从字符流读取文件并缓存字符
            String line;
            while ((line = br.readLine()) != null) {
                subProcessLines.add(line);
            }
            br.close();
            ins.close();
            input.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return subProcessLines;
    }

    private Set<Integer> findProcessIds(List<String> subProcessLines) {
        Set<Integer> subProcessIds = new HashSet<>();
        for (String subProcessLine : subProcessLines) {
            int offset = subProcessLine.lastIndexOf(" ");
            String spid = subProcessLine.substring(offset);
            spid = spid.replaceAll(" ", "");

            if (!StringUtils.isNumeric(spid)) {
                continue;
            }

            int pid = -1;
            try {
                pid = Integer.parseInt(spid);
            } catch (NumberFormatException e) {
                BurpExtender.stderr.println(e.getMessage());
            }
            subProcessIds.add(pid);

        }

        return subProcessIds;
    }

    private boolean killWithPid(Set<Integer> subProcessIds) {
        for (Integer subProcessId : subProcessIds) {
            String cmdLine = "cmd /c taskkill /F /pid " + subProcessId;
            try {
                Process process = Runtime.getRuntime().exec(cmdLine);
            } catch (IOException e) {
                e.printStackTrace();
                return false;
            }
        }
        return true;
    }

    public void kill() {
        SwingUtilities.invokeLater(() -> {
            List<String> subProcessLines = getSubProcessLines();
            if (null == subProcessLines || 0 > subProcessLines.size()) {
                return;
            }

            Set<Integer> subProcessIds = findProcessIds(subProcessLines);
            if (null == subProcessIds || 0 >= subProcessIds.size()) {
                return;
            }

            if (killWithPid(subProcessIds)) {
                OLD_SQLMAPAPI_SUB_PROCESS_KILLED = true;
            }
        });
    }
}
