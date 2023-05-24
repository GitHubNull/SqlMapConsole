package sqlmapApi;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import com.alibaba.fastjson2.JSON;
import entities.TaskId2TaskIndexMap;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;
import sqlmapApi.requestsBody.ScanOptions;
import sqlmapApi.responsesBody.TaskNewResponse;
import utils.ScanOptionsHelper;
import utils.TmpRequestFileHelper;

import javax.swing.*;
import java.io.IOException;

import static utils.GlobalStaticsVar.TASK_ID_INDEX_MAP_QUEUE;

public class SqlMapApiClient {
    SqlMapApiImpl sqlMapApi;

    public SqlMapApiClient(SqlMapApiImpl sqlMapApi) {
        this.sqlMapApi = sqlMapApi;
    }

    public Call genScanTaskId() {
        return sqlMapApi.taskNew();
    }

    public Call addScanTask(String taskId, ScanOptions scanOptions) {
        if ((null == taskId || taskId.trim().isEmpty()) || (null == scanOptions)) {
            return null;
        }

        return sqlMapApi.scanStart(taskId, scanOptions);
    }

    public synchronized void startScanTask(String taskName, String commandLineStr, IHttpRequestResponse httpRequestResponse) throws IOException {
        final String finalCommandLineStr = commandLineStr;

        SwingUtilities.invokeLater(() -> {

            SqlMapApiClient sqlMapApiClient = BurpExtender.getSqlMapApiClient();

            Call call = sqlMapApiClient.genScanTaskId();
            if (null == call) {
                return;
            }

            call.enqueue(new Callback() {
                @Override
                public void onFailure(@NotNull Call call, @NotNull IOException e) {
                    BurpExtender.stderr.println(e.getMessage());
                }

                @Override
                public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
                    assert response.body() != null;
                    sqlmapApi.responsesBody.TaskNewResponse taskNewResponse = JSON.parseObject(response.body().string(), TaskNewResponse.class);
                    if (!taskNewResponse.getSuccess()) {
                        return;
                    }


                    ScanOptions scanOptions = null;
                    try {
                        scanOptions = ScanOptionsHelper.CommandLine2ScanOptions(finalCommandLineStr);
                    } catch (IllegalAccessException ex) {
                        BurpExtender.stderr.println(ex.getMessage());
                        return;
//                            throw new RuntimeException(ex);
                    }
//                        ScanOptions scanOptions = new ScanOptions();


                    // push task to sqlmapApi
                    if (null == scanOptions.getRequestFile() || scanOptions.getRequestFile().isEmpty()) {
                        final String tmpRequestFilePath = TmpRequestFileHelper.writeBytesToFile(httpRequestResponse.getRequest());
                        if (null == tmpRequestFilePath) {
                            sqlMapApiClient.deleteScanTask(taskNewResponse.getTaskid());
                            return;
                        }

                        scanOptions.setRequestFile(tmpRequestFilePath);
                    }

                    Call callIn = sqlMapApiClient.addScanTask(taskNewResponse.getTaskid(), scanOptions);
                    if (null == callIn) {
                        return;
                    }

                    callIn.enqueue(new Callback() {
                        @Override
                        public void onFailure(@NotNull Call call, @NotNull IOException e) {
                            BurpExtender.stderr.println(e.getMessage());
                        }

                        @Override
                        public void onResponse(@NotNull Call call, @NotNull Response response) {

                            // add new row to history panel
                            int id = BurpExtender.addScanTaskToTaskHistory(httpRequestResponse, taskName, taskNewResponse.getTaskid());
                            if (-1 == id) {
                                return;
                            }

                            // push scan status item to scan_status_queue
                            SwingUtilities.invokeLater(() -> TASK_ID_INDEX_MAP_QUEUE.offer(new TaskId2TaskIndexMap(taskNewResponse.getTaskid(), id)));

                        }
                    });

                }
            });


        });
    }


    public Call deleteScanTask(String taskId) {
        if (null == taskId || taskId.trim().isEmpty()) {
            return null;
        }
        return sqlMapApi.taskDelete(taskId);
    }

    public Call stopScanTask(String taskId) {
        if (null == taskId || taskId.trim().isEmpty()) {
            return null;
        }
        return sqlMapApi.scanStop(taskId);
    }

    public Call killScanTask(String taskId) {
        if (null == taskId || taskId.trim().isEmpty()) {
            return null;
        }
        return sqlMapApi.scanKill(taskId);
    }


    public Call updateScanTask(String taskId, ScanOptions scanOptions) {
        if ((null == taskId || taskId.trim().isEmpty()) || (null == scanOptions)) {
            return null;
        }

        return sqlMapApi.scanStart(taskId, scanOptions);
    }

    public Call getScanTaskStatus(String taskId) {
        if (null == taskId || taskId.trim().isEmpty()) {
            return null;
        }

        return sqlMapApi.scanStatus(taskId);
    }

    public Call getScanTaskData(String taskId) {
        if (null == taskId || taskId.trim().isEmpty()) {
            return null;
        }

        return sqlMapApi.scanData(taskId);
    }


    public Call getScanTaskLog(String taskId) {
        if (null == taskId || taskId.trim().isEmpty()) {
            return null;
        }

        return sqlMapApi.scanLog(taskId);
    }

    public Call getScanTaskLogRange(String taskId, int startIndex, int endIndex) {
        if (null == taskId || taskId.trim().isEmpty()) {
            return null;
        }

        return sqlMapApi.scanLogRange(taskId, startIndex, endIndex);
    }

}
