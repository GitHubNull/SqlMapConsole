package ui.component;

import burp.BurpExtender;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.jetbrains.annotations.NotNull;
import sqlmapApi.SqlMapApiClient;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;

public class ScanResultShowDialog extends JDialog {
    JTextArea payloadTextArea;
    JTextArea logsTextArea;

    JButton closeBtn;

    String taskId;

    public ScanResultShowDialog(String taskId) {
        setTitle("扫描结果");
        setLayout(new BorderLayout());
        this.taskId = taskId;

        payloadTextArea = new JTextArea();
        payloadTextArea.setEditable(false);
        add(new JScrollPane(payloadTextArea), BorderLayout.NORTH);

        logsTextArea = new JTextArea();
        logsTextArea.setEditable(false);

        add(new JScrollPane(logsTextArea), BorderLayout.CENTER);

        JPanel southPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));

        closeBtn = new JButton("关闭");
        closeBtn.addActionListener(e -> dispose());

        southPanel.add(closeBtn);

        add(southPanel, BorderLayout.SOUTH);

        pack();
        setSize(getPreferredSize());
        setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);

        getScanResult();
    }

    private void getScanResult() {
        SqlMapApiClient sqlMapApiClient = BurpExtender.getSqlMapApiClient();
        if (null == sqlMapApiClient) {
            return;
        }

        Call taskDataCall = sqlMapApiClient.getScanTaskData(taskId);
        taskDataCall.enqueue(new Callback() {
            @Override
            public void onFailure(@NotNull Call call, @NotNull IOException e) {
                BurpExtender.stderr.println(e.getMessage());
            }

            @Override
            public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
                ResponseBody body = response.body();
                if (null == body) {
                    return;
                }

                String bodyText = body.string();
                if (bodyText.isEmpty()) {
                    return;
                }

                JSONObject jsonObject = JSONObject.parseObject(bodyText);
                JSONArray data = jsonObject.getJSONArray("data");
                if (null == data) {
                    return;
                }

                payloadTextArea.setText(data.toJSONString());
            }
        });

        Call taskLogsCall = sqlMapApiClient.getScanTaskLog(taskId);
        taskLogsCall.enqueue(new Callback() {
            @Override
            public void onFailure(@NotNull Call call, @NotNull IOException e) {
                BurpExtender.stderr.println(e.getMessage());
            }

            @Override
            public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
                ResponseBody body = response.body();
                if (null == body) {
                    return;
                }

                String bodyText = body.string();
                if (bodyText.isEmpty()) {
                    return;
                }

                JSONObject jsonObject = JSONObject.parseObject(bodyText);
                JSONArray data = jsonObject.getJSONArray("log");
                if (null == data) {
                    return;
                }

                logsTextArea.setText(data.toJSONString());
            }
        });

    }

}
