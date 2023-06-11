package ui.component;

import burp.BurpExtender;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import com.alibaba.fastjson2.JSONWriter;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.jetbrains.annotations.NotNull;
import sqlmapApi.SqlMapApiClient;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.IOException;

import static utils.GlobalStaticVariables.EX_MSG;

public class ScanResultShowDialog extends JFrame {
    JTextArea payloadTextArea;
    JTextArea logsTextArea;

    JButton closeBtn;

    String taskId;

    public ScanResultShowDialog(String taskId) {
        setTitle(EX_MSG.getMsg("scanResult"));
        setLayout(new BorderLayout());
        this.taskId = taskId;


        payloadTextArea = new JTextArea();
        payloadTextArea.setEditable(false);
        JScrollPane payloadPanel = new JScrollPane(payloadTextArea);
        payloadPanel.setBorder(new TitledBorder(EX_MSG.getMsg("payload")));

        logsTextArea = new JTextArea();
        logsTextArea.setEditable(false);
        JScrollPane logsPanel = new JScrollPane(logsTextArea);
        logsPanel.setBorder(new TitledBorder(EX_MSG.getMsg("log")));

        JSplitPane resultPanel = new JSplitPane(JSplitPane.VERTICAL_SPLIT, payloadPanel, logsPanel);

        add(resultPanel, BorderLayout.CENTER);

        JPanel southPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));

        closeBtn = new JButton(EX_MSG.getMsg("close"));
        closeBtn.addActionListener(e -> dispose());

        southPanel.add(closeBtn);

        add(southPanel, BorderLayout.SOUTH);

        setSize(getPreferredSize());
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLocationRelativeTo(null);

        getScanResult();
    }

    private void getScanResult() {
        SqlMapApiClient sqlMapApiClient = BurpExtender.getSqlMapApiClient();
        if (null == sqlMapApiClient) {
            return;
        }

        Call taskDataCall = sqlMapApiClient.getScanTaskData(taskId);
        if (null == taskDataCall) {
            return;
        }

        taskDataCall.enqueue(new Callback() {
            @Override
            public void onFailure(@NotNull Call call, @NotNull IOException e) {
                BurpExtender.stderr.println(e.getMessage());
            }

            @Override
            public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
                ResponseBody body = response.body();
                if (null == body) {
                    body.close();
                    return;
                }

                String bodyText = body.string();
                body.close();
                if (bodyText.isEmpty()) {
                    return;
                }

                JSONObject jsonObject = JSONObject.parseObject(bodyText);
                JSONArray data = jsonObject.getJSONArray("data");
                if (null == data || data.isEmpty()) {
                    return;
                }

                payloadTextArea.setText(data.toJSONString(JSONWriter.Feature.PrettyFormat));
                setSize(getPreferredSize());
                setLocationRelativeTo(null);
            }
        });

        Call taskLogsCall = sqlMapApiClient.getScanTaskLog(taskId);
        if (null == taskLogsCall) {
            return;
        }

        taskLogsCall.enqueue(new Callback() {
            @Override
            public void onFailure(@NotNull Call call, @NotNull IOException e) {
                BurpExtender.stderr.println(e.getMessage());
            }

            @Override
            public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
                ResponseBody body = response.body();
                if (null == body) {
                    body.close();
                    return;
                }

                String bodyText = body.string();
                body.close();
                if (bodyText.isEmpty()) {
                    return;
                }

                JSONObject jsonObject = JSONObject.parseObject(bodyText);
                JSONArray data = jsonObject.getJSONArray("log");
                if (null == data || data.isEmpty()) {
                    return;
                }

                logsTextArea.setText(data.toJSONString(JSONWriter.Feature.PrettyFormat));
                setSize(getPreferredSize());
                setLocationRelativeTo(null);
            }
        });

    }

}
