package ui.panel.subPanel;

import burp.BurpExtender;
import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import entities.InjectionStatus;
import entities.TaskId2TaskIndexMap;
import entities.TaskItem;
import models.ScanTaskTableModel;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.jetbrains.annotations.NotNull;
import sqlmapApi.SqlMapApiClient;
import sqlmapApi.SqlMapApiImpl;
import sqlmapApi.SqlMapApiService;
import sqlmapApi.responsesBody.AdminFlushResponse;
import sqlmapApi.responsesBody.ScanStatusResponse;
import ui.component.MessageConsole;
import utils.GlobalStaticVariables;
import utils.MyStringUtil;
import utils.OSinfo;
import utils.OldSqlmapApiSubProcessKillHelper;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static utils.GlobalStaticVariables.*;

public class SqlMapServiceTabPanel extends JPanel {
    JPanel northPanel;

    JPanel pythonExePathPanel;
    JLabel pythonExePathLabel;
    JTextField pythonExePathTextFiled;
    JButton pythonExePathChooserBtn;

    JPanel sqlmapApiPathPanel;
    JLabel sqlmapApiPathLabel;
    JTextField sqlmapApiPathTextFiled;
    JButton sqlmapApiPathChooserBtn;

    JPanel sqlmapApiPortPanel;
    JLabel sqlmapApiPortLabel;
    JTextField sqlmapApiPortTextFiled;
    JButton sqlmapApiPortOperationBtn;
    static String[] sqlmapApiPortOperationBtnTexts = new String[]{EX_MSG.getMsg("edit"), EX_MSG.getMsg("lock")};

    JPanel sqlmapApiTmpRequestFilePathPanel;
    JLabel sqlmapApiTmpRequestFilePathLabel;
    JTextField sqlmapApiTmpRequestFilePathTextFiled;
    JButton sqlmapApiTmpRequestFilePathChooserBtn;

    JPanel centerPanel;

    JPanel sqlmapApiServiceOperationPanel;

    JButton startSqlMapApiBtn;
    JButton stopSqlMapApiBtn;
    JButton flushSqlMapApiLogBtn;
    JButton flushSqlMapApiServiceBtn;

    JScrollPane sqlmapApiServiceRunningLogViewContainer;
    JTextPane sqlmapApiServiceRunningConsole;

    JTextPane sqlmapApiServiceStatusTextPanel;


    SqlMapApiService sqlMapApiService;
    MessageConsole mc;

    SqlMapApiImpl sqlMapApiImpl;
    volatile SqlMapApiClient sqlMapApiClient;
    private final ReentrantReadWriteLock reentrantReadWriteLock = new ReentrantReadWriteLock();

    public SqlMapServiceTabPanel() {
        setLayout(new BorderLayout());

        northPanel = new JPanel();

        northPanel.setLayout(new BoxLayout(northPanel, BoxLayout.Y_AXIS));

        pythonExePathPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        pythonExePathLabel = new JLabel(EX_MSG.getMsg("pythonExePath"));
        pythonExePathTextFiled = new JTextField(GlobalStaticVariables.PYTHON_EXEC_PATH);
        pythonExePathTextFiled.setColumns(80);
        pythonExePathChooserBtn = new JButton(EX_MSG.getMsg("pleaseChoose"));

        pythonExePathPanel.add(pythonExePathLabel);
        pythonExePathPanel.add(pythonExePathTextFiled);
        pythonExePathPanel.add(pythonExePathChooserBtn);

        sqlmapApiPathPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        sqlmapApiPathLabel = new JLabel(EX_MSG.getMsg("sqlmapApiFilePath"));
        sqlmapApiPathTextFiled = new JTextField(GlobalStaticVariables.SQLMAP_API_PATH);
        sqlmapApiPathTextFiled.setColumns(80);
        sqlmapApiPathChooserBtn = new JButton(EX_MSG.getMsg("pleaseChoose"));

        sqlmapApiPathPanel.add(sqlmapApiPathLabel);
        sqlmapApiPathPanel.add(sqlmapApiPathTextFiled);
        sqlmapApiPathPanel.add(sqlmapApiPathChooserBtn);


        sqlmapApiPortPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        sqlmapApiPortLabel = new JLabel(EX_MSG.getMsg("sqlmapApiPort"));
        sqlmapApiPortTextFiled = new JTextField(Integer.toString(GlobalStaticVariables.SQLMAP_API_PORT));
        sqlmapApiPortTextFiled.setEnabled(false);
        sqlmapApiPortTextFiled.setColumns(80);
        sqlmapApiPortOperationBtn = new JButton(EX_MSG.getMsg("edit"));

        sqlmapApiPortPanel.add(sqlmapApiPortLabel);
        sqlmapApiPortPanel.add(sqlmapApiPortTextFiled);
        sqlmapApiPortPanel.add(sqlmapApiPortOperationBtn);

        sqlmapApiTmpRequestFilePathPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        sqlmapApiTmpRequestFilePathLabel = new JLabel(EX_MSG.getMsg("sqlmapApiTmpRequestFilePath"));
        sqlmapApiTmpRequestFilePathTextFiled = new JTextField(TMP_REQUEST_FILE_DIR_PATH);
        sqlmapApiTmpRequestFilePathTextFiled.setColumns(80);
        sqlmapApiTmpRequestFilePathChooserBtn = new JButton(EX_MSG.getMsg("pleaseChoose"));

        sqlmapApiTmpRequestFilePathPanel.add(sqlmapApiTmpRequestFilePathLabel);
        sqlmapApiTmpRequestFilePathPanel.add(sqlmapApiTmpRequestFilePathTextFiled);
        sqlmapApiTmpRequestFilePathPanel.add(sqlmapApiTmpRequestFilePathChooserBtn);


        northPanel.add(pythonExePathPanel);
        northPanel.add(sqlmapApiPathPanel);
        northPanel.add(sqlmapApiPortPanel);
        northPanel.add(sqlmapApiTmpRequestFilePathPanel);

        add(northPanel, BorderLayout.NORTH);

        centerPanel = new JPanel(new BorderLayout());

        sqlmapApiServiceOperationPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));

        startSqlMapApiBtn = new JButton(EX_MSG.getMsg("startSqlmapApi"));
        stopSqlMapApiBtn = new JButton(EX_MSG.getMsg("stopSqlMapApi"));
        flushSqlMapApiLogBtn = new JButton(EX_MSG.getMsg("flushSqlmapApiLog"));
        flushSqlMapApiServiceBtn = new JButton(EX_MSG.getMsg("flushHistoryScanResult"));

        sqlmapApiServiceOperationPanel.add(startSqlMapApiBtn);
        sqlmapApiServiceOperationPanel.add(stopSqlMapApiBtn);
        sqlmapApiServiceOperationPanel.add(flushSqlMapApiLogBtn);
        sqlmapApiServiceOperationPanel.add(flushSqlMapApiServiceBtn);

        centerPanel.add(sqlmapApiServiceOperationPanel, BorderLayout.NORTH);

        sqlmapApiServiceRunningConsole = new JTextPane();

        sqlmapApiServiceRunningLogViewContainer = new JScrollPane(sqlmapApiServiceRunningConsole);

        centerPanel.add(sqlmapApiServiceRunningLogViewContainer, BorderLayout.CENTER);


        add(centerPanel, BorderLayout.CENTER);

        sqlmapApiServiceStatusTextPanel = new JTextPane();

        add(sqlmapApiServiceStatusTextPanel, BorderLayout.SOUTH);


        mc = new MessageConsole(sqlmapApiServiceRunningConsole);
        mc.redirectErr(Color.RED, System.err);
        mc.redirectOut(Color.BLACK, System.out);
        mc.setMessageLines(100);

        sqlMapApiService = new SqlMapApiService();

        initActionListening();


    }

    private void initActionListening() {
        String userHome = System.getProperty("user.home");


        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // 服务配置更新
        pythonExePathTextFiled.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                flushData();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                flushData();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                flushData();
            }

            private void flushData() {
                String tmp = pythonExePathTextFiled.getText();
                if (null == tmp || tmp.trim().isEmpty()) {
                    return;
                }

                tmp = tmp.trim();

                File f = new File(tmp);
                if (f.exists()) {
                    if (tmp.contains(" ")) {
                        tmp = String.format("\"%s\"", tmp);
                    }

                    PYTHON_EXEC_PATH = tmp;
//                    pythonExePathTextFiled.setText(tmp);
                }
            }
        });

        sqlmapApiPathTextFiled.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                flushData();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                flushData();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                flushData();
            }

            private void flushData() {
                String tmp = sqlmapApiPathTextFiled.getText();
                if (null == tmp || tmp.trim().isEmpty()) {
                    return;
                }

                tmp = tmp.trim();

                File f = new File(tmp);
                if (f.exists()) {
                    if (tmp.contains(" ")) {
                        tmp = String.format("\"%s\"", tmp);
                    }

                    SQLMAP_API_PATH = tmp;
//                    sqlmapApiPathTextFiled.setText(tmp);
                }
            }
        });

        sqlmapApiTmpRequestFilePathTextFiled.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                flushData();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                flushData();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                flushData();
            }

            private void flushData() {
                String tmp = sqlmapApiTmpRequestFilePathTextFiled.getText();
                if (null == tmp || tmp.trim().isEmpty()) {
                    return;
                }

                tmp = tmp.trim();
                File f = new File(tmp);
                if (f.exists()) {
                    if (tmp.contains(" ")) {
                        tmp = String.format("\"%s\"", tmp);
                    }

                    TMP_REQUEST_FILE_DIR_PATH = tmp;
//                    sqlmapApiTmpRequestFilePathTextFiled.setText(tmp);
                }
            }
        });


        sqlmapApiPortTextFiled.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                flush();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                flush();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                flush();
            }

            private void flush() {
                String portStr = sqlmapApiPortTextFiled.getText();
                if (null == portStr || portStr.trim().isEmpty()) {
                    return;
                }

                portStr = portStr.trim();

                if (!MyStringUtil.isTruePortNumber(portStr)) {
                    return;
                }

                GlobalStaticVariables.SQLMAP_API_PORT = Integer.parseInt(portStr);
            }
        });

        sqlmapApiPortOperationBtn.addActionListener(e -> {
            boolean oldFlag = sqlmapApiPortTextFiled.isEnabled();
            sqlmapApiPortTextFiled.setEnabled(!oldFlag);
//            sqlmapApiPortOperationBtn.setBackground(oldFlag == true ? Color.GREEN : Color.GRAY);
            sqlmapApiPortOperationBtn.setText(oldFlag ? sqlmapApiPortOperationBtnTexts[0] : sqlmapApiPortOperationBtnTexts[1]);
        });


        pythonExePathChooserBtn.addActionListener(e -> {

            JFileChooser fileChooser = new JFileChooser(userHome);

            if (OSinfo.isWindows()) {
                FileNameExtensionFilter filter = new FileNameExtensionFilter("python.exe", "exe");
                fileChooser.setFileFilter(filter);
            }

            int returnVal = fileChooser.showOpenDialog(SqlMapServiceTabPanel.this);
            if (returnVal == JFileChooser.APPROVE_OPTION) {

                File file = fileChooser.getSelectedFile();
                if (null == file || file.getPath().trim().isEmpty()) {

                    return;
                }

                String fileName = file.getName();
                Set<String> pythonExeFileSet = new HashSet<>();

                if (OSinfo.isMacOS() || OSinfo.isLinux()) {
                    pythonExeFileSet.add("python");
                    pythonExeFileSet.add("python3");
                } else if (OSinfo.isWindows()) {
                    pythonExeFileSet.add("python.exe");
                    pythonExeFileSet.add("python2.exe");
                    pythonExeFileSet.add("python3.exe");
                }

                if (!pythonExeFileSet.contains(fileName)) {
                    return;
                }

                String fileAbsolutePath = file.getAbsolutePath().trim();
                if (fileAbsolutePath.contains(" ")) {
                    fileAbsolutePath = String.format("\"%s\"", fileAbsolutePath);
                }
                PYTHON_EXEC_PATH = fileAbsolutePath;


                pythonExePathTextFiled.setText(fileAbsolutePath);
            }


        });

        sqlmapApiPathChooserBtn.addActionListener(e -> {
            FileNameExtensionFilter filter = new FileNameExtensionFilter("sqlmapapi.py", "py");
            JFileChooser fileChooser = new JFileChooser(userHome);
            fileChooser.setFileFilter(filter);
            int returnVal = fileChooser.showOpenDialog(SqlMapServiceTabPanel.this);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();
                if (null == file || file.getPath().trim().isEmpty()) {
                    return;
                }

                String fileName = file.getName();

                if (!"sqlmapapi.py".equals(fileName)) {
                    return;
                }

                String fileAbsolutePath = file.getAbsolutePath().trim();
                if (fileAbsolutePath.contains(" ")) {
                    fileAbsolutePath = String.format("\"%s\"", fileAbsolutePath);
                }
                SQLMAP_API_PATH = fileAbsolutePath;


                sqlmapApiPathTextFiled.setText(fileAbsolutePath);
            }
        });

        sqlmapApiTmpRequestFilePathChooserBtn.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser(userHome);
            fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            int returnVal = fileChooser.showOpenDialog(SqlMapServiceTabPanel.this);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();
                if (null == file) {
                    return;
                }

                String fileAbsolutePath = file.getAbsolutePath();

                if (fileAbsolutePath.trim().isEmpty()) {
                    return;
                }


                fileAbsolutePath = fileAbsolutePath.trim();
                if (fileAbsolutePath.contains(" ")) {
                    fileAbsolutePath = String.format("\"%s\"", fileAbsolutePath);
                }
                TMP_REQUEST_FILE_DIR_PATH = fileAbsolutePath;


                sqlmapApiTmpRequestFilePathTextFiled.setText(fileAbsolutePath);


            }
        });


        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // 开启/关闭 sqlmapapi 服务

        startSqlMapApiBtn.addActionListener(this::startService);

        stopSqlMapApiBtn.addActionListener(e -> stopService());

        flushSqlMapApiLogBtn.addActionListener(e -> sqlmapApiServiceRunningConsole.setText(""));

        flushSqlMapApiServiceBtn.addActionListener(e -> {
            SQLMAPAPI_SERVICE_STOP_FLAG_LOCK.readLock().lock();
            try {

                // 如果服务未运行退出
                if (SQLMAPAPI_SERVICE_STOP_FLAG) {
                    return;
                }
            } finally {
                SQLMAPAPI_SERVICE_STOP_FLAG_LOCK.readLock().unlock();
            }


            // 请求刷新历史扫描结果
            Call call = sqlMapApiImpl.adminFlush();
            if (null == call) {
                return;
            }

            call.enqueue(new Callback() {
                @Override
                public void onFailure(@NotNull Call call, @NotNull IOException e) {
                    System.out.println(e.getMessage());
                }

                @Override
                public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {

                    ResponseBody responseBody = response.body();
                    if (null == responseBody) {
                        response.close();
                        return;
                    }

                    String bodyStr = responseBody.string();
                    response.close();
                    if (bodyStr.trim().isEmpty()) {
                        return;
                    }

                    AdminFlushResponse adminFlushResponse = JSON.parseObject(bodyStr, AdminFlushResponse.class);
                    if (adminFlushResponse.getSuccess()) {

                        // 清除任务扫描队列
                        TASK_ID_INDEX_MAP_QUEUE.clear();

                        // 遍历所有任务，对状态为运行中的任务进行翻转，翻转为暂停
                        BurpExtender.flushScanTaskStatus();
                    }
                }
            });


        });


    }

    public void stopService() {
        OldSqlmapApiSubProcessKillHelper.kill();
        startSqlMapApiBtn.setEnabled(true);
//            startSqlMapApiBtn.setBackground(Color.GREEN);

        stopSqlMapApiBtn.setEnabled(false);
//            stopSqlMapApiBtn.setBackground(Color.GRAY);

        sqlMapApiService.stop();

        SwingUtilities.invokeLater(() -> {
            sqlmapApiServiceStatusTextPanel.setBackground(Color.GRAY);
            sqlmapApiServiceStatusTextPanel.setText(EX_MSG.getMsg("sqlMapApiStopped"));

            BurpExtender.getConsoleTab().getTaskHistory().getStatusInfoText().setBackground(Color.GRAY);
            BurpExtender.getConsoleTab().getTaskHistory().getStatusInfoText().setText(EX_MSG.getMsg("sqlMapApiStopped"));
        });


        SQLMAPAPI_SERVICE_STOP_FLAG_LOCK.writeLock().lock();
        try {
            SQLMAPAPI_SERVICE_STOP_FLAG = true;
            TASK_ID_INDEX_MAP_QUEUE.clear();
            SCAN_TASK_QUEUE.clear();
            sqlMapApiClient = null;
            sqlMapApiImpl = null;
        } finally {
            SQLMAPAPI_SERVICE_STOP_FLAG_LOCK.writeLock().unlock();
        }


//        sqlmapApiServiceRunningConsole.setText("");
    }

    private void startPollScanTaskQueue() {
        final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        final ScheduledFuture<?> workerHandle = scheduler.scheduleAtFixedRate(this::pollScanTaskQueue, 1000L, 1100L, TimeUnit.MILLISECONDS);
        while (true) {
            SQLMAPAPI_SERVICE_STOP_FLAG_LOCK.readLock().lock();
            try {
                if (SQLMAPAPI_SERVICE_STOP_FLAG) {
                    workerHandle.cancel(true);
                    scheduler.shutdown();
                    break;
                }
            } finally {
                SQLMAPAPI_SERVICE_STOP_FLAG_LOCK.readLock().unlock();
            }

        }
    }

    private void pollScanTaskQueue() {
        TaskItem taskItem = SCAN_TASK_QUEUE.poll();
        if (null == taskItem) {
            return;
        }

        try {
            BurpExtender.startScanTask(taskItem.getTaskName(), taskItem.getScanTaskCommandLineStr(),
                    taskItem.getHttpRequestResponse());
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    private void pollingSqlmapApiSubProcessOutputWorker(BufferedReader bufferedReader) {
//        String readLineStr = "";
        try {
            String readLineStr = bufferedReader.readLine();
            if (null == readLineStr) {
                return;
            }

            System.out.println(readLineStr);
        } catch (IOException ex) {
            BurpExtender.stderr.println(ex.getMessage());
        }

    }

    // 后台轮询sqlmap api 进程输出并重定向到GUI的console界面
    private void pollingSqlmapApiSubProcessOutput() throws InterruptedException {
        BufferedReader bufferedReader;
        do {
            bufferedReader = sqlMapApiService.getBufferedReader();
        } while (null == bufferedReader);

        final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        BufferedReader finalBufferedReader = bufferedReader;
        final ScheduledFuture<?> workerHandle = scheduler.scheduleAtFixedRate(() -> pollingSqlmapApiSubProcessOutputWorker(finalBufferedReader), 300L, 1000L, TimeUnit.MILLISECONDS);
        while (true) {
            SQLMAPAPI_SERVICE_STOP_FLAG_LOCK.readLock().lock();
            try {
                if (SQLMAPAPI_SERVICE_STOP_FLAG) {
                    workerHandle.cancel(true);
                    scheduler.shutdown();
                    break;
                }
            } finally {
                SQLMAPAPI_SERVICE_STOP_FLAG_LOCK.readLock().unlock();
            }


        }
    }

    private void pollingScanTaskQueueStatusWorker() {
        TaskId2TaskIndexMap taskId2TaskIndexMap = TASK_ID_INDEX_MAP_QUEUE.poll();

        if (null == taskId2TaskIndexMap) {
            return;
        }


//            assert taskId2TaskIndexMap != null;
        Call call = sqlMapApiClient.getScanTaskStatus(taskId2TaskIndexMap.getTaskId());
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
                String bodyText = response.body().string();
                response.close();
                if (bodyText.trim().isEmpty()) {
                    return;
                }

                ScanStatusResponse scanStatusResponse = JSON.parseObject(bodyText, ScanStatusResponse.class);

                ScanTaskTableModel scanTaskTableModel = BurpExtender.getScanTaskTableModel();

                SwingUtilities.invokeLater(() -> scanTaskTableModel.updateScanTaskScanTaskStatusById(taskId2TaskIndexMap.getTaskIndex(), GlobalStaticVariables.STR_TO_SCAN_TASK_STATUS_MAP.get(scanStatusResponse.getStatus())));

                if (!"terminated".equals(scanStatusResponse.getStatus())) {
                    TASK_ID_INDEX_MAP_QUEUE.offer(taskId2TaskIndexMap);
                    return;
                }

                // 获取注入扫描是否成功
                SwingUtilities.invokeLater(() -> getScanTaskResult(taskId2TaskIndexMap));

            }
        });

    }

    // 后台轮询sqlmap api 任务队列的状态
    private void pollingScanTaskQueueStatus() throws InterruptedException {
        reentrantReadWriteLock.readLock().lock();
        try {
            while (true) {
                if (null != sqlMapApiClient) {
                    break;
                }
            }
        } finally {
            reentrantReadWriteLock.readLock().unlock();
        }

        final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        final ScheduledFuture<?> workerHandle = scheduler.scheduleAtFixedRate(this::pollingScanTaskQueueStatusWorker, 3000L, 1000L, TimeUnit.MILLISECONDS);

        while (true) {
            SQLMAPAPI_SERVICE_STOP_FLAG_LOCK.readLock().lock();
            try {
                if (SQLMAPAPI_SERVICE_STOP_FLAG) {
//                    SQLMAPAPI_SERVICE_STOP_FLAG_LOCK.readLock().unlock();
                    workerHandle.cancel(true);
                    scheduler.shutdown();
                    break;
                }
            } finally {
                SQLMAPAPI_SERVICE_STOP_FLAG_LOCK.readLock().unlock();
            }

//            Thread.sleep(3000);

        }
    }

    // 获取注入扫描是否成功函数
    public void getScanTaskResult(TaskId2TaskIndexMap taskId2TaskIndexMap) {
        Call call = sqlMapApiClient.getScanTaskData(taskId2TaskIndexMap.getTaskId());
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
                ResponseBody responseBody = response.body();
                if (null == responseBody) {
                    response.close();
                    return;
                }
                String body = responseBody.string();
                response.close();
                if (body.trim().isEmpty()) {
                    return;
                }

                JSONObject scanDataPre = JSON.parseObject(body);
                JSONArray scanData = (JSONArray) scanDataPre.get("data");
                if (null == scanData || scanData.isEmpty()) {
                    BurpExtender.getScanTaskTableModel().updateScanTaskScanTaskInjectedById(taskId2TaskIndexMap.getTaskIndex(), InjectionStatus.DISABLE_INJECT);
                } else {
                    BurpExtender.getScanTaskTableModel().updateScanTaskScanTaskInjectedById(taskId2TaskIndexMap.getTaskIndex(), InjectionStatus.ENABLE_INJECT);
                }

            }
        });


    }

    public void flushConfig() {
        pythonExePathTextFiled.setText(PYTHON_EXEC_PATH);
        sqlmapApiPathTextFiled.setText(SQLMAP_API_PATH);
        sqlmapApiPortTextFiled.setText(Integer.toString(SQLMAP_API_PORT));
        sqlmapApiTmpRequestFilePathTextFiled.setText(TMP_REQUEST_FILE_DIR_PATH);
    }


    public SqlMapApiClient getSqlMapApiClient() {
        return sqlMapApiClient;
    }

    private void startService(ActionEvent e) {

        startSqlMapApiBtn.setEnabled(false);
//            startSqlMapApiBtn.setBackground(Color.GRAY);

        stopSqlMapApiBtn.setEnabled(true);
//            stopSqlMapApiBtn.setBackground(Color.GREEN);

        SQLMAPAPI_SERVICE_STOP_FLAG_LOCK.writeLock().lock();
        try {
            sqlMapApiService.start();

            sqlMapApiImpl = new SqlMapApiImpl(SQLMAP_API_HOST, SQLMAP_API_PORT);
//        sqlMapApi = new SqlMapApiImpl(GlobalStaticVariables.SQLMAP_API_HOST, 8775);
            TASK_ID_INDEX_MAP_QUEUE.clear();

            reentrantReadWriteLock.writeLock().lock();
            try {
                sqlMapApiClient = new SqlMapApiClient(sqlMapApiImpl);
            } finally {
                reentrantReadWriteLock.writeLock().unlock();
            }

            SQLMAPAPI_SERVICE_STOP_FLAG = false;

            SwingUtilities.invokeLater(() -> {
                sqlmapApiServiceStatusTextPanel.setBackground(Color.GREEN);
                sqlmapApiServiceStatusTextPanel.setText(EX_MSG.getMsg("sqlMapApiIsRunning"));


                BurpExtender.getConsoleTab().getTaskHistory().getStatusInfoText().setBackground(Color.GREEN);
                BurpExtender.getConsoleTab().getTaskHistory().getStatusInfoText().setText(EX_MSG.getMsg("sqlMapApiIsRunning"));
            });

        } catch (IOException ex) {
            BurpExtender.debugError(ex.getMessage());

            SQLMAPAPI_SERVICE_STOP_FLAG = true;

            sqlmapApiServiceStatusTextPanel.setBackground(Color.RED);
            sqlmapApiServiceStatusTextPanel.setText(EX_MSG.getMsg("sqlMapApiStartedFailed"));
            BurpExtender.getConsoleTab().getTaskHistory().getStatusInfoText().setText(EX_MSG.getMsg("sqlMapApiStartedFailed"));
            BurpExtender.getConsoleTab().getTaskHistory().getStatusInfoText().setBackground(Color.RED);

            return;
        } finally {
            SQLMAPAPI_SERVICE_STOP_FLAG_LOCK.writeLock().unlock();
        }


        // start poll scan task queue
        new Thread(this::startPollScanTaskQueue).start();

        // scan scan task running status thread
        new Thread(() -> {
            try {
                pollingScanTaskQueueStatus();
            } catch (InterruptedException ex) {
                throw new RuntimeException(ex);
            }
        }).start();

        // write sqlmap api status to gui console thread
        new Thread(() -> {
            try {
                pollingSqlmapApiSubProcessOutput();
            } catch (InterruptedException ex) {
                throw new RuntimeException(ex);
            }
        }).start();

    }

    public void updateI18n() {
        pythonExePathLabel.setText(EX_MSG.getMsg("pythonExePath"));
        pythonExePathChooserBtn.setText(EX_MSG.getMsg("pleaseChoose"));

        sqlmapApiPathLabel.setText(EX_MSG.getMsg("sqlmapApiFilePath"));
        sqlmapApiPathChooserBtn.setText(EX_MSG.getMsg("pleaseChoose"));

        sqlmapApiPortLabel.setText(EX_MSG.getMsg("sqlmapApiPort"));

        sqlmapApiPortOperationBtnTexts = new String[]{EX_MSG.getMsg("edit"), EX_MSG.getMsg("lock")};
        sqlmapApiPortOperationBtn.setText(EX_MSG.getMsg("edit"));

        sqlmapApiTmpRequestFilePathLabel.setText(EX_MSG.getMsg("sqlmapApiTmpRequestFilePath"));
        sqlmapApiTmpRequestFilePathChooserBtn.setText(EX_MSG.getMsg("pleaseChoose"));

        startSqlMapApiBtn.setText(EX_MSG.getMsg("startSqlmapApi"));
        stopSqlMapApiBtn.setText(EX_MSG.getMsg("stopSqlMapApi"));
        flushSqlMapApiLogBtn.setText(EX_MSG.getMsg("flushSqlmapApiLog"));
        flushSqlMapApiServiceBtn.setText(EX_MSG.getMsg("flushHistoryScanResult"));
    }
}
