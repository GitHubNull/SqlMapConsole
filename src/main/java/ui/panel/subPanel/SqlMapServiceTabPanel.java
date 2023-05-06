package ui.panel.subPanel;

import burp.BurpExtender;
import sqlmapApiService.SqlMapApiService;
import ui.component.MessageConsole;
import utils.GlobalStaticsVar;
import utils.MyStringUtil;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.regex.Pattern;

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
    final static String[] sqlmapApiPortOperationBtnTexts = new String[]{"编辑", "锁定"};

    JPanel sqlmapApiTmpRequestFilePathPanel;
    JLabel sqlmapApiTmpRequestFilePathLabel;
    JTextField sqlmapApiTmpRequestFilePathTextFiled;
    JButton sqlmapApiTmpRequestFilePathChooserBtn;

    JPanel centerPanel;

    JPanel sqlmapApiServiceOperationPanel;

    JButton startSqlMapApiBtn;
    JButton stopSqlMapApiBtn;
    JButton flushSqlMapApiLogBtn;

    JScrollPane sqlmapApiServiceRunningLogViewContainer;
    JTextPane sqlmapApiServiceRunningConsole;

    JTextPane sqlmapApiServiceStatusTextPanel;

//    int port = 5678;
//    String pythonPath = "E:\\python\\Python39\\python.exe";
//    String sqlmapApiPath = "E:\\myProgram\\sqlmap\\sqlmap-1.7\\sqlmapapi.py";

    SqlMapApiService sqlMapApiService;
    MessageConsole mc;

    private static ReentrantReadWriteLock stopFlagReentrantLock = new ReentrantReadWriteLock();
    private static boolean sqlmapApiServiceStopFlag = false;
    private static ReentrantReadWriteLock.ReadLock stopFlagReadLock = stopFlagReentrantLock.readLock();
    private static ReentrantReadWriteLock.WriteLock stopFlagWriteLock = stopFlagReentrantLock.writeLock();


    private static ReentrantReadWriteLock sqlmapApiAdminTokenSetFlagReentrantLock = new ReentrantReadWriteLock();
    private static ReentrantReadWriteLock.ReadLock sqlmapApiAdminTokenSetFlagReadLock = stopFlagReentrantLock.readLock();
    private static ReentrantReadWriteLock.WriteLock sqlmapApiAdminTokenSetFlagWriteLock = stopFlagReentrantLock.writeLock();


    // flush console flag
//    static boolean flushConsoleFlag = false;
//    private static ReentrantReadWriteLock flushConsoleFlagReentrantLock = new ReentrantReadWriteLock();
//    private static ReentrantReadWriteLock.ReadLock flushConsoleFlagReadLock = stopFlagReentrantLock.readLock();
//    private static ReentrantReadWriteLock.WriteLock flushConsoleFlagWriteLock = stopFlagReentrantLock.writeLock();

    public SqlMapServiceTabPanel() {
        setLayout(new BorderLayout());

        northPanel = new JPanel();

        northPanel.setLayout(new BoxLayout(northPanel, BoxLayout.Y_AXIS));

        pythonExePathPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        pythonExePathLabel = new JLabel("python.exe文件路径");
        pythonExePathTextFiled = new JTextField(GlobalStaticsVar.pythonExecPath);
        pythonExePathTextFiled.setColumns(80);
        pythonExePathChooserBtn = new JButton("请选择...");

        pythonExePathPanel.add(pythonExePathLabel);
        pythonExePathPanel.add(pythonExePathTextFiled);
        pythonExePathPanel.add(pythonExePathChooserBtn);

        sqlmapApiPathPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        sqlmapApiPathLabel = new JLabel("sqlmapapi.py文件路径");
        sqlmapApiPathTextFiled = new JTextField(GlobalStaticsVar.sqlmapApiPath);
        sqlmapApiPathTextFiled.setColumns(80);
        sqlmapApiPathChooserBtn = new JButton("请选择...");

        sqlmapApiPathPanel.add(sqlmapApiPathLabel);
        sqlmapApiPathPanel.add(sqlmapApiPathTextFiled);
        sqlmapApiPathPanel.add(sqlmapApiPathChooserBtn);


        sqlmapApiPortPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        sqlmapApiPortLabel = new JLabel("sqlmapapi本地监听端口");
        sqlmapApiPortTextFiled = new JTextField(Integer.toString(GlobalStaticsVar.sqlmapApiPort));
        sqlmapApiPortTextFiled.setEnabled(false);
        sqlmapApiPortTextFiled.setColumns(80);
        sqlmapApiPortOperationBtn = new JButton("编辑");

        sqlmapApiPortPanel.add(sqlmapApiPortLabel);
        sqlmapApiPortPanel.add(sqlmapApiPortTextFiled);
        sqlmapApiPortPanel.add(sqlmapApiPortOperationBtn);

        sqlmapApiTmpRequestFilePathPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        sqlmapApiTmpRequestFilePathLabel = new JLabel("请求报文临时存储文件路径");
        sqlmapApiTmpRequestFilePathTextFiled = new JTextField(GlobalStaticsVar.tmpRequestDataFileParentPath);
        sqlmapApiTmpRequestFilePathTextFiled.setColumns(80);
        sqlmapApiTmpRequestFilePathChooserBtn = new JButton("请选择...");

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

        startSqlMapApiBtn = new JButton("启动sqlmapApi服务");
        stopSqlMapApiBtn = new JButton("关闭sqlmapApi服务");
        flushSqlMapApiLogBtn = new JButton("清除sqlmapApi服务日志");

        sqlmapApiServiceOperationPanel.add(startSqlMapApiBtn);
        sqlmapApiServiceOperationPanel.add(stopSqlMapApiBtn);
        sqlmapApiServiceOperationPanel.add(flushSqlMapApiLogBtn);

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

        sqlMapApiService = new SqlMapApiService(GlobalStaticsVar.pythonExecPath, GlobalStaticsVar.sqlmapApiPath, GlobalStaticsVar.sqlmapApiPort);

        initActionListening();


    }

    private void initActionListening() {
        String userHome = System.getProperty("user.home");

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // 服务配置更新

        sqlmapApiPortTextFiled.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                flush(e);
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                flush(e);
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                flush(e);
            }

            private void flush(DocumentEvent e) {
                String portStr = sqlmapApiPortTextFiled.getText();
                if (null == portStr || portStr.trim().isEmpty()) {
                    return;
                }

                if (!MyStringUtil.isTruePortNumber(portStr)) {
                    return;
                }

                GlobalStaticsVar.sqlmapApiPort = Integer.parseInt(portStr);
            }
        });

        sqlmapApiPortOperationBtn.addActionListener(e -> {
            boolean oldFlag = sqlmapApiPortTextFiled.isEnabled();
            sqlmapApiPortTextFiled.setEnabled(!oldFlag);
//            sqlmapApiPortOperationBtn.setBackground(oldFlag == true ? Color.GREEN : Color.GRAY);
            sqlmapApiPortOperationBtn.setText(oldFlag == true ? sqlmapApiPortOperationBtnTexts[0] : sqlmapApiPortOperationBtnTexts[1]);
        });


        pythonExePathChooserBtn.addActionListener(e -> {
            FileNameExtensionFilter filter = new FileNameExtensionFilter("python.exe", "exe");
            JFileChooser fileChooser = new JFileChooser(userHome);
            fileChooser.setFileFilter(filter);
            int returnVal = fileChooser.showOpenDialog(SqlMapServiceTabPanel.this);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();
                if (null == file || file.getPath().trim().isEmpty()) {
                    return;
                }

                String fileName = file.getName();
                Set<String> pythonExeFileSet = new HashSet<String>();

                pythonExeFileSet.add("python.exe");
                pythonExeFileSet.add("python2.exe");
                pythonExeFileSet.add("python3.exe");

                if (!pythonExeFileSet.contains(fileName)) {
                    return;
                }

                GlobalStaticsVar.pythonExecPath = file.getAbsolutePath();
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


                GlobalStaticsVar.sqlmapApiPath = file.getAbsolutePath();
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

                String directPath = file.getAbsolutePath();

                if (directPath.trim().isEmpty()) {
                    return;
                }


                GlobalStaticsVar.tmpRequestDataFileParentPath = directPath;
            }
        });


        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // 开启/关闭 sqlmapapi 服务

        startSqlMapApiBtn.addActionListener(e -> {
            startSqlMapApiBtn.setEnabled(false);
//            startSqlMapApiBtn.setBackground(Color.GRAY);

            stopSqlMapApiBtn.setEnabled(true);
//            stopSqlMapApiBtn.setBackground(Color.GREEN);

            stopFlagWriteLock.lock();
            sqlmapApiServiceStopFlag = false;
            stopFlagWriteLock.unlock();


//            sqlmapApiAdminTokenSetFlagWriteLock.lock();
            GlobalStaticsVar.sqlmapApiAdminToken = "";
            GlobalStaticsVar.sqlmapApiAdminTokenSetFlag = false;
//            sqlmapApiAdminTokenSetFlagWriteLock.unlock();


            try {
                sqlMapApiService.start();
                sqlmapApiServiceStatusTextPanel.setBackground(Color.GREEN);
                sqlmapApiServiceStatusTextPanel.setText("sqlmapApi服务运行中...");
            } catch (IOException ex) {
                BurpExtender.stderr.println(ex.getMessage());
            }

            new Thread(() -> {
                BufferedReader bufferedReader = sqlMapApiService.getBufferedReader();
                if (null == bufferedReader) {
                    return;
                }

                String readLineStr;
                String separator = "Admin (secret) token: ";
                Pattern pattern = Pattern.compile("Admin \\(secret\\) token\\: (.*?)");
                while (true) {
                    stopFlagReadLock.lock();
                    if (sqlmapApiServiceStopFlag) {
                        stopFlagReadLock.unlock();
                        break;
                    }
                    stopFlagReadLock.unlock();

                    try {
                        if ((readLineStr = bufferedReader.readLine()) == null) {
                            break;
                        }

                    } catch (IOException ex) {
                        BurpExtender.stderr.println(ex.getMessage());
                        break;
                    }

//                        sqlmapApiAdminTokenSetFlagReentrantLock.readLock().lock();
                    if (!GlobalStaticsVar.sqlmapApiAdminTokenSetFlag && readLineStr.contains(separator)) {
//                            sqlmapApiAdminTokenSetFlagReadLock.unlock();

                        String[] tmp = readLineStr.split("Admin \\(secret\\) token\\: ", 2);
                        if (null != tmp && 0 != tmp.length) {

//                                sqlmapApiAdminTokenSetFlagReentrantLock.writeLock().lock();
                            GlobalStaticsVar.sqlmapApiAdminTokenSetFlag = true;
//                                sqlmapApiAdminTokenSetFlagReentrantLock.writeLock().unlock();

                            GlobalStaticsVar.sqlmapApiAdminToken = tmp[1].trim();
//                                System.out.println(String.format("sqlmapApiAdminToken: %s", GlobalStaticsVar.sqlmapApiAdminToken));
                        }
                    }
//                        if (GlobalStaticsVar.sqlmapApiAdminTokenSetFlag){
//                            sqlmapApiAdminTokenSetFlagReentrantLock.readLock().unlock();
//                        }

//                        flushConsoleFlagReadLock.lock();
                    System.out.println(readLineStr);
//                        flushConsoleFlagReadLock.unlock();
                }


            }).start();

        });

        stopSqlMapApiBtn.addActionListener(e -> {
            startSqlMapApiBtn.setEnabled(true);
//            startSqlMapApiBtn.setBackground(Color.GREEN);

            stopSqlMapApiBtn.setEnabled(false);
//            stopSqlMapApiBtn.setBackground(Color.GRAY);

            sqlMapApiService.stop();

            sqlmapApiServiceStatusTextPanel.setBackground(Color.GRAY);
            sqlmapApiServiceStatusTextPanel.setText("sqlmapApi服务已停止");

            stopFlagWriteLock.lock();
            sqlmapApiServiceStopFlag = true;
            stopFlagWriteLock.unlock();

            sqlmapApiServiceRunningConsole.setText("");

//            sqlmapApiAdminTokenSetFlagWriteLock.lock();
            GlobalStaticsVar.sqlmapApiAdminToken = "";
            GlobalStaticsVar.sqlmapApiAdminTokenSetFlag = false;
//            sqlmapApiAdminTokenSetFlagWriteLock.unlock();


        });

        flushSqlMapApiLogBtn.addActionListener(e -> {
//            flushConsoleFlagWriteLock.lock();
//            flushConsoleFlag = true;
            sqlmapApiServiceRunningConsole.setText("");
//            flushConsoleFlag = false;
//            flushConsoleFlagWriteLock.unlock();

        });


    }
}
