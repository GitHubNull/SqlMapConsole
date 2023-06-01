package controller;

import burp.BurpExtender;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import ui.component.ScanTaskConfigLevel1;
import ui.component.ScanTaskConfigLevel2;
import ui.component.ScanTaskConfigLevel3;
import ui.component.ScanTaskConfigLevel4;
import utils.GlobalStaticsVar;
import utils.MyStringUtil;

import javax.swing.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static utils.GlobalStaticsVar.SQLMAPAPI_SERVICE_STOP_FLAG;
import static utils.GlobalStaticsVar.SQLMAPAPI_SERVICE_STOP_FLAG_LOCK;

public class ContextMenuFactory implements IContextMenuFactory {
//    Set<Byte> allow_menu_in_set = new HashSet<>();

    public ContextMenuFactory() {
//        allow_menu_in_set.add(IContextMenuInvocation.)
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation contextMenuInvocation) {
        List<JMenuItem> menuItemList = new ArrayList<>();

        IHttpRequestResponse[] httpRequestResponses = contextMenuInvocation.getSelectedMessages();

        boolean stopFlag = false;
        SQLMAPAPI_SERVICE_STOP_FLAG_LOCK.readLock().lock();
        try {
            if (SQLMAPAPI_SERVICE_STOP_FLAG) {
                stopFlag = true;
            }
        } finally {
            SQLMAPAPI_SERVICE_STOP_FLAG_LOCK.readLock().unlock();
        }

        if ((null == httpRequestResponses || 0 == httpRequestResponses.length)) { // || 1 != httpRequestResponses.length
            return menuItemList;
        }

        JMenuItem scanConfigLevel_0 = new JMenuItem("[sqlIC-0]");
        JMenuItem scanConfigLevel_1 = new JMenuItem("[sqlIC-1]");
        JMenuItem scanConfigLevel_2 = new JMenuItem("[sqlIC-2]");
        JMenuItem scanConfigLevel_3 = new JMenuItem("[sqlIC-3]");
        JMenuItem scanConfigLevel_4 = new JMenuItem("[sqlIC-4]");


        initActionListening(contextMenuInvocation, scanConfigLevel_0, scanConfigLevel_1,
                scanConfigLevel_2, scanConfigLevel_3, scanConfigLevel_4);


        menuItemList.add(scanConfigLevel_0);
        menuItemList.add(scanConfigLevel_1);
        menuItemList.add(scanConfigLevel_2);
        menuItemList.add(scanConfigLevel_3);
        menuItemList.add(scanConfigLevel_4);

        for (JMenuItem menuItem : menuItemList) {
            menuItem.setEnabled(!stopFlag);

            if (stopFlag) {
                menuItem.setText(menuItem.getText() + " [sqlmapApi已停止]");
            }
        }

        return menuItemList;
    }

    private void initActionListening(IContextMenuInvocation contextMenuInvocation, JMenuItem scanConfigLevel_0,
                                     JMenuItem scanConfigLevel_1, JMenuItem scanConfigLevel_2,
                                     JMenuItem scanConfigLevel_3, JMenuItem scanConfigLevel_4) {
        IHttpRequestResponse[] httpRequestResponses = contextMenuInvocation.getSelectedMessages();

        scanConfigLevel_0.addActionListener(e -> {
            for (IHttpRequestResponse httpRequestResponse : httpRequestResponses) {
                String taskName = MyStringUtil.genTaskName();
                String scanTaskCommandLineStr = "-threads 5";
                if (!GlobalStaticsVar.DEFAULT_COMMAND_LINE_STR.trim().isEmpty()) {

                    scanTaskCommandLineStr = GlobalStaticsVar.DEFAULT_COMMAND_LINE_STR.trim();
                }

                try {
                    BurpExtender.startScanTask(taskName, scanTaskCommandLineStr, httpRequestResponse);
                } catch (IOException ex) {
                    BurpExtender.stderr.println(ex.getMessage());
                    throw new RuntimeException(ex);
                }
            }

        });

        scanConfigLevel_1.addActionListener(e -> {
            for (IHttpRequestResponse httpRequestResponse : httpRequestResponses) {
                ScanTaskConfigLevel1 scanTaskConfigLevel1 = new ScanTaskConfigLevel1(httpRequestResponse);
                scanTaskConfigLevel1.setVisible(true);
            }

        });

        scanConfigLevel_2.addActionListener(e -> {

            for (IHttpRequestResponse httpRequestResponse : httpRequestResponses) {
                ScanTaskConfigLevel2 scanTaskConfigLevel2 = new ScanTaskConfigLevel2(httpRequestResponse);
                scanTaskConfigLevel2.setScanTaskArgsList(BurpExtender.getScanTaskArgsListFromTaskArgPanel());
                scanTaskConfigLevel2.setVisible(true);
            }

        });

        scanConfigLevel_3.addActionListener(e -> {
            for (IHttpRequestResponse httpRequestResponse : httpRequestResponses) {
                ScanTaskConfigLevel3 scanTaskConfigLevel3 = new ScanTaskConfigLevel3(httpRequestResponse);
                scanTaskConfigLevel3.setScanTaskArgsList(BurpExtender.getScanTaskArgsListFromTaskArgPanel());
                scanTaskConfigLevel3.setVisible(true);
            }

        });

        scanConfigLevel_4.addActionListener(e -> {
            for (IHttpRequestResponse httpRequestResponse : httpRequestResponses) {
                ScanTaskConfigLevel4 scanTaskConfigLevel4 = new ScanTaskConfigLevel4(httpRequestResponse);
                scanTaskConfigLevel4.setScanTaskArgsList(BurpExtender.getScanTaskArgsListFromTaskArgPanel());
                scanTaskConfigLevel4.setVisible(true);
            }

        });
    }
}
