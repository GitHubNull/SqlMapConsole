package controller;

import burp.BurpExtender;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import ui.component.ScanTaskConfigLevel1;
import ui.component.ScanTaskConfigLevel2;
import ui.component.ScanTaskConfigLevel3;
import ui.component.ScanTaskConfigLevel4;
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

        JMenuItem scanConfigLevel0MenuItem = new JMenuItem("startSqlMapScanConfigLevel0");
        JMenuItem scanConfigLevel1MenuItem = new JMenuItem("startSqlMapScanConfigLevel1");
        JMenuItem scanConfigLevel2MenuItem = new JMenuItem("startSqlMapScanConfigLevel2");
        JMenuItem scanConfigLevel3MenuItem = new JMenuItem("startSqlMapScanConfigLevel3");
        JMenuItem scanConfigLevel4MenuItem = new JMenuItem("startSqlMapScanConfigLevel4");


        initActionListening(contextMenuInvocation, scanConfigLevel0MenuItem, scanConfigLevel1MenuItem,
                scanConfigLevel2MenuItem, scanConfigLevel3MenuItem, scanConfigLevel4MenuItem);


        menuItemList.add(scanConfigLevel0MenuItem);
        menuItemList.add(scanConfigLevel1MenuItem);
        menuItemList.add(scanConfigLevel2MenuItem);
        menuItemList.add(scanConfigLevel3MenuItem);
        menuItemList.add(scanConfigLevel4MenuItem);

        for (JMenuItem menuItem : menuItemList) {
            menuItem.setEnabled(!stopFlag);

            if (stopFlag) {
                menuItem.setText(menuItem.getText() + " [sqlmapApi已停止]");
            }
        }

        return menuItemList;
    }

    private void initActionListening(IContextMenuInvocation contextMenuInvocation, JMenuItem scanConfigLevel0MenuItem,
                                     JMenuItem scanConfigLevel1MenuItem, JMenuItem scanConfigLevel2MenuItem,
                                     JMenuItem scanConfigLevel3MenuItem, JMenuItem scanConfigLevel4MenuItem) {
        IHttpRequestResponse[] httpRequestResponses = contextMenuInvocation.getSelectedMessages();

        scanConfigLevel0MenuItem.addActionListener(e -> {
            // do something
//            BurpExtender.stdout.println("scanConfigLevel0MenuItem.addActionListener action trigger....");
            for (IHttpRequestResponse httpRequestResponse : httpRequestResponses) {
                String taskName = MyStringUtil.genTaskName();
                String scanTaskCommandLineStr = "-threads 5";
                try {
                    BurpExtender.startScanTask(taskName, scanTaskCommandLineStr, httpRequestResponse);
                } catch (IOException ex) {
                    BurpExtender.stderr.println(ex.getMessage());
//                    throw new RuntimeException(ex);
                }
            }

        });

        scanConfigLevel1MenuItem.addActionListener(e -> {
            for (IHttpRequestResponse httpRequestResponse : httpRequestResponses) {
                ScanTaskConfigLevel1 scanTaskConfigLevel1 = new ScanTaskConfigLevel1(httpRequestResponse);
                scanTaskConfigLevel1.setVisible(true);
            }

        });

        scanConfigLevel2MenuItem.addActionListener(e -> {

            for (IHttpRequestResponse httpRequestResponse : httpRequestResponses) {
                ScanTaskConfigLevel2 scanTaskConfigLevel2 = new ScanTaskConfigLevel2(httpRequestResponse);
                scanTaskConfigLevel2.setScanTaskArgsList(BurpExtender.getScanTaskArgsListFromTaskArgPanel());
                scanTaskConfigLevel2.setVisible(true);
            }

        });

        scanConfigLevel3MenuItem.addActionListener(e -> {
            for (IHttpRequestResponse httpRequestResponse : httpRequestResponses) {
                ScanTaskConfigLevel3 scanTaskConfigLevel3 = new ScanTaskConfigLevel3(httpRequestResponse);
                scanTaskConfigLevel3.setScanTaskArgsList(BurpExtender.getScanTaskArgsListFromTaskArgPanel());
                scanTaskConfigLevel3.setVisible(true);
            }

        });

        scanConfigLevel4MenuItem.addActionListener(e -> {
            for (IHttpRequestResponse httpRequestResponse : httpRequestResponses) {
                ScanTaskConfigLevel4 scanTaskConfigLevel4 = new ScanTaskConfigLevel4(httpRequestResponse);
                scanTaskConfigLevel4.setScanTaskArgsList(BurpExtender.getScanTaskArgsListFromTaskArgPanel());
                scanTaskConfigLevel4.setVisible(true);
            }

        });
    }
}
