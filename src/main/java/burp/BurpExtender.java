package burp;

import controller.ContextMenuFactory;
import entities.ScanTask;
import entities.ScanTaskArgs;
import ui.panel.ConsoleTab;

import java.awt.*;
import java.io.PrintWriter;
import java.util.List;

public class BurpExtender implements IBurpExtender, ITab, IExtensionStateListener {
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static PrintWriter stdout;
    public static PrintWriter stderr;
    public final static String NAME = "SqlMapConsole";

    public static ConsoleTab consoleTab;


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        BurpExtender.callbacks = callbacks;
        helpers = callbacks.getHelpers();

        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);

        callbacks.setExtensionName(NAME);

        consoleTab = new ConsoleTab();

        callbacks.addSuiteTab(this);

//        ContextFactory contextFactory = new ContextFactory();
        callbacks.registerContextMenuFactory(new ContextMenuFactory());

    }

    @Override
    public String getTabCaption() {
        return NAME;
    }

    @Override
    public Component getUiComponent() {
        return consoleTab;
    }

    @Override
    public void extensionUnloaded() {
        stdout.println("extensionUnloaded...");
    }

    public static void addNewScanTask(ScanTask scanTask) {
        consoleTab.addNewScanTask(scanTask);
    }

    public static void addNewScanTask(IHttpRequestResponse httpRequestResponse, String name) {
        consoleTab.addNewScanTask(httpRequestResponse, name);
    }

    public static int getNewScanTaskId() {
        return consoleTab.getNewScanTaskId();
    }

    public static List<ScanTaskArgs> getScanTaskArgsList() {
        return consoleTab.getScanTaskArgsList();
    }
}
