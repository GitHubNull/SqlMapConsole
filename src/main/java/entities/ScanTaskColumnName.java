package entities;

import static utils.GlobalStaticVariables.EX_MSG;

public class ScanTaskColumnName {
    public static String ID = EX_MSG.getMsg("index"); // 0
    public static String TASK_ID = EX_MSG.getMsg("taskId"); // 1
    public static String NAME = EX_MSG.getMsg("taskName"); // 2
    public static String METHOD = EX_MSG.getMsg("method"); // 3
    public static String HOST = EX_MSG.getMsg("host"); // 4
    public static String PORT = EX_MSG.getMsg("port"); // 5
    public static String URL = EX_MSG.getMsg("url"); // 6
    public static String RESPONSE_STATUS_CODE = EX_MSG.getMsg("status_code"); // 7
    public static String RESPONSE_CONTENT_LENGTH = EX_MSG.getMsg("content_length"); // 8
    public static String CMD_LINE = EX_MSG.getMsg("commandLine"); //9
    public static String TASK_STATUS = EX_MSG.getMsg("task_status"); // 10
    public static String INJECT_STATUS = EX_MSG.getMsg("injectionStatus"); // 11
    public static String COMMENT = EX_MSG.getMsg("comment"); // 12

    public static void updateI18n() {
        ID = EX_MSG.getMsg("index"); // 0
        TASK_ID = EX_MSG.getMsg("taskId"); // 1
        NAME = EX_MSG.getMsg("taskName"); // 2
        METHOD = EX_MSG.getMsg("method"); // 3
        HOST = EX_MSG.getMsg("host"); // 4
        PORT = EX_MSG.getMsg("port"); // 5
        URL = EX_MSG.getMsg("url"); // 6
        RESPONSE_STATUS_CODE = EX_MSG.getMsg("status_code"); // 7
        RESPONSE_CONTENT_LENGTH = EX_MSG.getMsg("content_length"); // 8
        CMD_LINE = EX_MSG.getMsg("commandLine"); //9
        TASK_STATUS = EX_MSG.getMsg("task_status"); // 10
        INJECT_STATUS = EX_MSG.getMsg("injectionStatus"); // 11
        COMMENT = EX_MSG.getMsg("comment"); // 12
    }

}
