package entities;

import static utils.GlobalStaticVariables.EX_MSG;

public class ScanTaskStatus {
    public static String NOT_STARTED = EX_MSG.getMsg("notStart");
    public static String RUNNING = EX_MSG.getMsg("scanning");
    public static String FINISHED = EX_MSG.getMsg("scanTaskFinished");

    public static String STOPPED = EX_MSG.getMsg("stopped");
    public static String KILLED = EX_MSG.getMsg("killed");
    public static String ERROR = EX_MSG.getMsg("unknownError");

    public static void updateI18n() {
        NOT_STARTED = EX_MSG.getMsg("notStart");
        RUNNING = EX_MSG.getMsg("scanning");
        FINISHED = EX_MSG.getMsg("scanTaskFinished");

        STOPPED = EX_MSG.getMsg("stopped");
        KILLED = EX_MSG.getMsg("killed");
        ERROR = EX_MSG.getMsg("unknownError");
    }
}
