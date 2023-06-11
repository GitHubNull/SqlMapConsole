package entities;

import static utils.GlobalStaticVariables.EX_MSG;

public final class CommandLineColumnName {
    public static String ID = EX_MSG.getMsg("index");
    public static String WAS_DEFAULT = EX_MSG.getMsg("wasDefault");
    public static String TAG = EX_MSG.getMsg("tag");

    public static String COMMAND_LINE = EX_MSG.getMsg("commandLine");

    public static void updateI18n() {
        ID = EX_MSG.getMsg("index");
        WAS_DEFAULT = EX_MSG.getMsg("wasDefault");
        TAG = EX_MSG.getMsg("tag");

        COMMAND_LINE = EX_MSG.getMsg("commandLine");
    }
}
