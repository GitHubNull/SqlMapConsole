package entities;

import static utils.GlobalStaticVariables.EX_MSG;

public class InjectionStatus {
    public static String ENABLE_INJECT = EX_MSG.getMsg("enableInject"); // enableInject
    public static String DISABLE_INJECT = EX_MSG.getMsg("disableInject"); // disableInject
    public static String NOT_SURE = EX_MSG.getMsg("notSure"); // notSure

    public static void updateI18n() {
        ENABLE_INJECT = EX_MSG.getMsg("enableInject"); // enableInject
        DISABLE_INJECT = EX_MSG.getMsg("disableInject"); // disableInject
        NOT_SURE = EX_MSG.getMsg("notSure"); // notSure
    }
}
