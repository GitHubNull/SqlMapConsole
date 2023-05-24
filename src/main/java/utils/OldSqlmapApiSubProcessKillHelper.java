package utils;

import static utils.GlobalStaticsVar.SQLMAP_API_PORT;

public class OldSqlmapApiSubProcessKillHelper {

    public static void kill() {
        if (OSinfo.isWindows()) {
//            System.out.println("OldSqlmapApiSubProcessKillHelper.kill() OSinfo.isWindows()");
            WindowsOSKiller windowsOSKiller = new WindowsOSKiller(SQLMAP_API_PORT);
            windowsOSKiller.kill();
        } else if (OSinfo.isMacOS()) {
            MacOSKiller macOSKiller = new MacOSKiller(SQLMAP_API_PORT);
            macOSKiller.kill();
        } else if (OSinfo.isLinux()) {
            LinuxOSKiller linuxOSKiller = new LinuxOSKiller(SQLMAP_API_PORT);
            linuxOSKiller.kill();
        }
    }

//    public static void main(String[] args) {
//        kill();
//    }
}
