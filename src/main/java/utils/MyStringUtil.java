package utils;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.regex.Pattern;

public class MyStringUtil {
    public static boolean isPositiveInteger(String numberStr) {
        if (null == numberStr || numberStr.trim().isEmpty()) {
            return false;
        }

        Pattern pattern = Pattern.compile("[0-9]+");
        if (!pattern.matcher(numberStr).matches()) {
            return false;
        }

        if ("0".equals(numberStr.substring(0, 1))) {
            return false;
        }

        return true;

    }

    public static boolean isTruePortNumber(String portStr) {
        if (!isPositiveInteger(portStr)) {
            return false;
        }

        int number = Integer.parseInt(portStr);
        if (0 >= number || number >= 65535) {
            return false;
        }

        return true;
    }

    public static String getDateTimeStr(int type) {
        switch (type) {
            case 0:
                return LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
            case 1:
                return LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss"));
            default:
                return LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
        }

    }


    public static String genTaskName() {
        return String.format("task-%s", getDateTimeStr(0));
    }


//    public static void main(String[] args) {
//        String numberStr = "1234";
//        if (isTruePortNumber(numberStr)){
//            System.out.println("------------");;
//        }
//
//    }

}
