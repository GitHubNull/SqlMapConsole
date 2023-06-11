package utils;


import java.util.HashSet;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Set;

public final class MessageUtil {

    private ResourceBundle bundle;
    private Locale locale;
    private final static Set<Locale> chineseLocalSet = new HashSet<>();

    static {
        chineseLocalSet.add(Locale.CHINESE);
        chineseLocalSet.add(Locale.CHINA);
        chineseLocalSet.add(Locale.SIMPLIFIED_CHINESE);
    }

    public MessageUtil() {
        bundle = ResourceBundle.getBundle("ExtenderMessages");
        locale = Locale.getDefault();

        if (!chineseLocalSet.contains(locale) && !Locale.US.equals(locale)) {
            locale = Locale.US;
        }
    }

    public MessageUtil(Locale locale) {
        bundle = ResourceBundle.getBundle("ExtenderMessages", locale);

        if (!chineseLocalSet.contains(locale) && !Locale.US.equals(locale)) {
            this.locale = Locale.US;
        } else {
            this.locale = locale;
        }

    }

    public Locale getLocale() {
        return locale;
    }

    public void setLocale(Locale argLocale) {
        locale = argLocale;
    }


    public String getMsg(String msgKey) {
        String result = "@value was null@";
        if (null == bundle) {
            return result;
        }

        result = bundle.getString(msgKey);
//        if (chineseLocalSet.contains(locale)){
//            try {
//                result = new String(bundle.getString(msgKey).getBytes("ISO-8859-1"), "UTF8");
//            } catch (UnsupportedEncodingException e) {
//                throw new RuntimeException(e);
//            }
//        }else {
//            result = bundle.getString(msgKey);
//        }

        return result;
    }

    public static boolean inChinese() {
        Locale locale1 = Locale.getDefault();
        return chineseLocalSet.contains(locale1);
    }

    public static boolean inChinese(Locale preLocale) {
        return chineseLocalSet.contains(preLocale);
    }
}
