package utils;

import burp.BurpExtender;
import entities.ScanTaskStatus;
import entities.TaskId2TaskIndexMap;
import entities.TaskItem;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import sqlmapApi.requestsBody.ScanOptions;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class GlobalStaticVariables {
    public final static String SQLMAP_API_HOST = "127.0.0.1"; // sqlmap_api_host
    public static int SQLMAP_API_PORT = 5678; // sqlmap_api_port
    public static String PYTHON_EXEC_PATH = "E:/dev-tools/python/Python39/python.exe"; // python_exec_path
    public static String SQLMAP_API_PATH = "E:/myProcgram/sqlmap/sqlmap-1.7/sqlmapapi.py"; // sqlmap_api_path

    public static String TMP_REQUEST_FILE_DIR_PATH = "E:/tmp"; // tmp_Request_File_dir_Path

    public static Queue<TaskId2TaskIndexMap> TASK_ID_INDEX_MAP_QUEUE = new ConcurrentLinkedQueue<>(); // task_id_index_map_queue

    public static Queue<TaskItem> SCAN_TASK_QUEUE = new ConcurrentLinkedQueue<>();
    public final static int SCAN_TASK_QUEUE_MAX_SIZE = 5;
    public final static Map<String, String> STR_TO_SCAN_TASK_STATUS_MAP = new HashMap<>(); // str_to_scan_task_status_map

    public static final String COMMIT_ACTION = "commit"; // commit_action
    public final static List<String> SCAN_OPTIONS_KEYWORDS = new ArrayList<>(); // scan_options_keywords
    public static Options SCAN_OPTIONS_PARSER_DATA = new Options(); // scan_options_parser_data

    public static boolean SQLMAPAPI_SERVICE_STOP_FLAG = true; // sqlmapapi_service_stop_flag
    public static ReentrantReadWriteLock SQLMAPAPI_SERVICE_STOP_FLAG_LOCK = new ReentrantReadWriteLock(); // sqlmapapi_service_stop_flag_lock

    public static ReentrantReadWriteLock OLD_SQLMAPAPI_SUB_PROCESS_KILLED_LOCK = new ReentrantReadWriteLock();
    public static boolean OLD_SQLMAPAPI_SUB_PROCESS_KILLED = false; // old sqlmapapi sub process killed
    public final static String SCAN_OPTIONS_HELP_TEXT = MyStringUtil.genScanOptionsHelpText();  // scan_options_help_text

    public final static String EXTENDER_CONFIG_SEPARATOR = "/";

    public final static String COMMAND_LINES_STR_VAR = "command_lines_str";
    public static String DEFAULT_COMMAND_LINE_STR = "-threads 5"; // default_command_line_str
    public static MessageUtil EX_MSG = new MessageUtil();

    static {
        STR_TO_SCAN_TASK_STATUS_MAP.put("not running", ScanTaskStatus.NOT_STARTED);
        STR_TO_SCAN_TASK_STATUS_MAP.put("running", ScanTaskStatus.RUNNING);
        STR_TO_SCAN_TASK_STATUS_MAP.put("terminated", ScanTaskStatus.FINISHED);

        STR_TO_SCAN_TASK_STATUS_MAP.put("stopped", ScanTaskStatus.STOPPED);
        STR_TO_SCAN_TASK_STATUS_MAP.put("killed", ScanTaskStatus.KILLED);
        STR_TO_SCAN_TASK_STATUS_MAP.put("unknownError", ScanTaskStatus.ERROR);

//        SCAN_OPTIONS = new Options();

        ScanOptions scanOptions = new ScanOptions();
        //获取实体类 返回的是一个数组 数组的数据就是实体类中的字段
        Field[] fields = scanOptions.getClass().getDeclaredFields();
        for (Field field : fields) {
            //有的字段是用private修饰的 将他设置为可读
            field.setAccessible(true);
            // 输出属性名和属性值
            String fieldName = field.getName();

            Option tmpOption = Option.builder().longOpt(fieldName)
                    .argName(fieldName)
                    .hasArg()
                    .type(field.getType())
                    .build();
            SCAN_OPTIONS_PARSER_DATA.addOption(tmpOption);

            Class<?> classes = field.getType();

            String firstLetter = fieldName.substring(0, 1).toUpperCase();
            String getter = "get" + firstLetter + fieldName.substring(1);

            Object value;
            try {
                Method method = scanOptions.getClass().getMethod(getter);
                value = method.invoke(scanOptions);
            } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException exception) {
                BurpExtender.stderr.println(exception.getMessage());
                continue;
            }

            String keyWord = fieldName;

            if (classes.equals(String.class) && null != value) {
                keyWord = String.format("%s %s", fieldName, value);
            } else if (classes.equals(Boolean.class) && null != value) {
                keyWord = String.format("%s %b", fieldName, value);
            } else if (classes.equals(Integer.class) && null != value) {
                keyWord = String.format("%s %d", fieldName, (Integer) value);
            }

            SCAN_OPTIONS_KEYWORDS.add(keyWord);
        }
    }


}
