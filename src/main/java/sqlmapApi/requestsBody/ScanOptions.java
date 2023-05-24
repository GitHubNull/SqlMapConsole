package sqlmapApi.requestsBody;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ScanOptions {
    private String direct;
    private String url;
    private String logFile;
    private String bulkFile;
    private String requestFile;
    private String sessionFile;
    private String googleDork;
    private String configFile;
    private String method;
    private String data;
    private String paramDel;
    private String cookie;
    private String cookieDel;
    private String liveCookies;
    private String loadCookies;

    @Builder.Default
    private Boolean dropSetCookie = false; // default value false

    private String agent;

    @Builder.Default
    private Boolean mobile = false; // default value false


    @Builder.Default
    private Boolean randomAgent = false; // default value false

    private String host;
    private String referer;
    private String headers;
    private String authType;
    private String authCred;
    private String authFile;
    private String ignoreCode;

    @Builder.Default
    private Boolean ignoreProxy = false; // default value false


    @Builder.Default
    private Boolean ignoreRedirects = false; // default value false


    @Builder.Default
    private Boolean ignoreTimeouts = false; // default value false

    private String proxy;
    private String proxyCred;
    private String proxyFile;
    private String proxyFreq;

    @Builder.Default
    private Boolean tor = false; // default value false

    private String torPort;

    @Builder.Default
    private String torType = "SOCKS5"; // default value SOCKS5


    @Builder.Default
    private Boolean checkTor = false; // default value false


    @Builder.Default
    private Integer delay = 0; // default value 0


    @Builder.Default
    private Integer timeout = 30; // default value 30


    @Builder.Default
    private Integer retries = 3; // default value 3

    private String retryOn;
    private String rParam;
    private String safeUrl;
    private String safePost;
    private String safeReqFile;

    @Builder.Default
    private Integer safeFreq = 0; // default value 0


    @Builder.Default
    private Boolean skipUrlEncode = false; // default value false

    private String csrfToken;
    private String csrfUrl;
    private String csrfMethod;
    private String csrfData;

    @Builder.Default
    private Integer csrfRetries = 0; // default value 0


    @Builder.Default
    private Boolean forceSSL = false; // default value false


    @Builder.Default
    private Boolean chunked = false; // default value false


    @Builder.Default
    private Boolean hpp = false; // default value false

    private String evalCode;

    @Builder.Default
    private Boolean optimize = false; // default value false


    @Builder.Default
    private Boolean predictOutput = false; // default value false


    @Builder.Default
    private Boolean keepAlive = false; // default value false


    @Builder.Default
    private Boolean nullConnection = false; // default value false


    @Builder.Default
    private Integer threads = 1; // default value 1

    private String testParameter;
    private String skip;

    @Builder.Default
    private Boolean skipStatic = false; // default value false

    private String paramExclude;
    private String paramFilter;
    private String dbms;
    private String dbmsCred;
    private String os;

    @Builder.Default
    private Boolean invalidBignum = false; // default value false


    @Builder.Default
    private Boolean invalidLogical = false; // default value false


    @Builder.Default
    private Boolean invalidString = false; // default value false


    @Builder.Default
    private Boolean noCast = false; // default value false


    @Builder.Default
    private Boolean noEscape = false; // default value false

    private String prefix;
    private String suffix;
    private String tamper;

    @Builder.Default
    private Integer level = 1; // default value 1


    @Builder.Default
    private Integer risk = 1; // default value 1

    private String string;
    private String notString;
    private String regexp;
    private String code;

    @Builder.Default
    private Boolean smart = false; // default value false


    @Builder.Default
    private Boolean textOnly = false; // default value false


    @Builder.Default
    private Boolean titles = false; // default value false


    @Builder.Default
    private String technique = "BEUSTQ"; // default value BEUSTQ


    @Builder.Default
    private Integer timeSec = 5; // default value 5

    private String uCols;
    private String uChar;
    private String uFrom;
    private String dnsDomain;
    private String secondUrl;
    private String secondReq;

    @Builder.Default
    private Boolean extensiveFp = false; // default value false


    @Builder.Default
    private Boolean getAll = false; // default value false


    @Builder.Default
    private Boolean getBanner = false; // default value false


    @Builder.Default
    private Boolean getCurrentUser = false; // default value false


    @Builder.Default
    private Boolean getCurrentDb = false; // default value false


    @Builder.Default
    private Boolean getHostname = false; // default value false


    @Builder.Default
    private Boolean isDba = false; // default value false


    @Builder.Default
    private Boolean getUsers = false; // default value false


    @Builder.Default
    private Boolean getPasswordHashes = false; // default value false


    @Builder.Default
    private Boolean getPrivileges = false; // default value false


    @Builder.Default
    private Boolean getRoles = false; // default value false


    @Builder.Default
    private Boolean getDbs = false; // default value false


    @Builder.Default
    private Boolean getTables = false; // default value false


    @Builder.Default
    private Boolean getColumns = false; // default value false


    @Builder.Default
    private Boolean getSchema = false; // default value false


    @Builder.Default
    private Boolean getCount = false; // default value false


    @Builder.Default
    private Boolean dumpTable = false; // default value false


    @Builder.Default
    private Boolean dumpAll = false; // default value false


    @Builder.Default
    private Boolean search = false; // default value false


    @Builder.Default
    private Boolean getComments = false; // default value false


    @Builder.Default
    private Boolean getStatements = false; // default value false

    private String db;
    private String tbl;
    private String col;
    private String exclude;
    private String pivotColumn;
    private String dumpWhere;
    private String user;

    @Builder.Default
    private Boolean excludeSysDbs = false; // default value false

    private String limitStart;
    private String limitStop;
    private String firstChar;
    private String lastChar;
    private String sqlQuery;

//    @Builder.Default
//    private Boolean sqlShell = false; // default value false

    private String sqlFile;

    @Builder.Default
    private Boolean commonTables = false; // default value false


    @Builder.Default
    private Boolean commonColumns = false; // default value false


    @Builder.Default
    private Boolean commonFiles = false; // default value false


    @Builder.Default
    private Boolean udfInject = false; // default value false

    private String shLib;
    private String fileRead;
    private String fileWrite;
    private String fileDest;
    private String osCmd;

    @Builder.Default
    private Boolean osShell = false; // default value false


    @Builder.Default
    private Boolean osPwn = false; // default value false


    @Builder.Default
    private Boolean osSmb = false; // default value false


    @Builder.Default
    private Boolean osBof = false; // default value false


    @Builder.Default
    private Boolean privEsc = false; // default value false

    private String msfPath;
    private String tmpPath;

    @Builder.Default
    private Boolean regRead = false; // default value false


    @Builder.Default
    private Boolean regAdd = false; // default value false


    @Builder.Default
    private Boolean regDel = false; // default value false

    private String regKey;
    private String regVal;
    private String regData;
    private String regType;
    private String trafficFile;
    private String answers;

    @Builder.Default
    private Boolean batch = true; // default value true

    private String base64Parameter;

    @Builder.Default
    private Boolean base64Safe = false; // default value false

    private String binaryFields;
    private String charset;

    @Builder.Default
    private Boolean checkInternet = false; // default value false


    @Builder.Default
    private Boolean cleanup = false; // default value false

    private String crawlDepth;
    private String crawlExclude;

    @Builder.Default
    private String csvDel = ","; // default value ,

    private String dumpFile;

    @Builder.Default
    private String dumpFormat = "CSV"; // default value CSV

    private String encoding;

    @Builder.Default
    private Boolean eta = false; // default value false


    @Builder.Default
    private Boolean flushSession = false; // default value false


    @Builder.Default
    private Boolean forms = false; // default value false


    @Builder.Default
    private Boolean freshQueries = false; // default value false


    @Builder.Default
    private Integer googlePage = 1; // default value 1

    private String harFile;

    @Builder.Default
    private Boolean hexConvert = false; // default value false

    private String outputDir;

    @Builder.Default
    private Boolean parseErrors = false; // default value false

    private String postprocess;
    private String preprocess;

    @Builder.Default
    private Boolean repair = false; // default value false

    private String saveConfig;
    private String scope;

    @Builder.Default
    private Boolean skipHeuristics = false; // default value false


    @Builder.Default
    private Boolean skipWaf = false; // default value false

    private String testFilter;
    private String testSkip;
    private String webRoot;
    private String alert;

    @Builder.Default
    private Boolean beep = false; // default value false


    @Builder.Default
    private Boolean dependencies = false; // default value false


    @Builder.Default
    private Boolean disableColoring = true; // default value true


    @Builder.Default
    private Boolean listTampers = false; // default value false


    @Builder.Default
    private Boolean noLogging = false; // default value false


    @Builder.Default
    private Boolean offline = false; // default value false


    @Builder.Default
    private Boolean purge = false; // default value false

    private String resultsFile;
    private String tmpDir;

    @Builder.Default
    private Boolean unstable = false; // default value false


    @Builder.Default
    private Boolean updateAll = false; // default value false


//    @Builder.Default
//    private Boolean wizard = false; // default value false


    @Builder.Default
    private Integer verbose = 1; // default value 1


    @Builder.Default
    private Boolean dummy = false; // default value false


    @Builder.Default
    private Boolean disablePrecon = false; // default value false


    @Builder.Default
    private Boolean profile = false; // default value false


    @Builder.Default
    private Boolean forceDns = false; // default value false

    private String murphyRate;

    @Builder.Default
    private Boolean smokeTest = false; // default value false


    @Builder.Default
    private Boolean api = true; // default value true


    @Builder.Default
    private String taskid = "b65dd9496ba03e0c"; // default value b65dd9496ba03e0c


    @Builder.Default
    private String database = "C:\\Users\\wangg\\AppData\\Local\\Temp\\sqlmapipc-4_tty95h"; // default value C:\Users\wangg\AppData\Local\Temp\sqlmapipc-4_tty95h


}
