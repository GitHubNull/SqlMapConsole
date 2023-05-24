package sqlmapApi;

import okhttp3.Call;
import sqlmapApi.requestsBody.ScanOptions;

public interface SqlMapApi {

    // new task
    // GET {{sqlmap_api}}/task/new
    public Call taskNew();

    // delete task
    // GET {{sqlmap_api}}/task/{{taskid}}/delete
    public Call taskDelete(String taskId);


    ////////////////////////////////////////////////////////////////////////////////
    // admin api
    ///////////////////////////////////////////////////////////////////////////////

    // admin list
    // GET {{sqlmap_api}}/admin/list
    public Call adminList();

    // admin flush
    // GET {{sqlmap_api}}/admin/flush
    public Call adminFlush();

    // scan task start
    // POST {{sqlmap_api}}/scan/{{taskid}}/start
    public Call scanStart(String taskId, ScanOptions scanOptions);

    // scan task stop
    // GET {{sqlmap_api}}/scan/{{taskid}}/stop
    public Call scanStop(String taskId);

    // scan task kill
    // GET {{sqlmap_api}}/scan/{{taskid}}/kill
    public Call scanKill(String taskId);

    // scan status
    // GET {{sqlmap_api}}/scan/{{taskid}}/status
    public Call scanStatus(String taskId);

    // scan data
    // GET {{sqlmap_api}}/scan/{{taskid}}/data
    public Call scanData(String taskId);

    // scan log range start and end
    // GET {{sqlmap_api}}/scan/{{taskid}}/log/1/6
    public Call scanLogRange(String taskId, int startIndex, int endIndex);

    // scan log all
    // GET {{sqlmap_api}}/scan/{{taskid}}/log
    public Call scanLog(String taskId);


    ////////////////////////////////////////////////////////////////
    // options apis
    ////////////////////////////////////////////////////////////////

    // option list
    // GET {{sqlmap_api}}/option/{{taskid}}/list
    public Call optionList(String taskId);

    // option get
    // POST {{sqlmap_api}}/option/{{taskid}}/get
    public Call optionGet(String taskId);


    // option set
    // POST {{sqlmap_api}}/option/{{taskid}}/set
    public Call optionSet(String taskId);
}
