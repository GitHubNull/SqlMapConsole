package sqlmapApi;

import okhttp3.Call;
import sqlmapApi.requestsBody.ScanOptions;

public interface SqlMapApi {

    // new task
    // GET {{sqlmap_api}}/task/new
    Call taskNew();

    // delete task
    // GET {{sqlmap_api}}/task/{{taskid}}/delete
    Call taskDelete(String taskId);


    ////////////////////////////////////////////////////////////////////////////////
    // admin api
    ///////////////////////////////////////////////////////////////////////////////

    // admin list
    // GET {{sqlmap_api}}/admin/list
    Call adminList();

    // admin flush
    // GET {{sqlmap_api}}/admin/flush
    Call adminFlush();

    // scan task start
    // POST {{sqlmap_api}}/scan/{{taskid}}/start
    Call scanStart(String taskId, ScanOptions scanOptions);

    // scan task stop
    // GET {{sqlmap_api}}/scan/{{taskid}}/stop
    Call scanStop(String taskId);

    // scan task kill
    // GET {{sqlmap_api}}/scan/{{taskid}}/kill
    Call scanKill(String taskId);

    // scan status
    // GET {{sqlmap_api}}/scan/{{taskid}}/status
    Call scanStatus(String taskId);

    // scan data
    // GET {{sqlmap_api}}/scan/{{taskid}}/data
    Call scanData(String taskId);

    // scan log range start and end
    // GET {{sqlmap_api}}/scan/{{taskid}}/log/1/6
    Call scanLogRange(String taskId, int startIndex, int endIndex);

    // scan log all
    // GET {{sqlmap_api}}/scan/{{taskid}}/log
    Call scanLog(String taskId);


    ////////////////////////////////////////////////////////////////
    // options apis
    ////////////////////////////////////////////////////////////////

    // option list
    // GET {{sqlmap_api}}/option/{{taskid}}/list
    Call optionList(String taskId);

    // option get
    // POST {{sqlmap_api}}/option/{{taskid}}/get
    Call optionGet(String taskId);


    // option set
    // POST {{sqlmap_api}}/option/{{taskid}}/set
    Call optionSet(String taskId);
}
