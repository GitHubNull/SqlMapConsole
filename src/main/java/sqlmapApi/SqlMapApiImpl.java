package sqlmapApi;

import com.alibaba.fastjson2.JSON;
import okhttp3.*;
import sqlmapApi.requestsBody.ScanOptions;

public class SqlMapApiImpl implements SqlMapApi {
    String host;
    int port;

    final OkHttpClient client;
    String base_url;

    private final static MediaType JSON_TYPE = MediaType.get("application/json; charset=utf-8");


    public SqlMapApiImpl(String host, int port) {
        this.host = host;
        this.port = port;
        client = new OkHttpClient();
        base_url = String.format("http://%s:%d", host, port);
    }

    private String genApiUrl(String apiPath) {
        return String.format("%s%s", base_url, apiPath);
    }

    private Request buildRequest(String apiPath, String method, RequestBody requestBody) {
        String apiUrl = genApiUrl(apiPath);
        Request.Builder requestBuilder = new Request.Builder().url(apiUrl);
        requestBuilder.method(method, requestBody);
        return requestBuilder.build();
    }

    @Override
    public Call taskNew() {
        String apiPath = "/task/new";
//        String apiUrl = genApiUrl(apiPath);
//        Request.Builder requestBuilder = new Request.Builder().url(apiUrl);
//        requestBuilder.method("GET",null);
//        Request request = requestBuilder.build();
        return client.newCall(buildRequest(apiPath, "GET", null));
    }

    @Override
    public Call taskDelete(String taskId) {
        String apiPath = String.format("/task/%s/delete", taskId);
        return client.newCall(buildRequest(apiPath, "GET", null));
    }

    @Override
    public Call adminList() {
        String apiPath = "/admin/list";
        return client.newCall(buildRequest(apiPath, "GET", null));
    }

    @Override
    public Call adminFlush() {
        String apiPath = "/admin/flush";
        return client.newCall(buildRequest(apiPath, "GET", null));
    }

    @Override
    public Call scanStart(String taskId, ScanOptions scanOptions) {
        String apiPath = String.format("/scan/%s/start", taskId);
        String json = JSON.toJSONString(scanOptions);
        RequestBody requestBody = RequestBody.create(json, JSON_TYPE);
        return client.newCall(buildRequest(apiPath, "POST", requestBody));
    }

    @Override
    public Call scanStop(String taskId) {
        String apiPath = String.format("/scan/%s/stop", taskId);
        return client.newCall(buildRequest(apiPath, "GET", null));
    }

    @Override
    public Call scanKill(String taskId) {
        String apiPath = String.format("/scan/%s/kill", taskId);
        return client.newCall(buildRequest(apiPath, "GET", null));
    }

    @Override
    public Call scanStatus(String taskId) {
        String apiPath = String.format("/scan/%s/status", taskId);
        return client.newCall(buildRequest(apiPath, "GET", null));
    }

    @Override
    public Call scanData(String taskId) {
        String apiPath = String.format("/scan/%s/data", taskId);
        return client.newCall(buildRequest(apiPath, "GET", null));
    }

    @Override
    public Call scanLogRange(String taskId, int startIndex, int endIndex) {
        String apiPath = String.format("/scan/%s/log/%d/%d", taskId, startIndex, endIndex);
        return client.newCall(buildRequest(apiPath, "GET", null));
    }

    @Override
    public Call scanLog(String taskId) {
        String apiPath = String.format("/scan/%s/log", taskId);
        return client.newCall(buildRequest(apiPath, "GET", null));
    }

    @Override
    public Call optionList(String taskId) {
        String apiPath = String.format("/option/%/list", taskId);
        return client.newCall(buildRequest(apiPath, "GET", null));
    }

    @Override
    public Call optionGet(String taskId) {
        String apiPath = String.format("/option/%/get", taskId);
        return client.newCall(buildRequest(apiPath, "GET", null));
    }

    @Override
    public Call optionSet(String taskId) {
        String apiPath = String.format("/option/%/set", taskId);
        return client.newCall(buildRequest(apiPath, "GET", null));
    }
}
