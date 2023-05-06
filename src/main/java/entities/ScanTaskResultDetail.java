package entities;

import lombok.Data;

import java.util.ArrayList;

@Data
public class ScanTaskResultDetail implements Comparable<ScanTaskResultDetail> {
    int id;
    ArrayList<String> payloads = new ArrayList<>();
    String scanResult;


    @Override
    public int compareTo(ScanTaskResultDetail o) {
        Integer id = this.getId();
        return id.compareTo(o.getId());
    }
}
