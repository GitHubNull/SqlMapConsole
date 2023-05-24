package sqlmapApi.responsesBody;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ScanStatusResponse {
    String status;
    Integer returncode;
    Boolean success;
}
