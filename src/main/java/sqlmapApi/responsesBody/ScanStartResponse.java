package sqlmapApi.responsesBody;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class ScanStartResponse {
    Integer engineid;
    Boolean success;
}
