package burp;

public class InteractionData {
    private String type;
    private String timestamp;
    private String clientIp;
    private int clientPort;
    private String id;
    private String fullId;
    private String payload;
    private String detail;
    private String fullDetail;
    private String rawRequest;
    private String rawResponse;

    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }
    public String getClientIp() { return clientIp; }
    public void setClientIp(String clientIp) { this.clientIp = clientIp; }
    public int getClientPort() { return clientPort; }
    public void setClientPort(int clientPort) { this.clientPort = clientPort; }
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getFullId() { return fullId; }
    public void setFullId(String fullId) { this.fullId = fullId; }
    public String getPayload() { return payload; }
    public void setPayload(String payload) { this.payload = payload; }
    public String getDetail() { return detail; }
    public void setDetail(String detail) { this.detail = detail; }
    public String getFullDetail() { return fullDetail; }
    public void setFullDetail(String fullDetail) { this.fullDetail = fullDetail; }
    public String getRawRequest() { return rawRequest; }
    public void setRawRequest(String rawRequest) { this.rawRequest = rawRequest; }
    public String getRawResponse() { return rawResponse; }
    public void setRawResponse(String rawResponse) { this.rawResponse = rawResponse; }
}
