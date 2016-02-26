package dk.magenta.mox.agent.messages;

import dk.magenta.mox.agent.MessageInterface;
import dk.magenta.mox.agent.ParameterMap;
import dk.magenta.mox.json.JSONObject;

/**
 * Created by lars on 15-02-16.
 */
public class SearchDocumentMessage extends DocumentMessage {

    protected ParameterMap<String, String> query;

    public SearchDocumentMessage(String authorization, String objectType, ParameterMap<String, String> query) {
        super(authorization, objectType);
        this.query = query;
    }

    @Override
    public JSONObject getJSON() {
        return new JSONObject(this.query.toJSON());
    }

    @Override
    protected String getOperationName() {
        return DocumentMessage.OPERATION_SEARCH;
    }

    public static SearchDocumentMessage parse(Headers headers, JSONObject data) {
        String operationName = headers.optString(MessageInterface.HEADER_OPERATION);
        if ("search".equalsIgnoreCase(operationName)) {
            String authorization = headers.optString(MessageInterface.HEADER_AUTHORIZATION);
            String objectType = headers.optString(Message.HEADER_OBJECTTYPE);
            if (objectType != null) {
                ParameterMap<String, String> query = new ParameterMap<>();
                query.populateFromJSON(data);
                return new SearchDocumentMessage(authorization, objectType, query);
            }
        }
        return null;
    }
}
