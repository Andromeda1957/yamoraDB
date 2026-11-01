package io.yamora;

import java.util.Map;

/** One logical operation, including its complete accepted-response contract. */
interface RequestBoundary {
    HttpTransport.Response exchange(String method, String path, byte[] body, String media, String token,
            Map<String, String> headers, int maximum, boolean mutation, int... statuses) throws YamoraException;
}
