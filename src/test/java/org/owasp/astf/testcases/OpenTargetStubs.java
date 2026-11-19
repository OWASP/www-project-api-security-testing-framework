package org.owasp.astf.testcases;

import java.util.Map;

import org.owasp.astf.core.http.HttpClient;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * For mock-based tests that model a target which answers the same with or without credentials:
 * makes the mocked client's no-credential request methods return whatever the test stubbed for
 * the matching credentialed method. Call it after stubbing the credentialed methods.
 */
final class OpenTargetStubs {

    private OpenTargetStubs() { }

    static void answerNoAuthLikeCredentialed(HttpClient httpClient) throws java.io.IOException {
        when(httpClient.getWithStatusNoAuth(anyString()))
                .thenAnswer(inv -> httpClient.getWithStatus(inv.getArgument(0), Map.of()));
        when(httpClient.getNoAuth(anyString()))
                .thenAnswer(inv -> httpClient.get(inv.getArgument(0), Map.of()));
        when(httpClient.postWithStatusNoAuth(anyString(), any(), any()))
                .thenAnswer(inv -> httpClient.postWithStatus(inv.getArgument(0), Map.of(),
                        inv.getArgument(1), inv.getArgument(2)));
        when(httpClient.putWithStatusNoAuth(anyString(), any(), any()))
                .thenAnswer(inv -> httpClient.putWithStatus(inv.getArgument(0), Map.of(),
                        inv.getArgument(1), inv.getArgument(2)));
        when(httpClient.patchWithStatusNoAuth(anyString(), any(), any()))
                .thenAnswer(inv -> httpClient.patchWithStatus(inv.getArgument(0), Map.of(),
                        inv.getArgument(1), inv.getArgument(2)));
        when(httpClient.deleteWithStatusNoAuth(anyString()))
                .thenAnswer(inv -> httpClient.deleteWithStatus(inv.getArgument(0), Map.of()));
        when(httpClient.sendWithStatusNoAuth(anyString(), anyString(), any(), any()))
                .thenAnswer(inv -> {
                    String method = inv.getArgument(0);
                    String url = inv.getArgument(1);
                    String contentType = inv.getArgument(2);
                    String body = inv.getArgument(3);
                    return switch (method) {
                        case "POST" -> httpClient.postWithStatus(url, Map.of(), contentType, body);
                        case "PUT" -> httpClient.putWithStatus(url, Map.of(), contentType, body);
                        case "PATCH" -> httpClient.patchWithStatus(url, Map.of(), contentType, body);
                        case "DELETE" -> httpClient.deleteWithStatus(url, Map.of());
                        default -> httpClient.getWithStatus(url, Map.of());
                    };
                });
    }
}
