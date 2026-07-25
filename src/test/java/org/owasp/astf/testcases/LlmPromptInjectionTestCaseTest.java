package org.owasp.astf.testcases;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

@DisplayName("LLM Prompt Injection Test Case Tests")
class LlmPromptInjectionTestCaseTest {

    @Mock private HttpClient httpClient;
    private LlmPromptInjectionTestCase testCase;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testCase = new LlmPromptInjectionTestCase();
    }

    @Test
    @DisplayName("Should have correct metadata")
    void testMetadata() {
        assertEquals("ASTF-LLM-2023", testCase.getId());
        assertEquals("LLM Prompt Injection", testCase.getName());
        assertNotNull(testCase.getDescription());
    }

    @Test
    @DisplayName("Should detect prompt injection when the chatbot endpoint echoes the canary string")
    void testDetectsPromptInjection() throws IOException {
        // /api/chatbot/message — matches an LLM path pattern ("chatbot")
        EndpointInfo endpoint = new EndpointInfo("/api/chatbot/message", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200,
                        "{\"reply\":\"ASTF_PROMPT_INJECTION_CANARY_7f3a9c\"}",
                        Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect prompt injection when the canary is echoed");
        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Prompt Injection")));
        assertEquals(Severity.HIGH, findings.get(0).getSeverity());
    }

    @Test
    @DisplayName("Should NOT flag prompt injection when the endpoint doesn't comply with the injected instruction")
    void testNoInjectionWhenModelDoesNotComply() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/chatbot/message", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200,
                        "{\"reply\":\"I'm sorry, I can't help with that request.\"}",
                        Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not flag prompt injection when the canary is never echoed");
    }

    @Test
    @DisplayName("Should NOT test non-LLM-looking endpoints at all")
    void testSkipsNonLlmEndpoints() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "POST");

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not run prompt injection tests against a non-LLM-looking endpoint");
    }

    @Test
    @DisplayName("Should NOT test GET endpoints (no body to inject into)")
    void testSkipsGetEndpoints() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/chat/history", "GET");

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not run prompt injection tests against GET endpoints");
    }

    @Test
    @DisplayName("Should handle exceptions gracefully")
    void testExceptionHandledGracefully() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/assistant/ask", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenThrow(new IOException("Connection refused"));

        List<Finding> findings = assertDoesNotThrow(() -> testCase.execute(endpoint, httpClient));
        assertNotNull(findings);
    }
}
