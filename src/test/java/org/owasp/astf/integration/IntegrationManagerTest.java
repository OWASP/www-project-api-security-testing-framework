package org.owasp.astf.integration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.result.ScanResult;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("IntegrationManager Tests")
class IntegrationManagerTest {

    private IntegrationManager manager;

    @BeforeEach
    void setUp() {
        manager = new IntegrationManager();
    }

    @Test
    @DisplayName("Should register built-in integrations on construction")
    void testBuiltInIntegrations() {
        List<Integration> registered = manager.getRegisteredIntegrations();
        assertFalse(registered.isEmpty(), "Should have at least one built-in integration");
        assertTrue(registered.stream().anyMatch(i -> "GitHub Actions".equals(i.getName())),
                "Should include GitHub Actions integration");
    }

    @Test
    @DisplayName("Should register additional integrations")
    void testRegisterCustomIntegration() {
        Integration custom = new AlwaysAvailableIntegration("Custom");
        manager.registerIntegration(custom);

        assertTrue(manager.getRegisteredIntegrations().stream()
                        .anyMatch(i -> "Custom".equals(i.getName())),
                "Custom integration should be registered");
    }

    @Test
    @DisplayName("Should only return available integrations")
    void testGetAvailableIntegrations() {
        manager.registerIntegration(new AlwaysAvailableIntegration("Available1"));
        manager.registerIntegration(new NeverAvailableIntegration("Unavailable"));
        manager.registerIntegration(new AlwaysAvailableIntegration("Available2"));

        List<Integration> available = manager.getAvailableIntegrations();

        assertTrue(available.stream().allMatch(Integration::isAvailable),
                "All returned integrations should be available");
        assertFalse(available.stream().anyMatch(i -> "Unavailable".equals(i.getName())),
                "Unavailable integration should be excluded");
    }

    @Test
    @DisplayName("Should initialize only available integrations")
    void testInitializeAll() {
        AtomicBoolean availableInitialized = new AtomicBoolean(false);
        AtomicBoolean unavailableInitialized = new AtomicBoolean(false);

        manager.registerIntegration(new AlwaysAvailableIntegration("Track") {
            @Override
            public void initialize(ScanConfig config) { availableInitialized.set(true); }
        });
        manager.registerIntegration(new NeverAvailableIntegration("Skip") {
            @Override
            public void initialize(ScanConfig config) { unavailableInitialized.set(true); }
        });

        manager.initializeAll(new ScanConfig());

        assertTrue(availableInitialized.get(), "Available integration should be initialized");
        assertFalse(unavailableInitialized.get(), "Unavailable integration should NOT be initialized");
    }

    @Test
    @DisplayName("Should process results through all available integrations")
    void testProcessResults() {
        AtomicBoolean processed = new AtomicBoolean(false);
        manager.registerIntegration(new AlwaysAvailableIntegration("Processor") {
            @Override
            public void processResults(ScanResult result) { processed.set(true); }
        });

        manager.processResults(new ScanResult("https://example.com", List.of()));

        assertTrue(processed.get(), "Available integration should process results");
    }

    @Test
    @DisplayName("Should not throw when an integration's processResults throws")
    void testProcessResultsWithFailingIntegration() {
        manager.registerIntegration(new AlwaysAvailableIntegration("Faulty") {
            @Override
            public void processResults(ScanResult result) {
                throw new RuntimeException("Simulated failure");
            }
        });

        assertDoesNotThrow(() -> manager.processResults(
                new ScanResult("https://example.com", List.of())),
                "Manager should swallow integration exceptions");
    }

    @Test
    @DisplayName("getRegisteredIntegrations should return an unmodifiable view")
    void testRegisteredListIsUnmodifiable() {
        List<Integration> registered = manager.getRegisteredIntegrations();
        assertThrows(UnsupportedOperationException.class,
                () -> registered.add(new AlwaysAvailableIntegration("X")));
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static class AlwaysAvailableIntegration implements Integration {
        private final String name;
        AlwaysAvailableIntegration(String name) { this.name = name; }

        @Override public String getName() { return name; }
        @Override public boolean isAvailable() { return true; }
        @Override public void initialize(ScanConfig config) {}
        @Override public void processResults(ScanResult result) {}
    }

    private static class NeverAvailableIntegration implements Integration {
        private final String name;
        NeverAvailableIntegration(String name) { this.name = name; }

        @Override public String getName() { return name; }
        @Override public boolean isAvailable() { return false; }
        @Override public void initialize(ScanConfig config) {}
        @Override public void processResults(ScanResult result) {}
    }
}
