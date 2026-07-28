package org.owasp.astf.core.config;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Manages configuration settings for the application and test cases.
 * Implements the Singleton pattern to provide a central configuration
 * repository.
 * Supports loading configurations from properties files, environment variables,
 * and programmatic settings.
 */
public class ConfigurationManager {
    private static final Logger logger = LogManager.getLogger(ConfigurationManager.class);

    // Singleton instance
    private static ConfigurationManager instance;

    // Thread-safe map for storing configuration properties
    private final ConcurrentHashMap<String, Object> configProperties;

    // Map for storing test-specific configurations
    private final ConcurrentHashMap<String, TestConfig> testConfigs;

    /**
     * Private constructor to enforce Singleton pattern
     */
    private ConfigurationManager() {
        configProperties = new ConcurrentHashMap<>();
        testConfigs = new ConcurrentHashMap<>();
        loadDefaultConfigurations();
    }

    /**
     * Get the singleton instance of ConfigurationManager
     * 
     * @return The ConfigurationManager instance
     */
    public static synchronized ConfigurationManager getInstance() {
        if (instance == null) {
            instance = new ConfigurationManager();
        }
        return instance;
    }

    /**
     * Load default configurations from various sources
     */
    private void loadDefaultConfigurations() {
        // Load from system properties
        loadSystemProperties();

        // Load from environment variables
        loadEnvironmentVariables();

        // Try to load from default configuration file if it exists
        loadConfigurationFile("config/application.properties");
    }

    /**
     * Load configuration properties from system properties
     */
    private void loadSystemProperties() {
        try {
            Properties systemProps = System.getProperties();
            for (String key : systemProps.stringPropertyNames()) {
                if (key.startsWith("owasp.astf.")) {
                    configProperties.put(key, systemProps.getProperty(key));
                }
            }
            logger.debug("Loaded system properties");
        } catch (Exception e) {
            logger.warn("Failed to load system properties: {}", e.getMessage());
        }
    }

    /**
     * Load configuration from environment variables
     * This converts environment variables like OWASP_ASTF_PROPERTY_NAME to
     * owasp.astf.propertyName
     */
    private void loadEnvironmentVariables() {
        try {
            Map<String, String> envVars = System.getenv();
            for (Map.Entry<String, String> entry : envVars.entrySet()) {
                String key = entry.getKey();
                if (key.startsWith("OWASP_ASTF_")) {
                    // Convert OWASP_ASTF_PROPERTY_NAME to owasp.astf.propertyName
                    String configKey = "owasp.astf." + convertEnvironmentVarToProperty(key.substring(11));
                    configProperties.put(configKey, entry.getValue());
                }
            }
            logger.debug("Loaded environment variables");
        } catch (Exception e) {
            logger.warn("Failed to load environment variables: {}", e.getMessage());
        }
    }

    /**
     * Convert an environment variable name format to a property format
     * Example: PROPERTY_NAME -> propertyName
     * 
     * @param envVar The environment variable name without the OWASP_ASTF_ prefix
     * @return The converted property key
     */
    private String convertEnvironmentVarToProperty(String envVar) {
        StringBuilder result = new StringBuilder();
        String[] parts = envVar.toLowerCase().split("_");

        for (int i = 0; i < parts.length; i++) {
            if (i == 0) {
                result.append(parts[i]);
            } else {
                result.append(parts[i].substring(0, 1).toUpperCase());
                result.append(parts[i].substring(1));
            }
        }

        return result.toString();
    }

    /**
     * Load configuration from a properties file
     * 
     * @param filePath Path to the properties file
     * @return true if loaded successfully, false otherwise
     */
    public boolean loadConfigurationFile(String filePath) {
        Path path = Paths.get(filePath);
        if (!Files.exists(path)) {
            logger.debug("Configuration file not found: {}", filePath);
            return false;
        }

        Properties props = new Properties();
        try (InputStream is = new FileInputStream(path.toFile())) {
            props.load(is);
            for (String key : props.stringPropertyNames()) {
                configProperties.put(key, props.getProperty(key));
            }
            logger.info("Loaded configuration from file: {}", filePath);
            return true;
        } catch (IOException e) {
            logger.warn("Failed to load configuration file {}: {}", filePath, e.getMessage());
            return false;
        }
    }

    /**
     * Get a string property value
     * 
     * @param key The property key
     * @return The property value or null if not found
     */
    public String getProperty(String key) {
        Object value = configProperties.get(key);
        return value != null ? value.toString() : null;
    }

    /**
     * Get a string property value with a default fallback
     * 
     * @param key          The property key
     * @param defaultValue The default value to return if key is not found
     * @return The property value or defaultValue if not found
     */
    public String getProperty(String key, String defaultValue) {
        Object value = configProperties.get(key);
        return value != null ? value.toString() : defaultValue;
    }

    /**
     * Get an integer property value
     * 
     * @param key          The property key
     * @param defaultValue The default value to return if key is not found or not an
     *                     integer
     * @return The integer value or defaultValue if not found or not convertible to
     *         int
     */
    public int getIntProperty(String key, int defaultValue) {
        Object value = configProperties.get(key);
        if (value == null) {
            return defaultValue;
        }

        if (value instanceof Number) {
            return ((Number) value).intValue();
        }

        try {
            return Integer.parseInt(value.toString());
        } catch (NumberFormatException e) {
            logger.warn("Failed to parse integer property {}: {}", key, value);
            return defaultValue;
        }
    }

    /**
     * Get a boolean property value
     * 
     * @param key          The property key
     * @param defaultValue The default value to return if key is not found
     * @return The boolean value or defaultValue if not found
     */
    public boolean getBooleanProperty(String key, boolean defaultValue) {
        Object value = configProperties.get(key);
        if (value == null) {
            return defaultValue;
        }

        if (value instanceof Boolean) {
            return (Boolean) value;
        }

        String stringValue = value.toString().toLowerCase();
        return "true".equals(stringValue) || "yes".equals(stringValue) || "1".equals(stringValue);
    }

    /**
     * Get a double property value
     * 
     * @param key          The property key
     * @param defaultValue The default value to return if key is not found
     * @return The double value or defaultValue if not found
     */
    public double getDoubleProperty(String key, double defaultValue) {
        Object value = configProperties.get(key);
        if (value == null) {
            return defaultValue;
        }

        if (value instanceof Number) {
            return ((Number) value).doubleValue();
        }

        try {
            return Double.parseDouble(value.toString());
        } catch (NumberFormatException e) {
            logger.warn("Failed to parse double property {}: {}", key, value);
            return defaultValue;
        }
    }

    /**
     * Set a configuration property
     * 
     * @param key   The property key
     * @param value The property value
     */
    public void setProperty(String key, Object value) {
        if (value == null) {
            configProperties.remove(key);
        } else {
            configProperties.put(key, value);
        }
    }

    /**
     * Check if a property exists
     * 
     * @param key The property key
     * @return true if property exists, false otherwise
     */
    public boolean hasProperty(String key) {
        return configProperties.containsKey(key);
    }

    /**
     * Get all properties starting with a prefix
     * 
     * @param prefix The prefix to filter properties
     * @return A map of properties with the given prefix
     */
    public Map<String, Object> getPropertiesWithPrefix(String prefix) {
        Map<String, Object> result = new HashMap<>();
        for (Map.Entry<String, Object> entry : configProperties.entrySet()) {
            if (entry.getKey().startsWith(prefix)) {
                result.put(entry.getKey(), entry.getValue());
            }
        }
        return result;
    }

    /**
     * Register a test configuration
     * 
     * @param testId The test ID
     * @param config The test configuration
     */
    public void registerTestConfig(String testId, TestConfig config) {
        testConfigs.put(testId, config);
    }

    /**
     * Get a test configuration
     * 
     * @param testId The test ID
     * @return The test configuration or null if not found
     */
    public TestConfig getTestConfig(String testId) {
        return testConfigs.get(testId);
    }

    /**
     * Create a new test configuration for a test ID
     * 
     * @param testId The test ID
     * @param name   The configuration name
     * @return The created test configuration
     */
    public TestConfig createTestConfig(String testId, String name) {
        TestConfig config = new TestConfig(name);
        registerTestConfig(testId, config);
        return config;
    }

    /**
     * Create a new test configuration for a test ID
     * 
     * @param testId      The test ID
     * @param name        The configuration name
     * @param description The configuration description
     * @return The created test configuration
     */
    public TestConfig createTestConfig(String testId, String name, String description) {
        TestConfig config = new TestConfig(name, description);
        registerTestConfig(testId, config);
        return config;
    }

    /**
     * Remove a test configuration
     * 
     * @param testId The test ID
     * @return The removed test configuration or null if not found
     */
    public TestConfig removeTestConfig(String testId) {
        return testConfigs.remove(testId);
    }

    /**
     * Reset the configuration manager (clear all properties and test configs)
     * This is mainly useful for testing purposes
     */
    public void reset() {
        configProperties.clear();
        testConfigs.clear();
        loadDefaultConfigurations();
    }
}