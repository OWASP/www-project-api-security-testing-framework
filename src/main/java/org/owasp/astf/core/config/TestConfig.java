package org.owasp.astf.core.config;

import java.util.HashMap;
import java.util.Map;

/**
 * Configuration class for test cases.
 * Contains settings and parameters that can be adjusted for each test
 * execution.
 * This allows for flexible configuration of test parameters without modifying
 * test case code.
 */
public class TestConfig {
    private final Map<String, Object> parameters;
    private String name;
    private String description;

    /**
     * Create a new TestConfig instance
     */
    public TestConfig() {
        this.parameters = new HashMap<>();
    }

    /**
     * Create a new TestConfig instance with the given name
     * 
     * @param name The name of this test configuration
     */
    public TestConfig(String name) {
        this.parameters = new HashMap<>();
        this.name = name;
    }

    /**
     * Create a new TestConfig instance with the given name and description
     * 
     * @param name        The name of this test configuration
     * @param description A description of this test configuration
     */
    public TestConfig(String name, String description) {
        this.parameters = new HashMap<>();
        this.name = name;
        this.description = description;
    }

    /**
     * Set a string parameter value
     * 
     * @param key   The parameter key
     * @param value The string value
     * @return This TestConfig instance for chaining
     */
    public TestConfig setString(String key, String value) {
        parameters.put(key, value);
        return this;
    }

    /**
     * Set an integer parameter value
     * 
     * @param key   The parameter key
     * @param value The integer value
     * @return This TestConfig instance for chaining
     */
    public TestConfig setInt(String key, int value) {
        parameters.put(key, value);
        return this;
    }

    /**
     * Set a boolean parameter value
     * 
     * @param key   The parameter key
     * @param value The boolean value
     * @return This TestConfig instance for chaining
     */
    public TestConfig setBoolean(String key, boolean value) {
        parameters.put(key, value);
        return this;
    }

    /**
     * Set a double parameter value
     * 
     * @param key   The parameter key
     * @param value The double value
     * @return This TestConfig instance for chaining
     */
    public TestConfig setDouble(String key, double value) {
        parameters.put(key, value);
        return this;
    }

    /**
     * Get a string parameter value
     * 
     * @param key The parameter key
     * @return The string value or null if not found
     */
    public String getString(String key) {
        Object value = parameters.get(key);
        return value != null ? value.toString() : null;
    }

    /**
     * Get a string parameter value with a default fallback
     * 
     * @param key          The parameter key
     * @param defaultValue The default value to return if key is not found
     * @return The string value or defaultValue if not found
     */
    public String getString(String key, String defaultValue) {
        Object value = parameters.get(key);
        return value != null ? value.toString() : defaultValue;
    }

    /**
     * Get an integer parameter value
     * 
     * @param key          The parameter key
     * @param defaultValue The default value to return if key is not found or not an
     *                     integer
     * @return The integer value or defaultValue if not found or not convertible to
     *         int
     */
    public int getInt(String key, int defaultValue) {
        Object value = parameters.get(key);
        if (value == null) {
            return defaultValue;
        }

        if (value instanceof Number) {
            return ((Number) value).intValue();
        }

        try {
            return Integer.parseInt(value.toString());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Get a boolean parameter value
     * 
     * @param key          The parameter key
     * @param defaultValue The default value to return if key is not found
     * @return The boolean value or defaultValue if not found
     */
    public boolean getBoolean(String key, boolean defaultValue) {
        Object value = parameters.get(key);
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
     * Get a double parameter value
     * 
     * @param key          The parameter key
     * @param defaultValue The default value to return if key is not found
     * @return The double value or defaultValue if not found
     */
    public double getDouble(String key, double defaultValue) {
        Object value = parameters.get(key);
        if (value == null) {
            return defaultValue;
        }

        if (value instanceof Number) {
            return ((Number) value).doubleValue();
        }

        try {
            return Double.parseDouble(value.toString());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Check if the config contains a parameter
     * 
     * @param key The parameter key
     * @return true if the parameter exists, false otherwise
     */
    public boolean hasParameter(String key) {
        return parameters.containsKey(key);
    }

    /**
     * Get the name of this test configuration
     * 
     * @return The name
     */
    public String getName() {
        return name;
    }

    /**
     * Set the name of this test configuration
     * 
     * @param name The name to set
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Get the description of this test configuration
     * 
     * @return The description
     */
    public String getDescription() {
        return description;
    }

    /**
     * Set the description of this test configuration
     * 
     * @param description The description to set
     */
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * Get all parameters as a map
     * 
     * @return The parameters map
     */
    public Map<String, Object> getAllParameters() {
        return new HashMap<>(parameters);
    }

    /**
     * Merge this configuration with another, with the other taking precedence
     * 
     * @param other The other configuration to merge with
     * @return A new TestConfig instance with merged parameters
     */
    public TestConfig merge(TestConfig other) {
        if (other == null) {
            return this;
        }

        TestConfig merged = new TestConfig(this.name, this.description);
        merged.parameters.putAll(this.parameters);
        merged.parameters.putAll(other.parameters);

        return merged;
    }
}