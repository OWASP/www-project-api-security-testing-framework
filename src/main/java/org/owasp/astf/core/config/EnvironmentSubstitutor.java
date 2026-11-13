package org.owasp.astf.core.config;

import java.io.IOException;
import java.util.Iterator;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;

/**
 * Replaces {@code $(VARIABLE)} placeholders in configuration values with the value of the
 * corresponding environment variable, so one config file can be reused across environments.
 * <p>
 * Rules:
 * <ul>
 *   <li>Only string values are substituted; keys are left untouched.</li>
 *   <li>A variable that is not set fails with an {@link IOException} naming the variable.
 *       Resolved values are never included in messages.</li>
 *   <li>A variable that is set to an empty string resolves to the empty string.</li>
 *   <li>{@code $$(NAME)} is an escape and yields the literal text {@code $(NAME)}.</li>
 *   <li>Resolved values are not scanned again, so a value containing {@code $(...)} is kept as-is.</li>
 * </ul>
 * </p>
 */
final class EnvironmentSubstitutor {

    /** Matches {@code $(NAME)} and the escaped form {@code $$(NAME)}. */
    private static final Pattern PLACEHOLDER = Pattern.compile("(\\$?)\\$\\(([A-Za-z_][A-Za-z0-9_]*)\\)");

    private final Function<String, String> lookup;

    /**
     * @param lookup Resolves a variable name to its value, or null when it is not set
     */
    EnvironmentSubstitutor(Function<String, String> lookup) {
        this.lookup = lookup;
    }

    /**
     * Substitutes placeholders in a single string.
     *
     * @param text The text, possibly containing placeholders
     * @param location Where the text came from (e.g. {@code headers.Authorization}), used in errors
     * @return The text with placeholders resolved
     * @throws IOException If a referenced variable is not set
     */
    String substitute(String text, String location) throws IOException {
        if (!text.contains("$(")) {
            return text;
        }
        Matcher matcher = PLACEHOLDER.matcher(text);
        StringBuilder out = new StringBuilder();
        while (matcher.find()) {
            String name = matcher.group(2);
            String replacement;
            if (!matcher.group(1).isEmpty()) {
                replacement = "$(" + name + ")";
            } else {
                replacement = lookup.apply(name);
                if (replacement == null) {
                    throw new IOException("Environment variable '" + name + "' referenced by '"
                            + location + "' in the configuration file is not set");
                }
            }
            matcher.appendReplacement(out, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(out);
        return out.toString();
    }

    /**
     * Substitutes placeholders in every string value of a JSON/YAML tree, in place.
     *
     * @param root The tree to update
     * @throws IOException If a referenced variable is not set
     */
    void substitute(JsonNode root) throws IOException {
        walk(root, "");
    }

    private void walk(JsonNode node, String path) throws IOException {
        if (node instanceof ObjectNode object) {
            Iterator<Map.Entry<String, JsonNode>> fields = object.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String childPath = path.isEmpty() ? field.getKey() : path + "." + field.getKey();
                replaceOrDescend(field.getValue(), childPath, field::setValue);
            }
        } else if (node instanceof ArrayNode array) {
            for (int i = 0; i < array.size(); i++) {
                int index = i;
                replaceOrDescend(array.get(i), path + "[" + i + "]", value -> array.set(index, value));
            }
        }
    }

    private void replaceOrDescend(JsonNode child, String path, Consumer<JsonNode> setter) throws IOException {
        if (child.isTextual()) {
            setter.accept(new TextNode(substitute(child.asText(), path)));
        } else {
            walk(child, path);
        }
    }
}
