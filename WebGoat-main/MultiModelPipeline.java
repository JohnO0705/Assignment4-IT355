import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

public class MultiModelPipeline {
    private static final HttpClient httpClient = HttpClient.newHttpClient();
    private static final String GEMINI_MODEL = "gemini-3.8-flash";
    private static final String ANTHROPIC_MODEL = "claude-sonnet-5-5";
    private static final String GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/interactions";
    private static final String ANTHROPIC_URL = "https://api.anthropic.com/v1/messages";
    
    // Directory where the structured output text files will be stored
    private static final String OUTPUT_DIR = "pipeline_outputs";

    public static void main(String[] args) {
        String webgoatFilePath = "src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5a.java";
        String groqKey = System.getenv("GROQ_API_KEY");
        String anthropicKey = System.getenv("ANTHROPIC_API_KEY");
        String geminiKey = System.getenv("GEMINI_API_KEY");

        try {
            System.out.println("Loading WebGoat Target Source Text: " + webgoatFilePath);
            String sourceCode = Files.readString(Paths.get(webgoatFilePath));

            String escapedCode = sourceCode.replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\n", "\\n")
                    .replace("\r", "\\r")
                    .replace("\t", "\\t");

            String staticAnalysisPrompt = "You are an automated SAST tool. Analyze this Java source code. Find vulnerabilities and return ONLY a valid, raw JSON block following this exact format without any markdown code wrappers: " +
                    "{\\\"findings\\\": [{\\\"filePath\\\": \\\"" + webgoatFilePath + "\\\", \\\"lineNumbers\\\": \\\"string\\\", \\\"cweId\\\": \\\"string\\\", \\\"cweName\\\": \\\"string\\\", \\\"description\\\": \\\"string\\\"}]}. Code: " + escapedCode;

            String defensivePatchPrompt = "You are an expert secure application developer. Securely rewrite the following code to eliminate any SQL Injection vulnerability using proper defense-in-depth methodologies (like PreparedStatements). Return ONLY a valid, raw JSON block following this exact format without any markdown code wrappers: " +
                    "{\\\"generatedCode\\\": \\\"your refactored secure code string\\\", \\\"mitigationSummary\\\": \\\"your manual verification text\\\"}. Code to fix: " + escapedCode;

            // ==========================================
            // ---- MODEL 1: Groq ----
            // ==========================================
            if (groqKey != null && !groqKey.isBlank()) {
                banner("Groq");
            
                // Fix: Explicitly point to Groq's proper completion route
                String groqEndpoint = "https://api.groq.com/openai/v1/chat/completions";
            
                // Task 1
                System.out.println(" [TASK 1] Running Static Analysis Scan...");
                String payload1 = "{" +
                    "\"model\": \"openai/gpt-oss-20b\"," +
                    "\"response_format\": {\"type\": \"json_object\"}," +
                    "\"temperature\": 0.1," + 
                    "\"messages\": [" +
                        "{\"role\": \"system\", \"content\": \"You are a strict JSON generator. Always output a valid JSON object matching the user requested keys exactly without extra conversational text wrappers.\"}," +
                        "{\"role\": \"user\", \"content\": \"" + staticAnalysisPrompt + "\"}" +
                    "]" +
                "}";
                String response1 = sendPostRequest(groqEndpoint, "Bearer " + groqKey, payload1, null);
                System.out.println(" Task 1 Findings Report:\n" + response1);
                saveOutput("Groq", "Task1_StaticAnalysis", response1);
            
                // Task 2
                System.out.println("\n [TASK 2] Generating Defensive Patch...");
                String payload2 = "{" +
                    "\"model\": \"openai/gpt-oss-20b\"," +
                    "\"response_format\": {\"type\": \"json_object\"}," +
                    "\"temperature\": 0.1," + 
                    "\"messages\": [" +
                        "{\"role\": \"system\", \"content\": \"You are a strict JSON generator. Always output a valid JSON object matching the user requested keys exactly without extra conversational text wrappers.\"}," +
                        "{\"role\": \"user\", \"content\": \"" + defensivePatchPrompt + "\"}" +
                    "]" +
                "}";
                String response2 = sendPostRequest(groqEndpoint, "Bearer " + groqKey, payload2, null);
                System.out.println(" Task 2 Refactoring Output:\n" + response2);
                saveOutput("Groq", "Task2_DefensivePatch", response2);
            }
            


            // ==========================================
            // ---- MODEL 2: GOOGLE GEMINI ----
            // ==========================================
            if (isSet(geminiKey)) {
                banner("Google_" + GEMINI_MODEL);
                Map<String, String> headers = Map.of("x-goog-api-key", geminiKey);

                System.out.println(" [TASK 1] Running Static Analysis Scan...");
                String response1 = post(GEMINI_URL, headers, geminiPayload(staticAnalysisPrompt));
                System.out.println(" Task 1 Findings Report:\n" + response1);
                saveOutput("Google_" + GEMINI_MODEL, "Task1_StaticAnalysis", response1);

                System.out.println("\n [TASK 2] Generating Defensive Patch...");
                String response2 = post(GEMINI_URL, headers, geminiPayload(defensivePatchPrompt));
                System.out.println(" Task 2 Refactoring Output:\n" + response2);
                saveOutput("Google_" + GEMINI_MODEL, "Task2_DefensivePatch", response2);
            }

            // ==========================================
            // ---- MODEL 3: ANTHROPIC CLAUDE ----
            // ==========================================
            if (isSet(anthropicKey)) {
                banner("Anthropic_" + ANTHROPIC_MODEL);
                Map<String, String> headers = Map.of(
                        "x-api-key", anthropicKey,
                        "anthropic-version", "2023-06-01");

                System.out.println(" [TASK 1] Running Static Analysis Scan...");
                String response1 = post(ANTHROPIC_URL, headers, anthropicPayload(staticAnalysisPrompt));
                System.out.println(" Task 1 Findings Report:\n" + response1);
                saveOutput("Anthropic_" + ANTHROPIC_MODEL, "Task1_StaticAnalysis", response1);

                System.out.println("\n [TASK 2] Generating Defensive Patch...");
                String response2 = post(ANTHROPIC_URL, headers, anthropicPayload(defensivePatchPrompt));
                System.out.println(" Task 2 Refactoring Output:\n" + response2);
                saveOutput("Anthropic_" + ANTHROPIC_MODEL, "Task2_DefensivePatch", response2);
            }

        } catch (Exception e) {
            System.err.println(" Pipeline failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static String post(String url, Map<String, String> headers, String jsonPayload) throws IOException, InterruptedException {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonPayload));
        headers.forEach(builder::header);
        HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        System.out.println(" HTTP status: " + response.statusCode());
        return response.body();
    }

    private static String geminiPayload(String prompt) {
        return "{\"model\": \"" + GEMINI_MODEL + "\", \"input\": \"" + prompt + "\"}";
    }

    private static String anthropicPayload(String prompt) {
        return "{\"model\": \"" + ANTHROPIC_MODEL + "\", \"max_tokens\": 4096, " +
                "\"messages\": [{\"role\": \"user\", \"content\": \"" + prompt + "\"}]}";
    }

    private static boolean isSet(String key) {
        return key != null && !key.isBlank();
    }

    private static void banner(String name) {
        System.out.println("\n ========================================");
        System.out.println(" EXECUTING PIPELINE FOR: " + name);
        System.out.println(" ========================================");
    }

    private static String sendPostRequest(String url, String authHeader, String jsonPayload, String anthropicKey) throws IOException, InterruptedException {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonPayload));
        if (authHeader != null) {
            builder.header("Authorization", authHeader);
        }
        if (anthropicKey != null) {
            builder.header("x-api-key", anthropicKey);
            builder.header("anthropic-version", "2023-06-01");
        }
        HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        return response.body();
    }

        /**
     * Helper method to output structured text files on disk.
     * Automatically extracts inner JSON content and pretty-prints it for readability.
     */
    private static void saveOutput(String modelName, String taskName, String content) {
        try {
            // Clean names to ensure they don't break file system paths
            String safeModelName = modelName.replaceAll("[^a-zA-Z0-9_-]", "_");
            
            // Create pipeline_outputs/ directory if it doesn't exist
            Path directoryPath = Paths.get(OUTPUT_DIR);
            if (!Files.exists(directoryPath)) {
                Files.createDirectories(directoryPath);
            }

            // Construct file name
            String fileName = String.format("%s_%s.txt", safeModelName, taskName);
            Path filePath = directoryPath.resolve(fileName);

            // Process content: Extract and clean up the nested LLM answer
            String printableContent = extractAndPrettyPrint(content);

            // Write contents to file
            Files.writeString(filePath, printableContent);
            System.out.println(" >>> Successfully saved to file: " + filePath.toAbsolutePath());
            
        } catch (IOException e) {
            System.err.println(" Failed to save file for " + modelName + " (" + taskName + "): " + e.getMessage());
        }
    }

        /**
     * Extract the raw inner text string from the LLM envelope and formats it into indented JSON.
     */
    private static String extractAndPrettyPrint(String rawJson) {
        String extracted = rawJson;

        // 1. Detect provider envelope and extract the actual inner text payload
        if (rawJson.contains("\"choices\"")) {
            // Groq / OpenAI format: Look for "content": "..."
            java.util.regex.Matcher matcher = java.util.regex.Pattern.compile("\"content\"\\s*:\\s*\"(.*?)\"\\s*(,\\s*\"|})").matcher(rawJson);
            if (matcher.find()) {
                extracted = matcher.group(1);
            }
        } else if (rawJson.contains("\"candidates\"")) {
            // Google Gemini format: Look for "text": "..." inside candidates
            java.util.regex.Matcher matcher = java.util.regex.Pattern.compile("\"text\"\\s*:\\s*\"(.*?)\"\\s*}\\s*\\]\\s*}\\s*\\]").matcher(rawJson);
            if (matcher.find()) {
                extracted = matcher.group(1);
            }
        } else if (rawJson.contains("\"content\"")) {
            // Anthropic Claude format: Look for "text": "..." inside content block
            java.util.regex.Matcher matcher = java.util.regex.Pattern.compile("\"text\"\\s*:\\s*\"(.*?)\"\\s*}\\s*\\]").matcher(rawJson);
            if (matcher.find()) {
                extracted = matcher.group(1);
            }
        }

        // 2. Unescape Java/JSON control characters to recover the true underlying JSON payload
        extracted = extracted.replace("\\\\", "\\")
                             .replace("\\\"", "\"")
                             .replace("\\n", "\n")
                             .replace("\\t", "\t")
                             .replace("\\r", "\r");

        // Strip any accidental markdown blocks if models ignore the prompt constraint
        extracted = extracted.trim();
        if (extracted.startsWith("```json")) {
            extracted = extracted.substring(7);
        }
        if (extracted.startsWith("```")) {
            extracted = extracted.substring(3);
        }
        if (extracted.endsWith("```")) {
            extracted = extracted.substring(0, extracted.length() - 3);
        }
        extracted = extracted.trim();

        // 3. Simple Pretty-Printer (adds neat line breaks and indentation)
        StringBuilder pretty = new StringBuilder();
        int indentLevel = 0;
        boolean inQuotes = false;

        for (int i = 0; i < extracted.length(); i++) {
            char charAt = extracted.charAt(i);

            // Handle strings so we don't accidentally split text inside quotes
            if (charAt == '"' && (i == 0 || extracted.charAt(i - 1) != '\\')) {
                inQuotes = !inQuotes;
            }

            if (inQuotes) {
                pretty.append(charAt);
                continue;
            }

            switch (charAt) {
                case '{':
                case '[':
                    pretty.append(charAt).append("\n").append("\t".repeat(++indentLevel));
                    break;
                case '}':
                case ']':
                    pretty.append("\n").append("\t".repeat(--indentLevel)).append(charAt);
                    break;
                case ',':
                    pretty.append(charAt).append("\n").append("\t".repeat(indentLevel));
                    break;
                case ':':
                    pretty.append(charAt).append(" ");
                    break;
                default:
                    if (charAt != '\r' && charAt != '\n' && charAt != '\t') {
                        pretty.append(charAt);
                    }
                    break;
            }
        }
        return pretty.toString();
    }

}
