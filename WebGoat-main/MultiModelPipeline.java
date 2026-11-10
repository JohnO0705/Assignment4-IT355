import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;

public class MultiModelPipeline {

    private static final HttpClient httpClient = HttpClient.newHttpClient();

    private static final String GEMINI_MODEL = "gemini-3.8-flash";
    private static final String ANTHROPIC_MODEL = "claude-sonnet-5-5";

    private static final String GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/interactions";
    private static final String ANTHROPIC_URL = "https://api.anthropic.com/v1/messages";

    public static void main(String[] args) {
        String webgoatFilePath = "src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5a.java"; // Path to the WebGoat source code file

        String groqKey = System.getenv("GROQ_API_KEY");
        String anthropicKey = System.getenv("ANTHROPIC_API_KEY");
        String geminiKey = System.getenv("GEMINI_API_KEY");

        try {
            System.out.println("Loading WebGoat Target Source Text: " + webgoatFilePath);
            String sourceCode = Files.readString(Paths.get(webgoatFilePath));
            
            // Clean up source code strings for safe JSON payload transmission
            String escapedCode = sourceCode.replace("\\", "\\\\")
                                           .replace("\"", "\\\"")
                                           .replace("\n", "\\n")
                                           .replace("\r", "\\r")
                                           .replace("\t", "\\t");

            // Define Prompts for both Tasks
            String staticAnalysisPrompt = "You are an automated SAST tool. Analyze this Java source code. Find vulnerabilities and return ONLY a valid, raw JSON block following this exact format without any markdown code wrappers: " +
                    "{\\\"findings\\\": [{\\\"filePath\\\": \\\"" + webgoatFilePath + "\\\", \\\"lineNumbers\\\": \\\"string\\\", \\\"cweId\\\": \\\"string\\\", \\\"cweName\\\": \\\"string\\\", \\\"description\\\": \\\"string\\\"}]}. Code: " + escapedCode;

            String defensivePatchPrompt = "You are an expert secure application developer. Securely rewrite the following code to eliminate any SQL Injection vulnerability using proper defense-in-depth methodologies (like PreparedStatements). Return ONLY a valid, raw JSON block following this exact format without any markdown code wrappers: " +
                    "{\\\"generatedCode\\\": \\\"your refactored secure code string\\\", \\\"mitigationSummary\\\": \\\"your manual verification text\\\"}. Code to fix: " + escapedCode;

            // ==========================================
            // ---- MODEL 1: Groq ----
            // ==========================================
            if (groqKey != null && !groqKey.isBlank()) {
                System.out.println("\n ========================================");
                System.out.println(" EXECUTING PIPELINE FOR: Groq");
                System.out.println(" ========================================");
                
                // Task 1
                System.out.println(" [TASK 1] Running Static Analysis Scan...");
                String payload1 = "{\"model\": \"openai/gpt-oss-20b\", \"response_format\": {\"type\": \"json_object\"}, \"messages\": [{\"role\": \"user\", \"content\": \"" + staticAnalysisPrompt + "\"}]}";
                String response1 = sendPostRequest("https://api.groq.com/openai/v1/chat/completions", "Bearer " + groqKey, payload1, null);
                System.out.println(" Task 1 Findings Report:\n" + response1);

                // Task 2
                System.out.println("\n [TASK 2] Generating Defensive Patch...");
                String payload2 = "{\"model\": \"openai/gpt-oss-20b\", \"response_format\": {\"type\": \"json_object\"}, \"messages\": [{\"role\": \"user\", \"content\": \"" + defensivePatchPrompt + "\"}]}";
                String response2 = sendPostRequest("https://api.groq.com/openai/v1/chat/completions", "Bearer " + groqKey, payload2, null);
                System.out.println(" Task 2 Refactoring Output:\n" + response2);
            }

            // ==========================================
            // ---- MODEL 2: GOOGLE GEMINI (Interactions API) ----
            // ==========================================
            if (isSet(geminiKey)) {
                banner("Google " + GEMINI_MODEL);
                Map<String, String> headers = Map.of("x-goog-api-key", geminiKey);

                System.out.println(" [TASK 1] Running Static Analysis Scan...");
                System.out.println(" Task 1 Findings Report:\n"
                        + post(GEMINI_URL, headers, geminiPayload(staticAnalysisPrompt)));

                System.out.println("\n [TASK 2] Generating Defensive Patch...");
                System.out.println(" Task 2 Refactoring Output:\n"
                        + post(GEMINI_URL, headers, geminiPayload(defensivePatchPrompt)));
            }

            // ==========================================
            // ---- MODEL 3: ANTHROPIC CLAUDE ----
            // ==========================================
            if (isSet(anthropicKey)) {
                banner("Anthropic " + ANTHROPIC_MODEL);
                Map<String, String> headers = Map.of(
                        "x-api-key", anthropicKey,
                        "anthropic-version", "2023-06-01");

                System.out.println(" [TASK 1] Running Static Analysis Scan...");
                System.out.println(" Task 1 Findings Report:\n"
                        + post(ANTHROPIC_URL, headers, anthropicPayload(staticAnalysisPrompt)));

                System.out.println("\n [TASK 2] Generating Defensive Patch...");
                System.out.println(" Task 2 Refactoring Output:\n"
                        + post(ANTHROPIC_URL, headers, anthropicPayload(defensivePatchPrompt)));
            }

        } catch (Exception e) {
            System.err.println(" Pipeline failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static String post(String url, Map<String, String> headers, String jsonPayload)
            throws IOException, InterruptedException {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonPayload));

        headers.forEach(builder::header);

        HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        System.out.println(" HTTP status: " + response.statusCode()); // 400 = bad request/key, 404 = bad model, 429 = rate limit
        return response.body();
    }

    // Gemini Interactions API: {"model": "...", "input": "..."}
    // The reply text is at steps[type=model_output].content[0].text
    private static String geminiPayload(String prompt) {
        return "{\"model\": \"" + GEMINI_MODEL + "\", \"input\": \"" + prompt + "\"}";
    }

    private static String anthropicPayload(String prompt) {
        return "{\"model\": \"" + ANTHROPIC_MODEL + "\", \"max_tokens\": 4096, "
                + "\"messages\": [{\"role\": \"user\", \"content\": \"" + prompt + "\"}]}";
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
}
