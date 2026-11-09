import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Paths;

public class MultiModelPipeline {

    private static final HttpClient httpClient = HttpClient.newHttpClient();

    public static void main(String[] args) {
        String webgoatFilePath = "src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjection.java"; // Path to the WebGoat source code file

        String openaiKey = System.getenv("OPENAI_API_KEY");
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
            // ---- MODEL 1: OPENAI GPT-4o ----
            // ==========================================
            if (openaiKey != null && !openaiKey.isBlank()) {
                System.out.println("\n🤖 ========================================");
                System.out.println("🤖 EXECUTING PIPELINE FOR: OpenAI GPT-4o");
                System.out.println("🤖 ========================================");
                
                // Task 1
                System.out.println("🔍 [TASK 1] Running Static Analysis Scan...");
                String payload1 = "{\"model\": \"gpt-4o\", \"response_format\": {\"type\": \"json_object\"}, \"messages\": [{\"role\": \"user\", \"content\": \"" + staticAnalysisPrompt + "\"}]}";
                String response1 = sendPostRequest("https://openai.com", "Bearer " + openaiKey, payload1, null);
                System.out.println("📊 Task 1 Findings Report:\n" + response1);

                // Task 2
                System.out.println("\n🛠️ [TASK 2] Generating Defensive Patch...");
                String payload2 = "{\"model\": \"gpt-4o\", \"response_format\": {\"type\": \"json_object\"}, \"messages\": [{\"role\": \"user\", \"content\": \"" + defensivePatchPrompt + "\"}]}";
                String response2 = sendPostRequest("https://openai.com", "Bearer " + openaiKey, payload2, null);
                System.out.println("✨ Task 2 Refactoring Output:\n" + response2);
            }

            // ==========================================
            // ---- MODEL 2: GOOGLE GEMINI 1.5 PRO ----
            // ==========================================
            if (geminiKey != null && !geminiKey.isBlank()) {
                System.out.println("\n🤖 ========================================");
                System.out.println("🤖 EXECUTING PIPELINE FOR: Google Gemini 1.5 Pro");
                System.out.println("🤖 ========================================");
                
                // Task 1
                System.out.println("🔍 [TASK 1] Running Static Analysis Scan...");
                String payload1 = "{\"contents\": [{\"parts\": [{\"text\": \"" + staticAnalysisPrompt + "\"}]}], \"generationConfig\": {\"responseMimeType\": \"application/json\"}}";
                String url1 = "https://googleapis.com" + geminiKey;
                String response1 = sendPostRequest(url1, null, payload1, null);
                System.out.println("📊 Task 1 Findings Report:\n" + response1);

                // Task 2
                System.out.println("\n🛠️ [TASK 2] Generating Defensive Patch...");
                String payload2 = "{\"contents\": [{\"parts\": [{\"text\": \"" + defensivePatchPrompt + "\"}]}], \"generationConfig\": {\"responseMimeType\": \"application/json\"}}";
                String response2 = sendPostRequest(url1, null, payload2, null);
                System.out.println("✨ Task 2 Refactoring Output:\n" + response2);
            }

            // ==========================================
            // ---- MODEL 3: ANTHROPIC CLAUDE 3.5 SONNET ----
            // ==========================================
            if (anthropicKey != null && !anthropicKey.isBlank()) {
                System.out.println("\n🤖 ========================================");
                System.out.println("🤖 EXECUTING PIPELINE FOR: Anthropic Claude 3.5 Sonnet");
                System.out.println("🤖 ========================================");
                
                // Task 1
                System.out.println("🔍 [TASK 1] Running Static Analysis Scan...");
                String payload1 = "{\"model\": \"claude-3-5-sonnet-20241022\", \"max_tokens\": 2000, \"messages\": [{\"role\": \"user\", \"content\": \"" + staticAnalysisPrompt + "\"}]}";
                String response1 = sendPostRequest("https://anthropic.com", null, payload1, anthropicKey);
                System.out.println("📊 Task 1 Findings Report:\n" + response1);

                // Task 2
                System.out.println("\n🛠️ [TASK 2] Generating Defensive Patch...");
                String payload2 = "{\"model\": \"claude-3-5-sonnet-20241022\", \"max_tokens\": 2000, \"messages\": [{\"role\": \"user\", \"content\": \"" + defensivePatchPrompt + "\"}]}";
                String response2 = sendPostRequest("https://anthropic.com", null, payload2, anthropicKey);
                System.out.println("✨ Task 2 Refactoring Output:\n" + response2);
            }

        } catch (Exception e) {
            System.err.println("❌ Pipeline failed: " + e.getMessage());
            e.printStackTrace();
        }
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
