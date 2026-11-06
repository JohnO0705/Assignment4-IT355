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
        String webgoatFilePath = "webgoat-lessons/sql-injection/src/main/java/org/owasp/webgoat/plugin/SqlInjectionLesson5a.java";

        String openaiKey = System.getenv("OPENAI_API_KEY");
        String anthropicKey = System.getenv("ANTHROPIC_API_KEY");
        String geminiKey = System.getenv("GEMINI_API_KEY");

        try {
            System.out.println("📂 Loading WebGoat Target Source Text: " + webgoatFilePath);
            String sourceCode = Files.readString(Paths.get(webgoatFilePath));
            
            // Clean up source code strings for safe JSON payload transmission
            String escapedCode = sourceCode.replace("\\", "\\\\")
                                           .replace("\"", "\\\"")
                                           .replace("\n", "\\n")
                                           .replace("\r", "\\r")
                                           .replace("\t", "\\t");

            String staticAnalysisPrompt = "You are an automated SAST tool. Analyze this Java source code. Find vulnerabilities and return ONLY a valid, raw JSON block following this exact format without any markdown code wrappers: " +
                    "{\\\"findings\\\": [{\\\"filePath\\\": \\\"" + webgoatFilePath + "\\\", \\\"lineNumbers\\\": \\\"string\\\", \\\"cweId\\\": \\\"string\\\", \\\"cweName\\\": \\\"string\\\", \\\"description\\\": \\\"string\\\"}]}. Code: " + escapedCode;

            // ---- MODEL 1: OPENAI GPT-4o ----
            if (openaiKey != null && !openaiKey.isBlank()) {
                System.out.println("\n🤖 EXECUTING PIPELINE FOR: OpenAI GPT-4o");
                String payload = "{\"model\": \"gpt-4o\", \"response_format\": {\"type\": \"json_object\"}, \"messages\": [{\"role\": \"user\", \"content\": \"" + staticAnalysisPrompt + "\"}]}";
                String response = sendPostRequest("https://openai.com", "Bearer " + openaiKey, payload, null);
                System.out.println("🔍 Scan Result:\n" + response);
            }

            // ---- MODEL 2: GOOGLE GEMINI 1.5 PRO ----
            if (geminiKey != null && !geminiKey.isBlank()) {
                System.out.println("\n🤖 EXECUTING PIPELINE FOR: Google Gemini 1.5 Pro");
                String payload = "{\"contents\": [{\"parts\": [{\"text\": \"" + staticAnalysisPrompt + "\"}]}], \"generationConfig\": {\"responseMimeType\": \"application/json\"}}";
                String url = "https://googleapis.com" + geminiKey;
                String response = sendPostRequest(url, null, payload, null);
                System.out.println("🔍 Scan Result:\n" + response);
            }

            // ---- MODEL 3: ANTHROPIC CLAUDE 3.5 SONNET ----
            if (anthropicKey != null && !anthropicKey.isBlank()) {
                System.out.println("\n🤖 EXECUTING PIPELINE FOR: Anthropic Claude 3.5 Sonnet");
                String payload = "{\"model\": \"claude-3-5-sonnet-20241022\", \"max_tokens\": 2000, \"messages\": [{\"role\": \"user\", \"content\": \"" + staticAnalysisPrompt + "\"}]}";
                String response = sendPostRequest("https://anthropic.com", "Bearer " + anthropicKey, payload, anthropicKey);
                System.out.println("🔍 Scan Result:\n" + response);
            }

        } catch (Exception e) {
            System.err.println("Pipeline failed: " + e.getMessage());
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
