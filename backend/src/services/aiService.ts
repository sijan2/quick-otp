/**
 * Supported AI providers
 */
export type AIProvider = 'openai' | 'gemini';

/**
 * Configuration for the AI processing service.
 */
export interface AIProcessingConfig {
  provider: AIProvider;
  // OpenAI specific config
  openAIApiKey?: string;
  openAIModelName?: string;
  openAIEndpoint?: string;
  // Gemini specific config
  geminiApiKey?: string;
  geminiModelName?: string;
  geminiEndpoint?: string;
}

/**
 * The expected structured output from the AI after processing an email.
 */
export interface AIProcessedEmail {
  code?: string | null;      // The verification code, null if not found
  url?: string | null;       // The verification URL, null if not found
}

/**
 * Type definitions for the OpenAI API response structure
 */
interface OpenAIChatCompletionChoice {
  index?: number;
  message: {
    role: string;
    content: string | null;
  };
  finish_reason?: string;
}

interface OpenAIChatCompletionUsage {
  prompt_tokens?: number;
  completion_tokens?: number;
  total_tokens?: number;
}

interface OpenAIChatCompletionResponse {
  id?: string;
  object?: string;
  created?: number;
  model?: string;
  choices: OpenAIChatCompletionChoice[];
  usage?: OpenAIChatCompletionUsage;
  system_fingerprint?: string;
}

/**
 * Type definitions for the Gemini API response structure
 */
interface GeminiContentPart {
  text: string;
}

interface GeminiContent {
  role: string;
  parts: GeminiContentPart[];
}

interface GeminiCandidate {
  content: GeminiContent;
  finishReason?: string;
  safetyRatings?: Array<{
    category: string;
    probability: string;
  }>;
}

interface GeminiResponse {
  candidates?: GeminiCandidate[];
  promptFeedback?: {
    safetyRatings?: Array<{
      category: string;
      probability: string;
    }>;
  };
}

const DEFAULT_OPENAI_MODEL = "gpt-4o-mini";
const DEFAULT_OPENAI_ENDPOINT = "https://api.openai.com/v1/chat/completions";
const DEFAULT_GEMINI_MODEL = "gemini-2.5-flash-preview-04-17";
const DEFAULT_GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models";

/**
 * System prompt for the OpenAI API to guide email content extraction.
 */
const createSystemPrompt = (): string => {
  return `
You are an expert AI assistant specialized in parsing email content to extract **actionable user verification items (OTPs or verification/password reset links)**. Your goal is to identify if an email's **primary purpose** is to provide such an item for **immediate use** by the user (e.g., to complete a login, sign-up, or password reset they initiated).

**Phase 1: Determine Email Intent (Crucial First Step)**

Before extracting anything, classify the email's primary intent:

1.  **ACTIONABLE VERIFICATION:** Is the email's main goal to provide:
    *   **An OTP/Code for immediate use?** (e.g., "Your code is XXXXXX to complete login.")
    *   **An Email Confirmation/Account Activation Link?** (e.g., "Click to verify your email.")
    *   **A Password Reset Link/Code for an ongoing request?** (e.g., "Here is your link/code to reset your password.")
    *   **If YES to any of these, proceed to Phase 2: Extraction.**

2.  **INFORMATIONAL / NOT ACTIONABLE (for OTP/link extraction):** Is the email's main goal to:
    *   Notify about a **successful login** or **detected sign-in**? (e.g., "Successful login from X", "New sign-in detected").
    *   Confirm a **password has already been changed**? (e.g., "Your password was successfully changed.").
    *   Provide general security advice, 2FA setup encouragement (unless providing an *active* setup code/link), promotional content, receipts, or support updates?
    *   **Keywords indicating "Informational" (even if links are present):** "successful login", "password changed", "new sign-in", "we detected a sign-in", "if you did not", "no further action is required", "just wanted to make sure", "immediately change your password" (as a precaution, not as the primary verification step), "enable two-factor authentication" (as advice).
    *   **If YES to any of these, or if the purpose is unclear/unrelated to immediate verification, YOU MUST output: { "code": null, "url": null } and stop.**

**Phase 2: Extraction Rules (Only if intent is ACTIONABLE VERIFICATION)**

**A. Extracting Verification Codes:**
    *   Look for explicitly labeled codes: "verification code", "OTP", "one-time password", "confirmation code", "security code", "auth code", "your single-use code is", "enter this code".
    *   Typically 4-10 characters (digits, alphanumeric).
    *   **Formatting:**
        *   Remove spaces within codes (e.g., "123 456" -> "123456").
        *   Preserve hyphens if they are part of the code's structure (e.g., "ABC-123").
    *   Ensure context is user verification, not order numbers, etc.

**B. Extracting Verification URLs:**

    **1. Pre-processing (Critical - Apply to the raw URL string from HTML href or text):**
        *   **HTML Decode:** Fully decode HTML entities (e.g., &amp; -> &, &quot; -> ", &apos; -> ', &lt; -> <, &gt; -> >).
        *   **Quoted-Printable Decode:** Fully decode quoted-printable encodings (e.g., =3D -> =, =20 -> space, remove =0A).
        *   **All subsequent URL checks operate on this fully decoded URL.**

    **2. Identification & Source:**
        *   Prioritize URLs from HTML <a> tags if available.
        *   Look for link text/surrounding text like: "confirm email", "verify account", "reset password", "activate account", "Sign In", "Verify".

    **3. Validation of the Decoded URL:**
        *   **Google Redirects:** If host is google.com (or known redirector) with a q= or url= parameter, extract and URL-decode its value. This unwrapped URL is the *actual* URL to validate. Re-apply all these validation steps (including pre-processing if it looks encoded) to the unwrapped URL.
        *   **General Parameter Structure:**
            *   Query parameters MUST be name=value. Reject if nameNO_EQUALSvalue (e.g., tokenXYZ instead of token=XYZ).
            *   A URL usually needs at least one valid name=value query parameter, OR a path structure strongly indicative of verification (e.g., /verify/TOKEN_VALUE).
        *   **Perplexity-Specific Structure (on decoded URL):**
            *   Must have parameters like callbackUrl=..., token=..., email=... (with the = and a value).
            *   Requires at least two valid parameters from this set.
            *   If parameters are present but malformed (e.g., tokenXYZ or emailtest@example.com without =), reject the URL.
        *   **Purpose:** The link's clear purpose must be for immediate verification/action completion, not general navigation or informational pages (unless explicitly stated as THE verification step).

    **4. Selection:**
        *   If multiple valid URLs are found, prefer the one most clearly tied to the verification action from HTML.

**Output Format (Strict JSON):**

*   Return a single, valid JSON object. NO markdown, NO explanatory text.
*   Format: { "code": string | null, "url": string | null }
*   If no actionable code or URL is found according to the rules above (or if the email intent was Informational), both code and url MUST be null.

**Examples:**

*   **Actionable OTP:** "Code: 736190" -> { "code": "736190", "url": null }
*   **Actionable OTP (hyphen):** "Code: X7G-P2R" -> { "code": "X7G-P2R", "url": null }
*   **Actionable OTP (spaces):** "Code: 123 456" -> { "code": "123456", "url": null }
*   **Actionable URL:** "Click https://service.example.com/confirm?token=xyz123 to confirm." -> { "code": null, "url": "https://service.example.com/confirm?token=xyz123" }
*   **Informational (Password Changed Notification):** "Your password was changed. If this wasn't you, reset here: [link]" -> { "code": null, "url": null }
*   **Actionable (Google Redirect):** "Click: https://www.google.com/url?q=https%3A%2F%2Fex.com%2Fverify%3Ftoken%3Dabc" -> { "code": null, "url": "https://ex.com/verify?token=abc" }
*   **Malformed Perplexity URL (Missing '='):** "...callbackUrlhttps%3A%2F%2F...&tokenabc..." -> { "code": null, "url": null }
*   **Informational (Security Advice):** "Learn about security: [link]" -> { "code": null, "url": null }

Process the email content based on these instructions.
  `.trim();
};

/**
 * Processes email content using the specified AI provider to extract verification codes or URLs.
 *
 * @param emailBody The raw text content of the email.
 * @param config Configuration containing the API keys and provider settings.
 * @returns A promise that resolves to an AIProcessedEmail object.
 */
export async function processEmailWithAI(
  emailBody: string,
  config: AIProcessingConfig
): Promise<AIProcessedEmail> {
  if (!emailBody || emailBody.trim() === "") {
    console.warn("[AIProcessor] Email body empty. Skipping.");
    return { code: null, url: null };
  }

  const systemPrompt = createSystemPrompt();

  switch (config.provider) {
    case 'openai':
      return processWithOpenAI(emailBody, systemPrompt, config);
    case 'gemini':
      return processWithGemini(emailBody, systemPrompt, config);
    default:
      console.error(`[AIProcessor] Unsupported AI provider: ${config.provider}`);
      return { code: null, url: null };
  }
}

/**
 * Process email content using OpenAI API
 */
async function processWithOpenAI(
  emailBody: string,
  systemPrompt: string,
  config: AIProcessingConfig
): Promise<AIProcessedEmail> {
  if (!config.openAIApiKey) {
    console.error("[AIProcessor] OpenAI API key missing.");
    return { code: null, url: null };
  }

  const modelName = config.openAIModelName || DEFAULT_OPENAI_MODEL;
  const endpoint = config.openAIEndpoint || DEFAULT_OPENAI_ENDPOINT;

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${config.openAIApiKey}`,
      },
      body: JSON.stringify({
        model: modelName,
        messages: [
          {
            role: "system",
            content: systemPrompt,
          },
          {
            role: "user",
            content: emailBody,
          },
        ],
        response_format: { type: "json_object" },
        temperature: 0.1,
        top_p: 0.5,
      }),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      console.error(`[AIProcessor] OpenAI API error: ${response.status} ${errorBody.substring(0, 500)}`);
      return { code: null, url: null };
    }

    const data = await response.json() as OpenAIChatCompletionResponse;

    if (!data.choices?.[0]?.message?.content) {
      console.error("[AIProcessor] OpenAI response missing expected content.", data);
      return { code: null, url: null };
    }

    return parseAIResponse(data.choices[0].message.content);
  } catch (error: any) {
    console.error("[AIProcessor] OpenAI processing error:", error.message);
    return { code: null, url: null };
  }
}

/**
 * Process email content using Gemini API
 */
async function processWithGemini(
  emailBody: string,
  systemPrompt: string,
  config: AIProcessingConfig
): Promise<AIProcessedEmail> {
  if (!config.geminiApiKey) {
    console.error("[AIProcessor] Gemini API key missing.");
    return { code: null, url: null };
  }

  const modelName = config.geminiModelName || DEFAULT_GEMINI_MODEL;
  const baseEndpoint = config.geminiEndpoint || DEFAULT_GEMINI_ENDPOINT;
  const endpoint = `${baseEndpoint}/${modelName}:generateContent?key=${config.geminiApiKey}`;

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        contents: [
          {
            parts: [
              { text: systemPrompt },
              { text: "\n\nNow process this email content:\n" + emailBody }
            ]
          }
        ],
        generationConfig: {
          temperature: 0.1,
          topP: 0.5,
          responseMimeType: "application/json"
        }
      }),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      console.error(`[AIProcessor] Gemini API error: ${response.status} ${errorBody.substring(0, 500)}`);
      return { code: null, url: null };
    }

    const data = await response.json() as GeminiResponse;

    if (!data.candidates?.[0]?.content?.parts?.[0]?.text) {
      console.error("[AIProcessor] Gemini response missing expected content.", data);
      return { code: null, url: null };
    }

    return parseAIResponse(data.candidates[0].content.parts[0].text);
  } catch (error: any) {
    console.error("[AIProcessor] Gemini processing error:", error.message);
    return { code: null, url: null };
  }
}

/**
 * Parse the AI response into AIProcessedEmail format
 */
function parseAIResponse(content: string): AIProcessedEmail {
  try {
    const processedEmail: AIProcessedEmail = JSON.parse(content);

    if (typeof processedEmail !== 'object' || processedEmail === null) {
      console.error("[AIProcessor] Parsed AI response not an object:", processedEmail);
      return { code: null, url: null };
    }

    if (processedEmail.code === undefined && processedEmail.url === undefined) {
      console.error("[AIProcessor] AI JSON missing code/url fields. Raw:", content.substring(0,500));
      return { code: null, url: null };
    }

    return {
      code: processedEmail.code !== undefined ? processedEmail.code : null,
      url: processedEmail.url !== undefined ? processedEmail.url : null
    };
  } catch (parseError: any) {
    console.error("[AIProcessor] CRITICAL: Error parsing AI JSON:", parseError.message, "Raw content:", content.substring(0,500));
    return { code: null, url: null };
  }
}
