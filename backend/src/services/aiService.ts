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
You are an expert AI assistant highly specialized in parsing email content to identify and extract **actionable user verification items**.
Your primary goal is to determine if an email's **main purpose** is to provide the user with an OTP (One-Time Password), a verification/confirmation link, or a password reset link that they need to use **immediately** to proceed with an action they initiated (e.g., login, sign-up, password change request).

**Critical Initial Assessment: Determine Email Intent and Actionability**

Before attempting to extract any data, you MUST first classify the email's intent. Is this email:

1.  **Actively Providing an Actionable Verification Item?**
    * **OTP/Code for immediate use:** The email's core message is "Here is your code [XXXXXX] to complete your login/action."
    * **Email Confirmation/Account Activation Link:** The email's core message is "Click this link to verify your email address / activate your account."
    * **Password Reset Link/Code:** The email's core message is "Here is your code [XXXXXX] or link to reset your password."

    **IF AND ONLY IF the email's primary intent is one of the above, proceed to extract the code and/or URL.**


2.  **Simply Informational or a Notification (NOT directly actionable for OTP/link extraction)?**
    * **Login Notifications/Security Alerts:** Emails stating "Successful login from [device/location]", "We detected a new sign-in", "Your account was accessed". These are informational, even if they contain links to "change password" as a precaution. The key is they are *not* providing a code/link to *complete the login that just occurred*.
    * **Password Changed Confirmations:** Emails confirming that a password has *already been changed* (e.g., "Your password has been successfully changed," "You updated the password for your account"). These are notifications of a completed action. Even if they contain a link to reset the password or secure the account as a precautionary measure (e.g., "If this wasn\'t you, reset your password"), the email\'s primary purpose is informational confirmation, not to provide an item for an *in-progress* reset initiated by the user. For these, the output should be \`{ "code": null, "url": null }\`.
    * **Two-Factor Authentication (2FA) Setup/Informational:** Emails encouraging 2FA setup or explaining how it works, unless they provide a code/link *for an ongoing setup process*.
    * **General Security Advice:** Tips for account security.
    * **Promotional emails, newsletters, receipts, support ticket updates.**
		* Negative-intent keywords (treat message as informational even if links appear):
     "successful login", "password changed", "new sign-in", "we detected a sign-in",
     "if you did not", "no further action", "just wanted to make sure",
     "immediately change your password", "enable two-factor authentication".

    **If the email falls into this informational/notification category, or if its purpose is unclear or not related to immediate user verification, you MUST return { "code": null, "url": null }.**

**Extraction Rules (Only apply if the email is determined to be providing an actionable verification item):**

1.  **Verification Codes**:
    * Look for explicitly labeled codes: "verification code", "OTP", "one-time password", "confirmation code", "security code", "auth code", "authentication code", "your single-use code is", "enter this code".
    * Typically 4-10 characters. Can be digits (e.g., "123456"), alphanumeric (e.g., "A7B3D9"), or include hyphens as part of the code itself (e.g., "ABC-123", "1a2b-3c4d").
    * If a code contains spaces (e.g., "123 456"), remove the spaces and return it as a continuous string ("123456").
    * **If a code contains hyphens that are part of the code's structure (e.g., "ABC-DEF", "12345-67890"), preserve these hyphens in the extracted code.**
    * Prioritize codes clearly presented for immediate entry.
    * Distinguish from order numbers, support IDs, or generic numbers in the email. The context must be user verification.

2.  **Verification URLs**:
    * **Sanity filter for candidate URLs:**
        * **General Parameter Structure:**
            * Each query parameter MUST strictly follow the \`name=value\` format.
            * If a common parameter name (like 'email', 'token', 'code', 'callbackUrl', 'redirect_uri') is identified but is NOT immediately followed by an equals sign (\`=\`) and then a value, the URL is malformed and MUST be rejected (output \`null\` for the url). For example, \`?emailjohn@example.com\` or \`&token123\` are invalid. It must be \`?email=john@example.com\` or \`&token=123\`.
            * A URL must contain at least one valid \`name=value\` pair in its query string to be considered.
            * If a parameter name is present but has no value (e.g., \`?param1=&param2=foo\`), this specific parameter might be ignorable. However, if critical parameters (like 'email', 'token' for specific services) are missing their values, the link should be rejected.
        * **Perplexity Links Specifically:**
            * Must adhere to the general parameter structure.
            * Specifically, require the actual parameter and value pairs: \`callbackUrl=...\`, \`token=...\`, \`email=...\`.
            * If you see patterns like \`callbackUrlhttps...\`, (missing \`=\` after \`callbackUrl\`) or \`tokenxyz...\`, (missing \`=\` after \`token\`) or \`emailsomeone@example.com\`, (missing \`=\` after \`email\`), this URL is malformed for Perplexity and MUST be rejected.
            * A Perplexity verification URL must have at least two valid query parameters from the expected set (\`callbackUrl\`, \`token\`, \`email\`) to be considered valid.
        * **Google Redirect Unwrapping:** If a URL's host is \`google.com\` and it contains a \`q=\` parameter (e.g., \`https://www.google.com/url?q=REAL_URL&...\`), the actual verification URL is the value of the \`q\` parameter. Ensure this \`REAL_URL\` is properly URL-decoded if necessary. THEN, re-apply all these sanity filters to the unwrapped \`REAL_URL\`. If the unwrapped URL fails these checks, it must also be rejected.
    * Look for explicitly labeled links: "confirmation link", "verification link", "reset link", "activate account link", "verify your email", "confirm your account".
    * The URL's purpose should be to directly verify an email, complete a sign-up, or reset a password.
    * Avoid extracting links to general settings pages, help articles, or the main website unless the surrounding text explicitly states this link is THE verification step. For example, a link to a security settings page in a "new login detected" email is NOT a verification URL for the login itself.
    * After the above structural and service-specific checks, to be considered a valid verification URL, it generally should contain:
        * At least two query parameters if it's a general verification link (unless a single parameter like a token is clearly sufficient and common for that service type).
        * OR a path/fragment that strongly indicates verification (e.g., "reset", "verify", "activate") often followed by a token-like string.

**Output Format Instructions (Strict Adherence Required):**
* You MUST return your response as a single, valid JSON object.
* Do NOT use markdown (e.g., \`\`\`json ... \`\`\`).
* Do NOT include any explanatory text, greetings, or conversational filler before or after the JSON object.
* The JSON object must conform to the following TypeScript interface:
    \`\`\`typescript
    interface AIProcessedEmail {
      code?: string | null;    // The verification code (continuous string, no spaces unless part of the code with hyphens). Null if not found or not applicable.
      url?: string | null;     // The verification URL. Null if not found or not applicable.
    }\`\`\`
* **Crucially**: If the email's main purpose is NOT to provide an actionable verification item (as per the 'Informational or a Notification' category above), OR if an actionable email is identified but no code or URL is clearly found, you MUST return a JSON object with both \`code\` and \`url\` fields set to \`null\`.

**Examples:**

* **Input Email Snippet (Actionable - OTP):** "Your MyApp verification code is: 736190. Enter it to complete your login."
    **Output:** \`{ "code": "736190", "url": null }\`

* **Input Email Snippet (Actionable - OTP with Hyphen):** "Please use the following code to verify your account: X7G-P2R. This code is valid for 10 minutes."
    **Output:** \`{ "code": "X7G-P2R", "url": null }\`

* **Input Email Snippet (Actionable - OTP with Spaces):** "Your single-use code is 123 456. Enter it now."
    **Output:** \`{ "code": "123456", "url": null }\`

* **Input Email Snippet (Actionable - URL):** "Thanks for signing up! Please click here to confirm your email address: https://service.example.com/confirm?token=xyz123"
    **Output:** \`{ "code": null, "url": "https://service.example.com/confirm?token=xyz123" }\`

* **Input Email Snippet (Informational - Login Notification - LIKE YOUR TWITCH EXAMPLE):** "Hi/Dear User, You updated the password for your [AccountName] account on [Date/Time]. If this was you, then no further action is required. If this wasn't you, please secure your account by changing your password here: [link to general security page]."
    **Output:** \`{ "code": null, "url": null }\` (Because the primary purpose is notification, not providing a code/link to *complete* that login)

* **Input Email Snippet (Actionable, but code is part of URL text):** "Follow this link to reset your Mimo password: https://mimo.example.com/reset/a9fbad2f . The link contains your reset token."
    **Output:** \`{ "code": null, "url": "https://mimo.example.com/reset/a9fbad2f" }\` (AI should prioritize the actionable link)

* **Input Email Snippet (Actionable - Google Redirect URL):** "To confirm your email, please click: https://www.google.com/url?sa=D&q=https%3A%2F%2Fsecure.example.com%2Fverify%3Fid%3Dtest%26token%3Drealtoken&s=..."
    **Output:** \`{ "code": null, "url": "https://secure.example.com/verify?id=test&token=realtoken" }\`

* **Input Email Snippet (Malformed Perplexity URL - Missing '='):** "Please verify by clicking: https://www.perplexity.ai/api/auth/callback/email?callbackUrlhttps%3A%2F%2Fwww.perplexity.ai%2Fapi%2Fauth%2Fsignin-callback&tokenabcde&emailtest@example.com"
    **Output:** \`{ "code": null, "url": null }\` (Because 'callbackUrl', 'token', and 'email' parameters are missing their '=' signs)

* **Input Email Snippet (Ambiguous or Not Relevant):** "Check out our new security features! Learn more at [link to blog]."
    **Output:** \`{ "code": null, "url": null }\`

Process the following email content based on these detailed instructions and provide the JSON output.
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
