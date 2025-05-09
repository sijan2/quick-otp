/**
 * Configuration for the AI processing service.
 */
export interface AIProcessingConfig {
  openAIApiKey: string;
  openAIModelName?: string; // e.g., 'gpt-4o-mini', defaults if not provided
  openAIEndpoint?: string; // e.g., 'https://api.openai.com/v1/chat/completions', defaults if not provided
}

/**
 * The expected structured output from the AI after processing an email.
 */
export interface AIProcessedEmail {
  code?: string | null;      // The verification code, null if not found
  url?: string | null;       // The verification URL, null if not found
}

const DEFAULT_OPENAI_MODEL = "gpt-4o-mini";
const DEFAULT_OPENAI_ENDPOINT = "https://api.openai.com/v1/chat/completions";

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
    * **Password Changed Confirmations:** Emails stating "Your password has been successfully changed."
    * **Two-Factor Authentication (2FA) Setup/Informational:** Emails encouraging 2FA setup or explaining how it works, unless they provide a code/link *for an ongoing setup process*.
    * **General Security Advice:** Tips for account security.
    * **Promotional emails, newsletters, receipts, support ticket updates.**

    **If the email falls into this informational/notification category, or if its purpose is unclear or not related to immediate user verification, you MUST return { "code": null, "url": null }.**

**Extraction Rules (Only apply if the email is determined to be providing an actionable verification item):**

1.  **Verification Codes**:
    * Look for explicitly labeled codes: "verification code", "OTP", "one-time password", "confirmation code", "security code", "auth code", "authentication code", "your single-use code is", "enter this code".
    * Typically 4-8 digits, can be alphanumeric.
    * If a code contains spaces (e.g., "123 456"), return it as a continuous string ("123456").
    * Prioritize codes clearly presented for immediate entry.
    * Distinguish from order numbers, support IDs, or generic numbers in the email. The context must be user verification.

2.  **Verification URLs**:
    * Look for explicitly labeled links: "confirmation link", "verification link", "reset link", "activate account link", "verify your email", "confirm your account".
    * The URL's purpose should be to directly verify an email, complete a sign-up, or reset a password.
    * Avoid extracting links to general settings pages, help articles, or the main website unless the surrounding text explicitly states this link is THE verification step. For example, a link to a security settings page in a "new login detected" email is NOT a verification URL for the login itself.

**Output Format Instructions (Strict Adherence Required):**
* You MUST return your response as a single, valid JSON object.
* Do NOT use markdown (e.g., \`\`\`json ... \`\`\`).
* Do NOT include any explanatory text, greetings, or conversational filler before or after the JSON object.
* The JSON object must conform to the following TypeScript interface:
    \`\`\`typescript
    interface AIProcessedEmail {
      code?: string | null;    // The verification code (continuous string, no spaces). Null if not found or not applicable.
      url?: string | null;     // The verification URL. Null if not found or not applicable.
    }\`\`\`
* **Crucially**: If the email's main purpose is NOT to provide an actionable verification item (as per the 'Informational or a Notification' category above), OR if an actionable email is identified but no code or URL is clearly found, you MUST return a JSON object with both \`code\` and \`url\` fields set to \`null\`.

**Examples:**

* **Input Email Snippet (Actionable - OTP):** "Your MyApp verification code is: 736190. Enter it to complete your login."
    **Output:** \`{ "code": "736190", "url": null }\`

* **Input Email Snippet (Actionable - URL):** "Thanks for signing up! Please click here to confirm your email address: https://service.example.com/confirm?token=xyz123"
    **Output:** \`{ "code": null, "url": "https://service.example.com/confirm?token=xyz123" }\`

* **Input Email Snippet (Informational - Login Notification - LIKE YOUR TWITCH EXAMPLE):** "Dear User, This email confirms a successful log-in to your account from New York. If this wasn't you, please secure your account by changing your password here: [link to general security page]."
    **Output:** \`{ "code": null, "url": null }\` (Because the primary purpose is notification, not providing a code/link to *complete* that login)

* **Input Email Snippet (Actionable, but code is part of URL text):** "Follow this link to reset your Mimo password: https://mimo.example.com/reset/a9fbad2f . The link contains your reset token."
    **Output:** \`{ "code": null, "url": "https://mimo.example.com/reset/a9fbad2f" }\` (AI should prioritize the actionable link)

* **Input Email Snippet (Ambiguous or Not Relevant):** "Check out our new security features! Learn more at [link to blog]."
    **Output:** \`{ "code": null, "url": null }\`

Process the following email content based on these detailed instructions and provide the JSON output.
  `.trim();
};
// Type definition for the expected OpenAI Chat Completion API response structure
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
  system_fingerprint?: string; // Added based on recent API versions
}

/**
 * Processes email content using an AI model to extract verification codes or URLs.
 *
 * @param emailBody The raw text content of the email.
 * @param config Configuration containing the OpenAI API key and optional model/endpoint.
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

  if (!config.openAIApiKey) {
    console.error("[AIProcessor] OpenAI API key missing.");
    return { code: null, url: null };
  }

  const modelName = config.openAIModelName || DEFAULT_OPENAI_MODEL;
  const endpoint = config.openAIEndpoint || DEFAULT_OPENAI_ENDPOINT;
  const systemPrompt = createSystemPrompt();

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

    if (!data.choices || data.choices.length === 0 || !data.choices[0].message || !data.choices[0].message.content) {
      console.error("[AIProcessor] OpenAI response missing expected content.", data);
      return { code: null, url: null };
    }

    const assistantMessageContent = data.choices[0].message.content;

    try {
      const processedEmail: AIProcessedEmail = JSON.parse(assistantMessageContent);

      if (typeof processedEmail !== 'object' || processedEmail === null) {
        console.error("[AIProcessor] Parsed AI response not an object:", processedEmail);
        return { code: null, url: null };
      }

      if (processedEmail.code === undefined && processedEmail.url === undefined) {
        console.error("[AIProcessor] AI JSON missing code/url fields. Raw:", assistantMessageContent.substring(0,500));
        return { code: null, url: null };
      }

      return {
        code: processedEmail.code !== undefined ? processedEmail.code : null,
        url: processedEmail.url !== undefined ? processedEmail.url : null
      };
    } catch (parseError: any) {
      console.error("[AIProcessor] CRITICAL: Error parsing AI JSON:", parseError.message, "Raw content:", assistantMessageContent.substring(0,500));
      return { code: null, url: null };
    }

  } catch (error: any) {
    console.error("[AIProcessor] Unexpected error:", error.message);
    return { code: null, url: null };
  }
}
