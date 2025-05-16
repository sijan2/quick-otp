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
You are an AI assistant specialized in parsing email content to extract actionable user verification items (OTPs or verification/password reset links). Your task is to analyze the following email content and determine if it contains such items for immediate use by the user.
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
            content: `
						You are an AI assistant specialized in parsing email content to extract actionable user verification items (OTPs or verification/password reset links). Your task is to analyze the following email content and determine if it contains such items for immediate use by the user.

							Here is the email content to analyze:

							<email_content>
							${emailBody}
							</email_content>

							Please follow these steps to process the email:

							1. Determine Email Intent:
								Analyze the email to classify its primary intent as either ACTIONABLE VERIFICATION or INFORMATIONAL / NOT ACTIONABLE.

							2. Extract Verification Code (if applicable):
								- Look for explicitly labeled codes such as "verification code", "OTP", "one-time password", "confirmation code", "security code", "auth code", "your single-use code is", "enter this code".
								- Codes are typically 4-10 characters (digits or alphanumeric).
								- Remove spaces within codes (e.g., "123 456" becomes "123456").
								- Preserve hyphens if they are part of the code's structure (e.g., "ABC-123").

							3. Extract Verification URL (if applicable):
								- Prioritize URLs from HTML <a> tags if available.
								- Look for link text or surrounding text like "confirm email", "verify account", "reset password", "activate account", "Sign In", "Verify".
								- Process the URL:
									a. HTML Decode: Fully decode HTML entities.
									b. Quoted-Printable Decode: Fully decode quoted-printable encodings.
								- Validate the decoded URL:
									a. Handle Google Redirects: If the host is google.com with a q= or url= parameter, extract and URL-decode its value.
									b. Check for proper parameter structure (name=value).
									c. For Perplexity-specific structure, ensure parameters like callbackUrl=..., token=..., email=... are present with the "=" sign and a value.
									d. IMPORTANT: Always include the "=" sign after the email parameter in the URL.
								- Select the most relevant URL if multiple valid ones are found.

							4. Prepare Output:
								Return a single, valid JSON object in the following format:
								{ "code": string | null, "url": string | null }
								If no actionable code or URL is found, or if the email intent is Informational, both code and url MUST be null for example if the email is about you just changed your password and even if it contains password resest link dont put it in actionable category just return null for both code and url as it is not actionable.
							`,
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
