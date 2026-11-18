import {
  FunctionCallingConfigMode,
  GoogleGenAI,
  HarmBlockThreshold,
  HarmCategory,
  type Content,
  type FunctionDeclaration,
} from '@google/genai';

/**
 * A narrow interface over the Gemini API so the agent loop can be tested with
 * a scripted fake model and the SDK stays at the edge of the system.
 */

export interface ModelCall {
  id?: string;
  name: string;
  args: Record<string, unknown>;
}

export interface ModelRequest {
  model: string;
  systemInstruction: string;
  contents: Content[];
  tools: FunctionDeclaration[];
  signal: AbortSignal;
}

export interface ModelResponse {
  /** The model turn exactly as returned (preserves thought signatures). */
  content: Content;
  calls: ModelCall[];
  usage: { input: number; output: number };
}

export interface ModelClient {
  generate(req: ModelRequest): Promise<ModelResponse>;
}

export class GeminiClient implements ModelClient {
  private readonly ai: GoogleGenAI;

  constructor(apiKey: string) {
    this.ai = new GoogleGenAI({ apiKey });
  }

  async generate(req: ModelRequest): Promise<ModelResponse> {
    const response = await this.ai.models.generateContent({
      model: req.model,
      contents: req.contents,
      config: {
        systemInstruction: req.systemInstruction,
        tools: [{ functionDeclarations: req.tools }],
        toolConfig: { functionCallingConfig: { mode: FunctionCallingConfigMode.ANY } },
        temperature: 1.0,
        maxOutputTokens: 4096,
        abortSignal: req.signal,
        safetySettings: [
          {
            category: HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
            threshold: HarmBlockThreshold.BLOCK_ONLY_HIGH,
          },
          {
            category: HarmCategory.HARM_CATEGORY_HARASSMENT,
            threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
          },
        ],
      },
    });
    const content = response.candidates?.[0]?.content ?? { role: 'model', parts: [] };
    const calls: ModelCall[] = (response.functionCalls ?? []).map((c) => ({
      ...(c.id ? { id: c.id } : {}),
      name: c.name ?? '',
      args: c.args ?? {},
    }));
    return {
      content,
      calls,
      usage: {
        input: response.usageMetadata?.promptTokenCount ?? 0,
        output: response.usageMetadata?.candidatesTokenCount ?? 0,
      },
    };
  }
}
