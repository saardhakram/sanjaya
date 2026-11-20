import { FunctionCallingConfigMode, GoogleGenAI, HarmBlockThreshold, HarmCategory, } from '@google/genai';
export class GeminiClient {
    ai;
    constructor(apiKey) {
        this.ai = new GoogleGenAI({ apiKey });
    }
    async generate(req) {
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
        const calls = (response.functionCalls ?? []).map((c) => ({
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
