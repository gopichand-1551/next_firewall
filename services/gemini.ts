import { GoogleGenAI, Type } from "@google/genai";
import { AnalysisResult, Severity, AnalysisType } from "../types";

// Initialize Gemini Client
const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
const MODEL_NAME = "gemini-2.5-flash";

export const analyzeContent = async (
  content: string,
  type: AnalysisType
): Promise<AnalysisResult> => {
  try {
    let systemInstruction = "";

    switch (type) {
      case AnalysisType.SQL_INJECTION:
        systemInstruction = `You are a cybersecurity expert specializing in SQL Injection detection. 
        Analyze the provided input string. Determine if it contains malicious SQL patterns, tautologies, union-based attacks, or blindly injected commands.`;
        break;
      case AnalysisType.PHISHING:
        systemInstruction = `You are a security analyst specializing in Phishing and Social Engineering. 
        Analyze the provided URL or Email content. Look for homograph attacks, suspicious domains, urgency cues, and malicious payload signatures.`;
        break;
      case AnalysisType.MALWARE:
        systemInstruction = `You are a malware analyst. Analyze the provided file metadata, script content, or heuristic behavior description. 
        Identify potential obfuscation, shellcode, or dangerous system calls.`;
        break;
      case AnalysisType.PACKET_INSPECTION:
        systemInstruction = `You are a Next-Generation Firewall (NGFW) Deep Packet Inspection (DPI) engine. 
        Analyze the raw packet payload (hex or string representation). Identify command and control (C2) beacons, exfiltration attempts, or exploit signatures.`;
        break;
      case AnalysisType.DOS_DDOS:
        systemInstruction = `You are a Network Reliability Engineer specializing in DDoS mitigation. 
        Analyze the provided traffic metrics (RPS, Protocol distribution, Source IP count). 
        Distinguish between normal traffic spikes, Volumetric DDoS (UDP/ICMP floods), and Application Layer attacks (Slowloris, HTTP Flood).`;
        break;
    }

    const response = await ai.models.generateContent({
      model: MODEL_NAME,
      contents: content,
      config: {
        systemInstruction: systemInstruction,
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            isThreat: { type: Type.BOOLEAN },
            severity: { type: Type.STRING, enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL", "SAFE"] },
            reasoning: { type: Type.STRING },
            suggestedAction: { type: Type.STRING },
            technicalDetails: { type: Type.STRING },
          },
          required: ["isThreat", "severity", "reasoning", "suggestedAction"],
        },
      },
    });

    if (!response.text) {
      throw new Error("No response from AI");
    }

    const result = JSON.parse(response.text) as AnalysisResult;
    return result;
  } catch (error) {
    console.error("Gemini Analysis Error:", error);
    return {
      isThreat: false,
      severity: Severity.LOW,
      reasoning: "Analysis failed due to API error. Defaulting to fail-open (safe).",
      suggestedAction: "Check API Key and connectivity.",
    };
  }
};

export const generateMockPacket = async (): Promise<string> => {
  // Helper to generate realistic looking packet payloads for simulation
  try {
    const response = await ai.models.generateContent({
      model: MODEL_NAME,
      contents: "Generate a random network packet payload string. It can be a normal HTTP request, a SQL injection attempt, or a binary C2 heartbeat. Just return the payload string, nothing else.",
    });
    return response.text || "GET / HTTP/1.1";
  } catch {
    return "PING 192.168.1.1";
  }
}