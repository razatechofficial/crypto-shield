/**
 * Enterprise SDK Generator Adapter
 * Provides clean TypeScript interface to the CommonJS enterprise generator
 */

export interface SDKGeneratorResult {
  [filePath: string]: string;
}

export interface SDK {
  name: string;
  version: string;
  languages: string | string[];
  algorithms: string | string[];
}

export class EnterpriseAdapter {
  /**
   * Generate production-ready SDK using the enterprise generator
   */
  static async generateSDK(sdk: SDK, languages: string[]): Promise<Record<string, SDKGeneratorResult>> {
    try {
      // Use require for CommonJS module to avoid import path issues in production
      const EnterpriseSDKGenerator = require("../enterprise-sdk-generator.cjs");

      // Parse algorithms safely
      const algorithms = Array.isArray(sdk.algorithms) 
        ? sdk.algorithms 
        : JSON.parse(sdk.algorithms);

      const results: Record<string, SDKGeneratorResult> = {};

      // Generate SDK for each language
      for (const language of languages) {
        console.log(`🏭 Generating ENTERPRISE-GRADE ${language} SDK with ALL 18 security gates...`);
        
        let fileMap: Record<string, string> = {};
        
        switch(language.toLowerCase()) {
          case 'javascript':
          case 'typescript':
            // Generate REAL JavaScript SDK with ALL security gates
            fileMap = EnterpriseSDKGenerator.generateJavaScriptSDK(sdk, algorithms);
            break;
          
          default:
            console.log(`⚠️ Language ${language} using JavaScript fallback with enterprise generator`);
            fileMap = EnterpriseSDKGenerator.generateJavaScriptSDK(sdk, algorithms);
            break;
        }
        
        results[language.toLowerCase()] = fileMap;
      }

      return results;
    } catch (error) {
      console.error('❌ Enterprise SDK generation failed:', error);
      throw new Error(`Failed to generate enterprise SDK: ${error.message}`);
    }
  }
}