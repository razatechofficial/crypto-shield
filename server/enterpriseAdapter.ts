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
      // Use dynamic import with proper path resolution for production
      const { createRequire } = await import('module');
      const require = createRequire(import.meta.url);
      const { FixedEnterpriseSDKGenerator } = require("../enterprise-sdk-generator-fixed.cjs");

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
            fileMap = FixedEnterpriseSDKGenerator.generateJavaScriptSDK(sdk, algorithms);
            break;
          
          case 'python':
            fileMap = FixedEnterpriseSDKGenerator.generatePythonSDK(sdk, algorithms);
            break;
            
          case 'java':
            fileMap = FixedEnterpriseSDKGenerator.generateJavaSDK(sdk, algorithms);
            break;
            
          case 'c':
          case 'c++':
          case 'cpp':
            fileMap = FixedEnterpriseSDKGenerator.generateCSDK(sdk, algorithms);
            break;
            
          case 'csharp':
          case 'c#':
            fileMap = FixedEnterpriseSDKGenerator.generateCSharpSDK(sdk, algorithms);
            break;
            
          case 'swift':
            fileMap = FixedEnterpriseSDKGenerator.generateSwiftSDK(sdk, algorithms);
            break;
          
          default:
            console.log(`⚠️ Language ${language} not yet implemented, using JavaScript SDK`);
            fileMap = FixedEnterpriseSDKGenerator.generateJavaScriptSDK(sdk, algorithms);
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