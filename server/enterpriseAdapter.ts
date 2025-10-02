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
            
          case 'android':
          case 'kotlin':
            fileMap = FixedEnterpriseSDKGenerator.generateAndroidSDK(sdk, algorithms);
            break;
          
          case 'go':
            fileMap = FixedEnterpriseSDKGenerator.generateGoSDK(sdk, algorithms);
            break;
          
          case 'rust':
            fileMap = FixedEnterpriseSDKGenerator.generateRustSDK(sdk, algorithms);
            break;
          
          case 'php':
            fileMap = FixedEnterpriseSDKGenerator.generatePHPSDK(sdk, algorithms);
            break;
          
          case 'ruby':
            fileMap = FixedEnterpriseSDKGenerator.generateRubySDK(sdk, algorithms);
            break;
          
          case 'scala':
            fileMap = FixedEnterpriseSDKGenerator.generateScalaSDK(sdk, algorithms);
            break;
          
          case 'dart':
            fileMap = FixedEnterpriseSDKGenerator.generateDartSDK(sdk, algorithms);
            break;
          
          case 'objectivec':
            fileMap = FixedEnterpriseSDKGenerator.generateSwiftSDK(sdk, algorithms); // Objective-C uses Swift SDK
            break;
          
          case 'reactnative':
            fileMap = FixedEnterpriseSDKGenerator.generateJavaScriptSDK(sdk, algorithms); // React Native uses JavaScript SDK
            break;
          
          case 'xamarin':
            fileMap = FixedEnterpriseSDKGenerator.generateCSharpSDK(sdk, algorithms); // Xamarin uses C# SDK
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
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      throw new Error(`Failed to generate enterprise SDK: ${errorMessage}`);
    }
  }
}