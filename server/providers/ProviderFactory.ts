/**
 * Multi-Cloud Provider Factory
 * 
 * Factory class for creating and managing cloud provider instances
 * for enterprise key management across AWS KMS, Azure Key Vault,
 * GCP KMS, HashiCorp Vault, and other providers.
 */

import { IProviderKMS, IProviderFactory } from './IProviderKMS';
import { AwsKmsAdapter } from './AwsKmsAdapter';
import { AzureKeyVaultAdapter } from './AzureKeyVaultAdapter';
import { GcpKmsAdapter } from './GcpKmsAdapter';
import { AwsKmsConfig, AzureKeyVaultConfig, GcpKmsConfig } from '@shared/schema';

export class ProviderFactory implements IProviderFactory {
  private static instance: ProviderFactory;
  private providers: Map<string, IProviderKMS> = new Map();

  private constructor() {}

  static getInstance(): ProviderFactory {
    if (!ProviderFactory.instance) {
      ProviderFactory.instance = new ProviderFactory();
    }
    return ProviderFactory.instance;
  }

  /**
   * Create a new provider instance
   */
  async createProvider(
    providerType: string,
    config: any,
    region: string,
    providerId?: string
  ): Promise<IProviderKMS> {
    const id = providerId || `${providerType}-${region}-${Date.now()}`;

    switch (providerType) {
      case 'aws_kms':
        return this.createAwsKmsProvider(config as AwsKmsConfig, id);
      
      case 'azure_key_vault':
        return this.createAzureKeyVaultProvider(config as AzureKeyVaultConfig, id);
      
      case 'gcp_kms':
        return this.createGcpKmsProvider(config as GcpKmsConfig, id);
      
      case 'hashicorp_vault':
        return this.createHashiCorpVaultProvider(config, id);
      
      case 'ibm_key_protect':
        return this.createIbmKeyProtectProvider(config, id);
      
      default:
        throw new Error(`Unsupported provider type: ${providerType}`);
    }
  }

  /**
   * Get an existing provider instance
   */
  getProvider(providerId: string): IProviderKMS | undefined {
    return this.providers.get(providerId);
  }

  /**
   * Cache a provider instance
   */
  cacheProvider(providerId: string, provider: IProviderKMS): void {
    this.providers.set(providerId, provider);
  }

  /**
   * Remove a provider instance from cache
   */
  removeProvider(providerId: string): void {
    this.providers.delete(providerId);
  }

  /**
   * Validate provider configuration
   */
  async validateConfig(providerType: string, config: any): Promise<boolean> {
    try {
      switch (providerType) {
        case 'aws_kms':
          return this.validateAwsKmsConfig(config as AwsKmsConfig);
        
        case 'azure_key_vault':
          return this.validateAzureKeyVaultConfig(config as AzureKeyVaultConfig);
        
        case 'gcp_kms':
          return this.validateGcpKmsConfig(config as GcpKmsConfig);
        
        case 'hashicorp_vault':
          return this.validateHashiCorpVaultConfig(config);
        
        case 'ibm_key_protect':
          return this.validateIbmKeyProtectConfig(config);
        
        default:
          return false;
      }
    } catch (error) {
      console.error(`Config validation failed for ${providerType}:`, error);
      return false;
    }
  }

  // ============================================================================
  // PROVIDER IMPLEMENTATIONS
  // ============================================================================

  private async createAwsKmsProvider(config: AwsKmsConfig, providerId: string): Promise<IProviderKMS> {
    const provider = new AwsKmsAdapter(config, providerId);
    
    // Test the connection
    const healthCheck = await provider.healthCheck();
    if (!healthCheck.healthy) {
      throw new Error(`AWS KMS provider health check failed: ${healthCheck.error}`);
    }
    
    this.cacheProvider(providerId, provider);
    return provider;
  }

  private async createAzureKeyVaultProvider(config: AzureKeyVaultConfig, providerId: string): Promise<IProviderKMS> {
    const provider = new AzureKeyVaultAdapter(config, providerId);
    
    // Test the connection
    const healthCheck = await provider.healthCheck();
    if (!healthCheck.healthy) {
      throw new Error(`Azure Key Vault provider health check failed: ${healthCheck.error}`);
    }
    
    this.cacheProvider(providerId, provider);
    return provider;
  }

  private async createGcpKmsProvider(config: GcpKmsConfig, providerId: string): Promise<IProviderKMS> {
    const provider = new GcpKmsAdapter(config, providerId);
    
    // Test the connection
    const healthCheck = await provider.healthCheck();
    if (!healthCheck.healthy) {
      throw new Error(`GCP KMS provider health check failed: ${healthCheck.error}`);
    }
    
    this.cacheProvider(providerId, provider);
    return provider;
  }

  private async createHashiCorpVaultProvider(config: any, providerId: string): Promise<IProviderKMS> {
    // TODO: Implement HashiCorp Vault adapter
    throw new Error('HashiCorp Vault provider not yet implemented');
  }

  private async createIbmKeyProtectProvider(config: any, providerId: string): Promise<IProviderKMS> {
    // TODO: Implement IBM Key Protect adapter
    throw new Error('IBM Key Protect provider not yet implemented');
  }

  // ============================================================================
  // CONFIG VALIDATION
  // ============================================================================

  private validateAwsKmsConfig(config: AwsKmsConfig): boolean {
    if (!config.accessKeyId || !config.secretAccessKey || !config.region) {
      return false;
    }

    // Basic validation for AWS region format
    const regionPattern = /^[a-z]{2}-[a-z]+-\d{1}$/;
    if (!regionPattern.test(config.region)) {
      return false;
    }

    return true;
  }

  private validateAzureKeyVaultConfig(config: AzureKeyVaultConfig): boolean {
    if (!config.clientId || !config.clientSecret || !config.tenantId || !config.vaultUrl) {
      return false;
    }

    // Basic validation for Azure tenant ID format (GUID)
    const guidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!guidPattern.test(config.tenantId)) {
      return false;
    }

    // Basic validation for vault URL
    if (!config.vaultUrl.startsWith('https://')) {
      return false;
    }

    return true;
  }

  private validateGcpKmsConfig(config: GcpKmsConfig): boolean {
    if (!config.projectId || !config.keyRingId || !config.locationId || !config.serviceAccountKey) {
      return false;
    }

    try {
      // Validate service account key is valid JSON
      JSON.parse(config.serviceAccountKey);
      return true;
    } catch {
      return false;
    }
  }

  private validateHashiCorpVaultConfig(config: any): boolean {
    // TODO: Implement HashiCorp Vault config validation
    return false;
  }

  private validateIbmKeyProtectConfig(config: any): boolean {
    // TODO: Implement IBM Key Protect config validation
    return false;
  }

  // ============================================================================
  // UTILITY METHODS
  // ============================================================================

  /**
   * Get supported provider types
   */
  getSupportedProviders(): Array<{
    type: string;
    name: string;
    description: string;
    regions?: string[];
  }> {
    return [
      {
        type: 'aws_kms',
        name: 'AWS Key Management Service',
        description: 'Fully managed encryption key service from Amazon Web Services',
        regions: [
          'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
          'eu-west-1', 'eu-west-2', 'eu-central-1', 'eu-north-1',
          'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2',
          'ca-central-1', 'sa-east-1'
        ]
      },
      {
        type: 'azure_key_vault',
        name: 'Azure Key Vault',
        description: 'Cloud-based key management service from Microsoft Azure',
        regions: [
          'eastus', 'eastus2', 'westus', 'westus2', 'centralus',
          'northeurope', 'westeurope', 'uksouth', 'ukwest',
          'southeastasia', 'eastasia', 'japaneast', 'japanwest',
          'australiaeast', 'australiasoutheast'
        ]
      },
      {
        type: 'gcp_kms',
        name: 'Google Cloud Key Management',
        description: 'Cryptographic key management service from Google Cloud Platform',
        regions: [
          'us-central1', 'us-east1', 'us-east4', 'us-west1', 'us-west2',
          'europe-west1', 'europe-west2', 'europe-west3', 'europe-west4',
          'asia-east1', 'asia-northeast1', 'asia-southeast1', 'asia-south1',
          'australia-southeast1'
        ]
      },
      {
        type: 'hashicorp_vault',
        name: 'HashiCorp Vault',
        description: 'Identity-based secrets and encryption management system',
      },
      {
        type: 'ibm_key_protect',
        name: 'IBM Key Protect',
        description: 'Full-service encryption solution for IBM Cloud',
      }
    ];
  }

  /**
   * Encrypt configuration data for storage
   */
  async encryptConfig(config: any, masterKey: string): Promise<string> {
    // TODO: Implement config encryption using the master key
    // For now, just base64 encode (NOT secure for production)
    return Buffer.from(JSON.stringify(config)).toString('base64');
  }

  /**
   * Decrypt configuration data from storage
   */
  async decryptConfig(encryptedConfig: string, masterKey: string): Promise<any> {
    // TODO: Implement config decryption using the master key
    // For now, just base64 decode (NOT secure for production)
    return JSON.parse(Buffer.from(encryptedConfig, 'base64').toString());
  }

  /**
   * Test provider connectivity
   */
  async testConnection(providerType: string, config: any): Promise<{
    success: boolean;
    responseTime?: number;
    error?: string;
  }> {
    const startTime = Date.now();
    
    try {
      const provider = await this.createProvider(providerType, config, config.region, 'test-connection');
      const healthCheck = await provider.healthCheck();
      
      return {
        success: healthCheck.healthy,
        responseTime: Date.now() - startTime,
        error: healthCheck.error,
      };
    } catch (error: any) {
      return {
        success: false,
        responseTime: Date.now() - startTime,
        error: error.message,
      };
    }
  }
}

// Export singleton instance
export const providerFactory = ProviderFactory.getInstance();