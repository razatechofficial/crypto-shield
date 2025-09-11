/**
 * Government Compliance Validation Toolkit
 * Comprehensive validation for FIPS 140-3, Common Criteria, and PQC readiness
 * 
 * CLASSIFICATION: Government-Level Security Compliance
 * VERSION: 2.0.0
 * STANDARDS: FIPS 140-3, NIST SP 800-175B, NSA CNSA 2.0
 */

import { EncryptionAlgorithm } from "@shared/schema";

export interface ComplianceRequirement {
  level: 'standard' | 'enhanced' | 'maximum' | 'confidential' | 'classified';
  fipsRequired: boolean;
  quantumSafe: boolean;
  minimumSecurityStrength: number;
  approvedAlgorithms: string[];
  prohibitedAlgorithms: string[];
  keyManagementRequirements: string[];
}

export interface ComplianceAssessment {
  compliant: boolean;
  level: string;
  score: number;
  findings: ComplianceFinding[];
  recommendations: string[];
  migrationPlan?: QuantumMigrationPlan;
}

export interface ComplianceFinding {
  type: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: 'algorithm' | 'implementation' | 'key_management' | 'quantum_readiness';
  message: string;
  recommendation: string;
  affected: string[];
}

export interface QuantumMigrationPlan {
  currentRiskLevel: 'low' | 'medium' | 'high' | 'critical';
  timelineYears: number;
  phases: MigrationPhase[];
  estimatedCost: string;
  priorityActions: string[];
}

export interface MigrationPhase {
  phase: number;
  name: string;
  timeline: string;
  actions: string[];
  algorithms: string[];
  riskReduction: number;
}

/**
 * Government Compliance Profiles
 */
export const COMPLIANCE_PROFILES = {
  // NIST Framework
  NIST_COMMERCIAL: {
    level: 'standard' as const,
    fipsRequired: false,
    quantumSafe: false,
    minimumSecurityStrength: 128,
    approvedAlgorithms: ['AES-256-GCM', 'ChaCha20-Poly1305', 'ECDSA-P256', 'Ed25519'],
    prohibitedAlgorithms: ['DES', 'MD5', 'SHA-1', 'RSA-1024'],
    keyManagementRequirements: ['key_rotation', 'secure_storage']
  },
  
  // FIPS 140-3 Level 1
  FIPS_140_3_L1: {
    level: 'enhanced' as const,
    fipsRequired: true,
    quantumSafe: false,
    minimumSecurityStrength: 128,
    approvedAlgorithms: ['AES-256-GCM', 'AES-192-GCM', 'RSA-3072', 'ECDSA-P256', 'SHA-256'],
    prohibitedAlgorithms: ['ChaCha20-Poly1305', 'Ed25519', 'X25519'],
    keyManagementRequirements: ['fips_validated_modules', 'key_rotation', 'audit_logging']
  },
  
  // FIPS 140-3 Level 2+ (Hardware)
  FIPS_140_3_L2: {
    level: 'maximum' as const,
    fipsRequired: true,
    quantumSafe: false,
    minimumSecurityStrength: 192,
    approvedAlgorithms: ['AES-256-GCM', 'RSA-4096', 'ECDSA-P384', 'SHA-384'],
    prohibitedAlgorithms: ['ChaCha20-Poly1305', 'AES-128-*'],
    keyManagementRequirements: ['hardware_security_module', 'tamper_evidence', 'role_based_auth']
  },
  
  // NSA CNSA 2.0 (Post-Quantum Ready)
  NSA_CNSA_2_0: {
    level: 'confidential' as const,
    fipsRequired: true,
    quantumSafe: true,
    minimumSecurityStrength: 256,
    approvedAlgorithms: ['ML-KEM-1024', 'ML-DSA-87', 'SLH-DSA-SHA2-128s', 'AES-256-GCM'],
    prohibitedAlgorithms: ['RSA-*', 'ECDSA-*', 'DH-*'],
    keyManagementRequirements: ['post_quantum_kem', 'quantum_safe_protocols', 'hybrid_migration']
  },
  
  // Suite B (Legacy Government)
  NSA_SUITE_B: {
    level: 'confidential' as const,
    fipsRequired: true,
    quantumSafe: false,
    minimumSecurityStrength: 192,
    approvedAlgorithms: ['AES-256-GCM', 'ECDSA-P384', 'ECDH-P384', 'SHA-384'],
    prohibitedAlgorithms: ['RSA-*', 'DH-*', 'ChaCha20-*'],
    keyManagementRequirements: ['elliptic_curve_only', 'suite_b_compliance', 'hardware_protection']
  },
  
  // Classified Systems (Top Secret)
  TOP_SECRET: {
    level: 'classified' as const,
    fipsRequired: true,
    quantumSafe: true,
    minimumSecurityStrength: 256,
    approvedAlgorithms: ['ML-KEM-1024', 'ML-DSA-87', 'SLH-DSA-SHAKE-128s', 'AES-256-GCM'],
    prohibitedAlgorithms: ['*classical_asymmetric*'],
    keyManagementRequirements: ['type1_encryption', 'quantum_safe_only', 'offline_key_generation']
  }
};

/**
 * FIPS 140-3 Algorithm Validation Database
 */
export const FIPS_VALIDATIONS = {
  'AES-128-GCM': { cert: '4282', level: 1, vendor: 'OpenSSL FIPS Module' },
  'AES-192-GCM': { cert: '4282', level: 1, vendor: 'OpenSSL FIPS Module' },
  'AES-256-GCM': { cert: '4282', level: 1, vendor: 'OpenSSL FIPS Module' },
  'SHA-256': { cert: '4284', level: 1, vendor: 'OpenSSL FIPS Module' },
  'SHA-384': { cert: '4284', level: 1, vendor: 'OpenSSL FIPS Module' },
  'SHA-512': { cert: '4284', level: 1, vendor: 'OpenSSL FIPS Module' },
  'HMAC-SHA256': { cert: '3752', level: 1, vendor: 'OpenSSL FIPS Module' },
  'RSA-2048': { cert: '4285', level: 1, vendor: 'OpenSSL FIPS Module' },
  'RSA-3072': { cert: '4285', level: 1, vendor: 'OpenSSL FIPS Module' },
  'ECDSA-P256': { cert: '4286', level: 1, vendor: 'OpenSSL FIPS Module' },
  'ECDSA-P384': { cert: '4286', level: 1, vendor: 'OpenSSL FIPS Module' }
};

/**
 * Government Compliance Validator
 */
export class GovernmentComplianceValidator {
  
  /**
   * Assess algorithm compliance against government standards
   */
  static assessAlgorithmCompliance(
    algorithms: EncryptionAlgorithm[],
    profileName: keyof typeof COMPLIANCE_PROFILES
  ): ComplianceAssessment {
    const profile = COMPLIANCE_PROFILES[profileName];
    const findings: ComplianceFinding[] = [];
    let score = 100;
    
    // Check FIPS requirements
    if (profile.fipsRequired) {
      const nonFipsAlgorithms = algorithms.filter(alg => !alg.fipsValidated);
      if (nonFipsAlgorithms.length > 0) {
        findings.push({
          type: 'critical',
          category: 'algorithm',
          message: 'Non-FIPS validated algorithms detected',
          recommendation: 'Replace with FIPS 140-3 validated alternatives',
          affected: nonFipsAlgorithms.map(a => a.name)
        });
        score -= 25;
      }
    }
    
    // Check quantum safety requirements
    if (profile.quantumSafe) {
      const quantumVulnerable = algorithms.filter(alg => !alg.isQuantumSafe);
      if (quantumVulnerable.length > 0) {
        findings.push({
          type: 'high',
          category: 'quantum_readiness',
          message: 'Quantum-vulnerable algorithms in use',
          recommendation: 'Implement post-quantum cryptography migration plan',
          affected: quantumVulnerable.map(a => a.name)
        });
        score -= 20;
      }
    }
    
    // Check minimum security strength
    const weakAlgorithms = algorithms.filter(alg => 
      alg.securityStrength && alg.securityStrength < profile.minimumSecurityStrength
    );
    if (weakAlgorithms.length > 0) {
      findings.push({
        type: 'medium',
        category: 'algorithm',
        message: 'Algorithms below minimum security strength',
        recommendation: `Upgrade to algorithms with ${profile.minimumSecurityStrength}-bit security`,
        affected: weakAlgorithms.map(a => a.name)
      });
      score -= 15;
    }
    
    // Check prohibited algorithms
    const prohibitedInUse = algorithms.filter(alg =>
      profile.prohibitedAlgorithms.some(prohibited => 
        alg.name.includes(prohibited.replace('*', ''))
      )
    );
    if (prohibitedInUse.length > 0) {
      findings.push({
        type: 'critical',
        category: 'algorithm',
        message: 'Prohibited algorithms detected',
        recommendation: 'Remove or replace prohibited algorithms immediately',
        affected: prohibitedInUse.map(a => a.name)
      });
      score -= 30;
    }
    
    // Generate recommendations
    const recommendations = this.generateRecommendations(findings, profile);
    
    // Create migration plan if quantum safety required
    const migrationPlan = profile.quantumSafe ? 
      this.createQuantumMigrationPlan(algorithms) : undefined;
    
    return {
      compliant: score >= 80 && findings.filter(f => f.type === 'critical').length === 0,
      level: profile.level,
      score: Math.max(0, score),
      findings,
      recommendations,
      migrationPlan
    };
  }
  
  /**
   * Generate compliance recommendations
   */
  private static generateRecommendations(
    findings: ComplianceFinding[],
    profile: ComplianceRequirement
  ): string[] {
    const recommendations: string[] = [];
    
    const criticalFindings = findings.filter(f => f.type === 'critical');
    if (criticalFindings.length > 0) {
      recommendations.push('IMMEDIATE ACTION REQUIRED: Address critical compliance violations');
    }
    
    if (profile.fipsRequired) {
      recommendations.push('Ensure all cryptographic operations use FIPS 140-3 validated modules');
      recommendations.push('Implement FIPS-compliant key management procedures');
    }
    
    if (profile.quantumSafe) {
      recommendations.push('Begin post-quantum cryptography migration planning');
      recommendations.push('Implement hybrid classical+PQC algorithms for transition period');
    }
    
    recommendations.push('Conduct regular compliance audits and algorithm reviews');
    recommendations.push('Maintain updated cryptographic inventory and risk assessments');
    
    return recommendations;
  }
  
  /**
   * Create quantum migration plan
   */
  private static createQuantumMigrationPlan(algorithms: EncryptionAlgorithm[]): QuantumMigrationPlan {
    const quantumVulnerable = algorithms.filter(alg => !alg.isQuantumSafe);
    const riskLevel = quantumVulnerable.length > 5 ? 'critical' : 
                     quantumVulnerable.length > 2 ? 'high' : 
                     quantumVulnerable.length > 0 ? 'medium' : 'low';
    
    return {
      currentRiskLevel: riskLevel,
      timelineYears: 3,
      phases: [
        {
          phase: 1,
          name: 'Assessment and Planning',
          timeline: '2025 Q1-Q2',
          actions: [
            'Complete cryptographic inventory',
            'Assess quantum computing threat timeline',
            'Develop migration strategy and priorities'
          ],
          algorithms: [],
          riskReduction: 0
        },
        {
          phase: 2,
          name: 'Hybrid Implementation',
          timeline: '2025 Q3-2026 Q4',
          actions: [
            'Deploy hybrid classical+PQC algorithms',
            'Update key management infrastructure',
            'Begin PQC algorithm testing and validation'
          ],
          algorithms: ['ML-KEM-768+ECDH-P256', 'ML-DSA-65+ECDSA-P256'],
          riskReduction: 60
        },
        {
          phase: 3,
          name: 'Full PQC Migration',
          timeline: '2027-2028',
          actions: [
            'Complete migration to post-quantum algorithms',
            'Deprecate classical asymmetric cryptography',
            'Validate quantum-safe infrastructure'
          ],
          algorithms: ['ML-KEM-1024', 'ML-DSA-87', 'SLH-DSA-SHA2-128s'],
          riskReduction: 95
        }
      ],
      estimatedCost: '$250K - $500K depending on infrastructure complexity',
      priorityActions: [
        'Replace RSA/ECDSA in new systems immediately',
        'Implement ML-KEM for key establishment',
        'Begin testing ML-DSA for digital signatures',
        'Plan hardware security module upgrades'
      ]
    };
  }
  
  /**
   * Validate FIPS compliance
   */
  static validateFIPSCompliance(algorithms: EncryptionAlgorithm[]): {
    compliant: boolean;
    validatedAlgorithms: string[];
    nonValidatedAlgorithms: string[];
    recommendations: string[];
  } {
    const validatedAlgorithms: string[] = [];
    const nonValidatedAlgorithms: string[] = [];
    
    algorithms.forEach(alg => {
      if (alg.fipsValidated && FIPS_VALIDATIONS[alg.name]) {
        validatedAlgorithms.push(alg.name);
      } else {
        nonValidatedAlgorithms.push(alg.name);
      }
    });
    
    const recommendations: string[] = [];
    if (nonValidatedAlgorithms.length > 0) {
      recommendations.push('Replace non-FIPS algorithms with validated alternatives');
      recommendations.push('Implement FIPS 140-3 validated cryptographic modules');
      recommendations.push('Ensure proper FIPS mode configuration and testing');
    }
    
    return {
      compliant: nonValidatedAlgorithms.length === 0,
      validatedAlgorithms,
      nonValidatedAlgorithms,
      recommendations
    };
  }
  
  /**
   * Assess quantum readiness
   */
  static assessQuantumReadiness(algorithms: EncryptionAlgorithm[]): {
    readinessScore: number;
    quantumSafeAlgorithms: number;
    quantumVulnerableAlgorithms: number;
    migrationProgress: number;
    recommendations: string[];
  } {
    const total = algorithms.length;
    const quantumSafe = algorithms.filter(alg => alg.isQuantumSafe).length;
    const quantumVulnerable = total - quantumSafe;
    
    const readinessScore = Math.round((quantumSafe / total) * 100);
    const migrationProgress = readinessScore;
    
    const recommendations: string[] = [];
    if (readinessScore < 25) {
      recommendations.push('URGENT: Begin immediate post-quantum migration planning');
      recommendations.push('Implement hybrid algorithms for critical systems');
    } else if (readinessScore < 50) {
      recommendations.push('Accelerate post-quantum algorithm adoption');
      recommendations.push('Prioritize migration of high-risk systems');
    } else if (readinessScore < 75) {
      recommendations.push('Complete remaining quantum-vulnerable algorithm migrations');
      recommendations.push('Validate post-quantum implementations');
    } else {
      recommendations.push('Maintain quantum-safe cryptography leadership');
      recommendations.push('Monitor for new post-quantum standards');
    }
    
    return {
      readinessScore,
      quantumSafeAlgorithms: quantumSafe,
      quantumVulnerableAlgorithms: quantumVulnerable,
      migrationProgress,
      recommendations
    };
  }

  /**
   * Recommend a compliance profile based on requirements
   */
  static recommendComplianceProfile(requirements: {
    securityLevel: string;
    dataTypes: string[];
    complianceRequirements: string[];
  }) {
    const { securityLevel, dataTypes, complianceRequirements } = requirements;
    
    // Check for government/classified data requirements
    if (dataTypes.includes('government') || dataTypes.includes('classified')) {
      return {
        recommendedProfile: 'TOP_SECRET',
        rationale: 'Classified or government data requires Top Secret compliance with Type 1 encryption',
        profile: COMPLIANCE_PROFILES.TOP_SECRET,
        urgency: 'critical'
      };
    }
    
    // Check for FIPS requirements
    const requiresFips = complianceRequirements.some(req => 
      req.includes('FIPS') || req.includes('FedRAMP') || req.includes('FISMA')
    );
    
    // Check for quantum readiness requirements
    const requiresQuantumSafe = securityLevel === 'post_quantum' || 
      securityLevel === 'quantum_ready' ||
      complianceRequirements.includes('post-quantum');
    
    // Determine appropriate profile
    if (requiresQuantumSafe && requiresFips) {
      return {
        recommendedProfile: 'NSA_CNSA_2_0',
        rationale: 'Post-quantum readiness with FIPS requirements suggests NSA CNSA 2.0',
        profile: COMPLIANCE_PROFILES.NSA_CNSA_2_0,
        urgency: 'high'
      };
    } else if (requiresFips && securityLevel === 'maximum') {
      return {
        recommendedProfile: 'FIPS_140_3_L2',
        rationale: 'Maximum security level with FIPS requirements needs FIPS 140-3 Level 2+',
        profile: COMPLIANCE_PROFILES.FIPS_140_3_L2,
        urgency: 'high'
      };
    } else if (requiresFips) {
      return {
        recommendedProfile: 'FIPS_140_3_L1',
        rationale: 'FIPS compliance requirements suggest FIPS 140-3 Level 1',
        profile: COMPLIANCE_PROFILES.FIPS_140_3_L1,
        urgency: 'medium'
      };
    } else if (requiresQuantumSafe) {
      return {
        recommendedProfile: 'NSA_CNSA_2_0',
        rationale: 'Quantum-safe requirements recommend NSA CNSA 2.0 for future readiness',
        profile: COMPLIANCE_PROFILES.NSA_CNSA_2_0,
        urgency: 'medium'
      };
    } else if (dataTypes.some(type => 
      ['financial', 'medical', 'biometric'].includes(type)
    )) {
      return {
        recommendedProfile: 'FIPS_140_3_L1',
        rationale: 'Sensitive personal/financial data suggests FIPS 140-3 compliance',
        profile: COMPLIANCE_PROFILES.FIPS_140_3_L1,
        urgency: 'medium'
      };
    } else {
      return {
        recommendedProfile: 'NIST_COMMERCIAL',
        rationale: 'General commercial applications can use NIST commercial standards',
        profile: COMPLIANCE_PROFILES.NIST_COMMERCIAL,
        urgency: 'low'
      };
    }
  }
}

/**
 * Export compliance toolkit
 */
export const ComplianceToolkit = {
  profiles: COMPLIANCE_PROFILES,
  validator: GovernmentComplianceValidator,
  fipsValidations: FIPS_VALIDATIONS
};

export default ComplianceToolkit;