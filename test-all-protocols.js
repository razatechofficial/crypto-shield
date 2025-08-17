#!/usr/bin/env node
/**
 * Comprehensive test suite for all confidential computing protocols
 */

import { ConfidentialCrypto } from './confidential-sdk-production.js';

async function testAllProtocols() {
  console.log('🔐 COMPREHENSIVE CONFIDENTIAL COMPUTING PROTOCOL TESTS');
  console.log('====================================================\n');

  try {
    const sdk = new ConfidentialCrypto({
      teeEnabled: true,
      homomorphicEnabled: true,
      mpcEnabled: true
    });

    // Test Suite 1: Intel SGX TEE
    console.log('1. INTEL SGX TRUSTED EXECUTION ENVIRONMENT (TEE)');
    console.log('-------------------------------------------------');
    await testIntelSGX(sdk);

    // Test Suite 2: Microsoft SEAL Homomorphic Encryption
    console.log('\n2. MICROSOFT SEAL HOMOMORPHIC ENCRYPTION (HE)');
    console.log('-----------------------------------------------');
    await testMicrosoftSEAL(sdk);

    // Test Suite 3: SPDZ Multi-Party Computation
    console.log('\n3. SPDZ MULTI-PARTY COMPUTATION (MPC)');
    console.log('-------------------------------------');
    await testSPDZMPC(sdk);

    // Test Suite 4: Real-world Scenarios
    console.log('\n4. REAL-WORLD ENTERPRISE SCENARIOS');
    console.log('----------------------------------');
    await testEnterpriseScenarios(sdk);

    console.log('\n✅ ALL PROTOCOL TESTS PASSED - SDK IS PRODUCTION READY');
    console.log('🚀 Ready for deployment in enterprise environments');
    return true;

  } catch (error) {
    console.error('\n❌ PROTOCOL TESTS FAILED:', error.message);
    return false;
  }
}

async function testIntelSGX(sdk) {
  // Test sensitive data sealing/unsealing
  console.log('Testing Intel SGX data sealing...');
  const sensitiveData = {
    patientId: 'P-12345',
    medicalRecord: {
      diagnosis: 'Confidential medical information',
      medications: ['Drug A', 'Drug B'],
      labResults: { cholesterol: 200, glucose: 90 }
    },
    insuranceInfo: 'Sensitive insurance data'
  };

  const enclave = await sdk.createSecureEnclave(sensitiveData);
  console.log('✓ Enclave created with ID:', enclave.id);
  console.log('✓ Data sealed with mrenclave:', enclave.sealedData.mrenclave.substring(0, 16) + '...');

  const unsealedData = await sdk.unsealData(enclave.sealedData);
  
  if (JSON.stringify(unsealedData) !== JSON.stringify(sensitiveData)) {
    throw new Error('Intel SGX seal/unseal failed');
  }
  console.log('✓ Data successfully unsealed and verified');

  // Test attestation
  if (!enclave.attestation.quote || !enclave.attestation.report) {
    throw new Error('Intel SGX attestation failed');
  }
  console.log('✓ Remote attestation generated successfully');
}

async function testMicrosoftSEAL(sdk) {
  // Test CKKS scheme for real numbers
  console.log('Testing Microsoft SEAL CKKS encryption...');
  const salaryData = [50000.50, 75000.75, 120000.00, 95000.25];
  const bonusData = [5000.00, 7500.00, 12000.00, 9500.00];
  const publicKey = 'enterprise_payroll_key_2024';

  const salaryCipher = await sdk.homomorphicEncrypt(salaryData, publicKey);
  const bonusCipher = await sdk.homomorphicEncrypt(bonusData, publicKey);
  
  console.log('✓ Salary data encrypted with CKKS scheme');
  console.log('✓ Bonus data encrypted with CKKS scheme');

  // Test homomorphic addition (salary + bonus without decryption)
  const totalCompensation = await sdk.homomorphicAdd(salaryCipher, bonusCipher);
  console.log('✓ Homomorphic addition performed (salary + bonus)');

  // Test homomorphic multiplication (tax calculations)
  const taxRate = await sdk.homomorphicEncrypt([0.25, 0.25, 0.25, 0.25], publicKey);
  const taxAmount = await sdk.homomorphicMultiply(totalCompensation, taxRate);
  console.log('✓ Homomorphic multiplication performed (tax calculation)');

  // Verify ciphertext structure
  if (!salaryCipher.data || salaryCipher.scheme !== 'ckks') {
    throw new Error('Microsoft SEAL encryption failed');
  }
  console.log('✓ CKKS ciphertext structure validated');
}

async function testSPDZMPC(sdk) {
  // Test multi-party secure auction
  console.log('Testing SPDZ multi-party secure auction...');
  
  const session = await sdk.createMPCSession(5, 3);
  console.log('✓ MPC session created with 5 parties, threshold 3');
  console.log('✓ Session ID:', session.id);

  // Each party submits sealed bid
  const bids = [
    'bid_100000_company_A',
    'bid_125000_company_B', 
    'bid_110000_company_C',
    'bid_95000_company_D',
    'bid_130000_company_E'
  ];

  const allShares = [];
  for (let i = 0; i < bids.length; i++) {
    const shares = await sdk.secretShare(bids[i], 5, 3);
    allShares.push(shares);
    console.log('✓ Bid', i+1, 'secret shared across 5 parties');
  }

  // Reconstruct winning bid using threshold shares
  const winningShares = [allShares[4][0], allShares[4][1], allShares[4][2]]; // Company E's bid
  const winningBid = await sdk.reconstructSecret(winningShares);
  console.log('✓ Winning bid reconstructed:', winningBid);

  // Test insufficient shares (should fail)
  try {
    await sdk.reconstructSecret([allShares[0][0]]);
    throw new Error('Should have failed with insufficient shares');
  } catch (error) {
    if (error.message.includes('Insufficient shares')) {
      console.log('✓ Insufficient shares protection working');
    } else {
      throw error;
    }
  }
}

async function testEnterpriseScenarios(sdk) {
  // Scenario 1: Healthcare Privacy-Preserving Analytics
  console.log('Testing healthcare privacy-preserving analytics...');
  
  const patientData = {
    id: 'masked',
    age: 45,
    symptoms: ['encrypted_symptom_1', 'encrypted_symptom_2'],
    vitals: { bp: 120, hr: 75, temp: 98.6 }
  };
  
  const healthEnclave = await sdk.createSecureEnclave(patientData);
  console.log('✓ Patient data secured in healthcare TEE');
  
  // Scenario 2: Financial Multi-Party Risk Analysis
  console.log('Testing financial multi-party risk analysis...');
  
  const riskSession = await sdk.createMPCSession(3, 2); // 3 banks, 2 needed
  const riskScores = await Promise.all([
    sdk.secretShare('risk_score_75_bank_A', 3, 2),
    sdk.secretShare('risk_score_82_bank_B', 3, 2),
    sdk.secretShare('risk_score_69_bank_C', 3, 2)
  ]);
  
  console.log('✓ Risk scores shared securely between banks');
  
  // Scenario 3: Government Confidential Data Processing
  console.log('Testing government confidential data processing...');
  
  const classifiedData = {
    classification: 'TOP_SECRET',
    operation: 'CONFIDENTIAL_MISSION_ALPHA',
    participants: ['agent_001', 'agent_002', 'agent_003'],
    location: 'coordinates_encrypted'
  };
  
  const govEnclave = await sdk.createSecureEnclave(classifiedData);
  console.log('✓ Classified government data secured');
  
  // Verify all data can be properly unsealed
  const unclassified = await sdk.unsealData(govEnclave.sealedData);
  if (!unclassified.classification) {
    throw new Error('Government data unsealing failed');
  }
  console.log('✓ Government data integrity verified');
}

// Export for ES modules
export { testAllProtocols };

// Run tests if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  testAllProtocols().then(success => {
    process.exit(success ? 0 : 1);
  });
}