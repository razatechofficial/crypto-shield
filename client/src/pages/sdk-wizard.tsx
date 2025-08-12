import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import AlgorithmSelector from "@/components/AlgorithmSelector";
import { ArrowLeft, ArrowRight, Download, Lightbulb } from "lucide-react";
import type { EncryptionAlgorithm } from '@shared/schema';

const languages = [
  { id: 'javascript', name: 'JavaScript', icon: '📜', category: 'Web Development' },
  { id: 'typescript', name: 'TypeScript', icon: '📘', category: 'Web Development' },
  { id: 'python', name: 'Python', icon: '🐍', category: 'Backend & Data Science' },
  { id: 'java', name: 'Java', icon: '☕', category: 'Enterprise & Android' },
  { id: 'kotlin', name: 'Kotlin', icon: '🎯', category: 'Android Development' },
  { id: 'swift', name: 'Swift', icon: '🦉', category: 'iOS Development' },
  { id: 'objectivec', name: 'Objective-C', icon: '🍎', category: 'iOS Development' },
  { id: 'csharp', name: 'C#', icon: '#️⃣', category: 'Enterprise & .NET' },
  { id: 'cpp', name: 'C++', icon: '⚡', category: 'Systems Programming' },
  { id: 'c', name: 'C', icon: '🔧', category: 'Systems Programming' },
  { id: 'go', name: 'Go', icon: '🐹', category: 'Backend & Cloud' },
  { id: 'rust', name: 'Rust', icon: '🦀', category: 'Systems Programming' },
  { id: 'php', name: 'PHP', icon: '🐘', category: 'Web Development' },
  { id: 'ruby', name: 'Ruby', icon: '💎', category: 'Web Development' },
  { id: 'dart', name: 'Dart/Flutter', icon: '🎯', category: 'Mobile Development' },
  { id: 'reactnative', name: 'React Native', icon: '📱', category: 'Mobile Development' },
  { id: 'xamarin', name: 'Xamarin', icon: '🔵', category: 'Mobile Development' },
];

const applicationTypes = [
  { id: 'web', name: 'Web Application', description: 'Browser-based applications with client-server architecture' },
  { id: 'mobile', name: 'Mobile Application', description: 'Native or hybrid mobile apps for iOS/Android' },
  { id: 'desktop', name: 'Desktop Application', description: 'Native desktop applications for Windows/Mac/Linux' },
  { id: 'api', name: 'API/Backend Service', description: 'Server-side APIs and microservices' },
  { id: 'iot', name: 'IoT/Embedded', description: 'Internet of Things devices and embedded systems' },
  { id: 'enterprise', name: 'Enterprise Software', description: 'Large-scale enterprise applications' },
];

const deploymentEnvironments = [
  { id: 'cloud', name: 'Cloud (AWS/Azure/GCP)', description: 'Public cloud environments' },
  { id: 'onpremise', name: 'On-Premise', description: 'Private data centers and servers' },
  { id: 'hybrid', name: 'Hybrid Cloud', description: 'Mix of cloud and on-premise' },
  { id: 'edge', name: 'Edge Computing', description: 'Edge devices and distributed computing' },
];

const complianceStandards = [
  { id: 'gdpr', name: 'GDPR', description: 'European data protection regulation' },
  { id: 'hipaa', name: 'HIPAA', description: 'Healthcare data protection (US)' },
  { id: 'pci', name: 'PCI DSS', description: 'Payment card industry standards' },
  { id: 'sox', name: 'SOX', description: 'Sarbanes-Oxley financial compliance' },
  { id: 'fips', name: 'FIPS 140-2', description: 'US government cryptographic standards' },
  { id: 'iso27001', name: 'ISO 27001', description: 'International security management standards' },
];

const securityLevels = [
  { id: 'standard', name: 'Standard Security', description: 'Basic encryption for general use cases' },
  { id: 'enhanced', name: 'Enhanced Security', description: 'Strong encryption for sensitive data' },
  { id: 'maximum', name: 'Maximum Security', description: 'Military-grade encryption for critical systems' },
];

const dataTypeOptions = [
  { id: 'personal', name: 'Personal Data', description: 'User profiles, contact information' },
  { id: 'financial', name: 'Financial Data', description: 'Payment info, transactions, banking' },
  { id: 'medical', name: 'Medical Records', description: 'Health information, patient data' },
  { id: 'business', name: 'Business Data', description: 'Corporate documents, trade secrets' },
  { id: 'communications', name: 'Communications', description: 'Messages, emails, chat logs' },
  { id: 'files', name: 'File Storage', description: 'Documents, images, media files' },
];

const features = [
  { id: 'autoRotation', name: 'Auto Key Rotation', description: 'Intelligent key rotation with zero downtime' },
  { id: 'selfHealing', name: 'Self-Healing Security', description: 'AI-powered threat detection and auto-response' },
  { id: 'zeroKnowledge', name: 'Zero-Knowledge Architecture', description: 'Complete server-side blindness to your data' },
  { id: 'telemetry', name: 'Real-time Telemetry', description: 'Advanced monitoring with predictive analytics' },
  { id: 'multiTenant', name: 'Multi-Tenant Isolation', description: 'Enterprise-grade tenant segregation' },
  { id: 'backup', name: 'Distributed Backup', description: 'Quantum-resistant backup with instant recovery' },
  { id: 'autoInstall', name: 'Zero-Config Installation', description: 'One-command setup with auto-dependency management' },
  { id: 'adaptiveEncryption', name: 'Adaptive Encryption', description: 'Dynamic algorithm selection based on threat level' },
  { id: 'quantumShield', name: 'Quantum Shield', description: 'Future-proof protection against quantum attacks' },
  { id: 'aiThreatDetection', name: 'AI Threat Detection', description: 'Machine learning-based anomaly detection' },
];

export default function SdkWizard() {
  const [step, setStep] = useState(1);
  const [sdkName, setSdkName] = useState('');
  const [applicationType, setApplicationType] = useState('');
  const [deploymentEnvironment, setDeploymentEnvironment] = useState('');
  const [complianceRequirements, setComplianceRequirements] = useState<string[]>([]);
  const [selectedLanguages, setSelectedLanguages] = useState<string[]>([]);
  const [selectedAlgorithm, setSelectedAlgorithm] = useState('');
  const [selectedFeatures, setSelectedFeatures] = useState<string[]>([
    'autoRotation', 
    'selfHealing', 
    'telemetry', 
    'zeroKnowledge',
    'autoInstall', 
    'adaptiveEncryption', 
    'quantumShield', 
    'aiThreatDetection'
  ]);
  const [securityLevel, setSecurityLevel] = useState('');
  const [dataTypes, setDataTypes] = useState<string[]>([]);
  const [recommendedAlgorithms, setRecommendedAlgorithms] = useState<EncryptionAlgorithm[]>([]);
  const [userSelectedAlgorithms, setUserSelectedAlgorithms] = useState<string[]>([]);
  
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: algorithms = [], isLoading: algorithmsLoading } = useQuery({
    queryKey: ["/api/algorithms"],
    retry: false,
  });

  // Fetch algorithm recommendations when application details are filled
  useEffect(() => {
    if (step === 3 && applicationType && securityLevel) {
      const fetchRecommendations = async () => {
        try {
          const response = await apiRequest('POST', '/api/algorithms/recommend', {
            applicationType,
            securityLevel,
            complianceRequirements,
            deploymentEnvironment,
          }) as unknown as EncryptionAlgorithm[];
          setRecommendedAlgorithms(response);
          // Auto-select recommended algorithms
          setUserSelectedAlgorithms(response.slice(0, 3).map((alg: EncryptionAlgorithm) => alg.id));
          if (response.length > 0 && !selectedAlgorithm) {
            setSelectedAlgorithm(response[0].id);
          }
        } catch (error) {
          if (isUnauthorizedError(error as Error)) {
            toast({
              title: "Unauthorized",
              description: "You are logged out. Logging in again...",
              variant: "destructive",
            });
            setTimeout(() => {
              window.location.href = "/api/login";
            }, 500);
          } else {
            console.error('Failed to fetch algorithm recommendations:', error);
          }
        }
      };
      fetchRecommendations();
    }
  }, [step, applicationType, securityLevel, complianceRequirements, deploymentEnvironment, selectedAlgorithm, toast]);

  const generateSDKMutation = useMutation({
    mutationFn: async (data: any) => {
      return await apiRequest('POST', '/api/sdks/generate', data);
    },
    onSuccess: () => {
      toast({
        title: "Success",
        description: "SDK generated successfully!",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/sdks"] });
      setStep(3);
    },
  });

  const handleNext = () => {
    // Step 1: Application Details
    if (step === 1 && (!sdkName || !applicationType || !deploymentEnvironment || !securityLevel)) {
      toast({
        title: "Missing Information",
        description: "Please fill in all required fields for your application.",
        variant: "destructive",
      });
      return;
    }
    
    // Step 2: Data & Compliance
    if (step === 2 && dataTypes.length === 0) {
      toast({
        title: "Missing Information", 
        description: "Please select at least one type of data you'll be encrypting.",
        variant: "destructive",
      });
      return;
    }
    
    // Step 3: Algorithm Selection
    if (step === 3 && userSelectedAlgorithms.length === 0) {
      toast({
        title: "Missing Information",
        description: "Please select at least one encryption algorithm.",
        variant: "destructive",
      });
      return;
    }
    
    // Step 4: Languages 
    if (step === 4 && selectedLanguages.length === 0) {
      toast({
        title: "Missing Information",
        description: "Please select at least one programming language.",
        variant: "destructive",
      });
      return;
    }
    
    if (step === 5) {
      handleGenerateSDK();
      return;
    }
    
    setStep(step + 1);
  };

  const handlePrevious = () => {
    setStep(step - 1);
  };

  const handleGenerateSDK = () => {
    // Generate single unified SDK with multiple languages and algorithms
    const unifiedSDK = {
      name: sdkName,
      applicationType,
      deploymentEnvironment,
      securityLevel,
      dataTypes,
      complianceRequirements,
      languages: selectedLanguages, // Array of selected languages
      algorithms: userSelectedAlgorithms, // Array of selected algorithms
      configuration: {
        // Zero Configuration - Auto Setup
        autoSetup: true,
        autoInstall: true,
        autoConfig: true,
        
        // Security Configuration
        quantumSafe: userSelectedAlgorithms.some(id => 
          Array.isArray(algorithms) && algorithms.find((alg: EncryptionAlgorithm) => alg.id === id)?.isPostQuantum
        ),
        encryptionLevel: securityLevel,
        complianceMode: complianceRequirements,
        
        // Multi-Language Support
        languageBindings: {
          crossPlatform: true,
          nativeOptimization: true,
          unifiedAPI: true,
          sharedConfiguration: true,
        },
        
        // Auto-Healing Configuration
        selfHealing: {
          enabled: selectedFeatures.includes('selfHealing'),
          threatDetection: true,
          autoRotation: selectedFeatures.includes('autoRotation'),
          rotationInterval: securityLevel === 'maximum' ? 7 : securityLevel === 'enhanced' ? 30 : 90,
          autoRecovery: true,
          anomalyDetection: true,
        },
        
        // Telemetry & Monitoring
        telemetry: {
          enabled: selectedFeatures.includes('telemetry'),
          realTimeMonitoring: true,
          performanceMetrics: true,
          securityEvents: true,
          usageAnalytics: true,
          alerting: {
            enabled: true,
            threatAlerts: true,
            performanceAlerts: true,
            keyExpirationAlerts: true,
          },
        },
        
        // Zero-Knowledge Architecture
        zeroKnowledge: {
          enabled: selectedFeatures.includes('zeroKnowledge'),
          clientSideEncryption: true,
          keyDerivation: 'client',
          serverBlindness: true,
        },
        
        // Multi-Tenant Support
        multiTenant: {
          enabled: selectedFeatures.includes('multiTenant'),
          isolation: 'strict',
          tenantKeySegregation: true,
        },
        
        // Backup & Recovery
        backup: {
          enabled: selectedFeatures.includes('backup'),
          autoBackup: true,
          backupInterval: '24h',
          distributedBackup: true,
          disasterRecovery: true,
        }
      },
      features: Object.fromEntries(
        features.map(feature => [
          feature.id, 
          selectedFeatures.includes(feature.id)
        ])
      ),
    };

    // Generate single unified SDK
    generateSDKMutation.mutate(unifiedSDK);
  };

  const handleFeatureToggle = (featureId: string) => {
    setSelectedFeatures(prev => 
      prev.includes(featureId) 
        ? prev.filter(id => id !== featureId)
        : [...prev, featureId]
    );
  };

  const handleLanguageToggle = (languageId: string) => {
    setSelectedLanguages(prev => 
      prev.includes(languageId) 
        ? prev.filter(id => id !== languageId)
        : [...prev, languageId]
    );
  };

  const handleDataTypeToggle = (dataTypeId: string) => {
    setDataTypes(prev => 
      prev.includes(dataTypeId) 
        ? prev.filter(id => id !== dataTypeId)
        : [...prev, dataTypeId]
    );
  };

  const handleComplianceToggle = (complianceId: string) => {
    setComplianceRequirements(prev => 
      prev.includes(complianceId) 
        ? prev.filter(id => id !== complianceId)
        : [...prev, complianceId]
    );
  };

  const getLanguagesByCategory = () => {
    const grouped: { [key: string]: typeof languages } = {};
    languages.forEach(lang => {
      if (!grouped[lang.category]) {
        grouped[lang.category] = [];
      }
      grouped[lang.category].push(lang);
    });
    return grouped;
  };



  if (algorithmsLoading) {
    return (
      <div className="p-6">
        <div className="max-w-4xl mx-auto">
          <div className="text-center">Loading algorithms...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6">
      <div className="max-w-4xl mx-auto">
        {/* Progress Steps */}
        <div className="mb-8">
          <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
            {[
              { num: 1, title: 'Application', subtitle: 'Basic details' },
              { num: 2, title: 'Data & Compliance', subtitle: 'Requirements' },
              { num: 3, title: 'Algorithm', subtitle: 'Encryption type' },
              { num: 4, title: 'Languages', subtitle: 'Programming' },
              { num: 5, title: 'Features', subtitle: 'Advanced options' },
              { num: 6, title: 'Generate', subtitle: 'Create SDK' },
            ].map(({ num, title, subtitle }, index) => (
              <div key={num} className="flex flex-col items-center text-center">
                <div className={`w-10 h-10 rounded-full flex items-center justify-center font-semibold mb-2 ${
                  step >= num ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground'
                }`}>
                  {num}
                </div>
                <span className={`text-xs font-medium ${step >= num ? 'text-foreground' : 'text-muted-foreground'}`}>
                  {title}
                </span>
                <span className={`text-xs ${step >= num ? 'text-muted-foreground' : 'text-muted-foreground'}`}>
                  {subtitle}
                </span>
                {index < 5 && <div className="hidden md:block w-full h-px bg-border mt-2 absolute translate-x-12"></div>}
              </div>
            ))}
          </div>
        </div>

        <Card className="bg-card border-border">
          <CardHeader>
            <CardTitle className="text-foreground text-2xl">Create Your Encryption SDK</CardTitle>
          </CardHeader>
          <CardContent className="p-8">
            {step === 1 && (
              <div className="space-y-8">
                <div className="text-center mb-6">
                  <h3 className="text-lg font-semibold text-foreground mb-2">Application Details</h3>
                  <p className="text-muted-foreground text-sm">Tell us about your application and requirements</p>
                </div>

                {/* SDK Name */}
                <div>
                  <Label htmlFor="sdkName" className="text-foreground font-medium mb-2 block">
                    Application/SDK Name *
                  </Label>
                  <Input
                    id="sdkName"
                    value={sdkName}
                    onChange={(e) => setSdkName(e.target.value)}
                    placeholder="e.g., Healthcare Portal, Banking App, E-commerce Platform"
                    className="bg-background border-border text-foreground"
                    data-testid="input-sdk-name"
                  />
                </div>

                {/* Application Type */}
                <div>
                  <Label className="text-foreground font-medium mb-4 block">Application Type *</Label>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {applicationTypes.map((type) => (
                      <Label 
                        key={type.id}
                        className="flex items-center space-x-3 bg-card border border-border rounded-lg p-4 cursor-pointer hover:bg-secondary transition-colors"
                        data-testid={`app-type-${type.id}`}
                      >
                        <Checkbox
                          checked={applicationType === type.id}
                          onCheckedChange={() => setApplicationType(type.id)}
                          className="border-border"
                        />
                        <div>
                          <h4 className="text-foreground font-medium">{type.name}</h4>
                          <p className="text-muted-foreground text-sm">{type.description}</p>
                        </div>
                      </Label>
                    ))}
                  </div>
                </div>

                {/* Deployment Environment */}
                <div>
                  <Label className="text-foreground font-medium mb-4 block">Deployment Environment *</Label>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {deploymentEnvironments.map((env) => (
                      <Label 
                        key={env.id}
                        className="flex items-center space-x-3 bg-card border border-border rounded-lg p-4 cursor-pointer hover:bg-secondary transition-colors"
                        data-testid={`deployment-${env.id}`}
                      >
                        <Checkbox
                          checked={deploymentEnvironment === env.id}
                          onCheckedChange={() => setDeploymentEnvironment(env.id)}
                          className="border-border"
                        />
                        <div>
                          <h4 className="text-foreground font-medium">{env.name}</h4>
                          <p className="text-muted-foreground text-sm">{env.description}</p>
                        </div>
                      </Label>
                    ))}
                  </div>
                </div>

                {/* Security Level */}
                <div>
                  <Label className="text-foreground font-medium mb-4 block">Security Level *</Label>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    {securityLevels.map((level) => (
                      <Label 
                        key={level.id}
                        className="flex items-center space-x-3 bg-card border border-border rounded-lg p-4 cursor-pointer hover:bg-secondary transition-colors"
                        data-testid={`security-${level.id}`}
                      >
                        <Checkbox
                          checked={securityLevel === level.id}
                          onCheckedChange={() => setSecurityLevel(level.id)}
                          className="border-border"
                        />
                        <div>
                          <h4 className="text-foreground font-medium">{level.name}</h4>
                          <p className="text-muted-foreground text-sm">{level.description}</p>
                        </div>
                      </Label>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {step === 2 && (
              <div className="space-y-8">
                <div className="text-center mb-6">
                  <h3 className="text-lg font-semibold text-foreground mb-2">Data Types & Compliance</h3>
                  <p className="text-muted-foreground text-sm">What kind of data will you be encrypting?</p>
                </div>

                {/* Data Types */}
                <div>
                  <Label className="text-foreground font-medium mb-4 block">Data Types You'll Encrypt *</Label>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {dataTypeOptions.map((dataType) => (
                      <Label 
                        key={dataType.id}
                        className="flex items-center space-x-3 bg-card border border-border rounded-lg p-4 cursor-pointer hover:bg-secondary transition-colors"
                        data-testid={`data-type-${dataType.id}`}
                      >
                        <Checkbox
                          checked={dataTypes.includes(dataType.id)}
                          onCheckedChange={() => handleDataTypeToggle(dataType.id)}
                          className="border-border"
                        />
                        <div>
                          <h4 className="text-foreground font-medium">{dataType.name}</h4>
                          <p className="text-muted-foreground text-sm">{dataType.description}</p>
                        </div>
                      </Label>
                    ))}
                  </div>
                </div>

                {/* Compliance Standards */}
                <div>
                  <Label className="text-foreground font-medium mb-4 block">Compliance Standards (Optional)</Label>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {complianceStandards.map((standard) => (
                      <Label 
                        key={standard.id}
                        className="flex items-center space-x-3 bg-card border border-border rounded-lg p-4 cursor-pointer hover:bg-secondary transition-colors"
                        data-testid={`compliance-${standard.id}`}
                      >
                        <Checkbox
                          checked={complianceRequirements.includes(standard.id)}
                          onCheckedChange={() => handleComplianceToggle(standard.id)}
                          className="border-border"
                        />
                        <div>
                          <h4 className="text-foreground font-medium">{standard.name}</h4>
                          <p className="text-muted-foreground text-sm">{standard.description}</p>
                        </div>
                      </Label>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {step === 3 && (
              <div className="space-y-8">
                <div className="text-center mb-6">
                  <h3 className="text-lg font-semibold text-foreground mb-2">Encryption Algorithms</h3>
                  <p className="text-muted-foreground text-sm">Based on your application requirements, we recommend these algorithms</p>
                </div>

                {/* Smart Recommendations */}
                {Array.isArray(recommendedAlgorithms) && recommendedAlgorithms.length > 0 && (
                  <div className="mb-8">
                    <div className="flex items-center gap-2 mb-4">
                      <Lightbulb className="w-5 h-5 text-yellow-500" />
                      <Label className="text-foreground font-medium">Recommended Algorithms</Label>
                      <Badge variant="secondary" className="text-xs">
                        Based on your {applicationType} app with {securityLevel} security
                      </Badge>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {Array.isArray(recommendedAlgorithms) && recommendedAlgorithms.slice(0, 4).map((algorithm) => (
                        <Label 
                          key={algorithm.id}
                          className="flex items-start space-x-3 bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4 cursor-pointer hover:bg-blue-100 dark:hover:bg-blue-900/20 transition-colors"
                          data-testid={`recommended-algorithm-${algorithm.id}`}
                        >
                          <Checkbox
                            checked={userSelectedAlgorithms.includes(algorithm.id)}
                            onCheckedChange={() => {
                              setUserSelectedAlgorithms(prev => 
                                prev.includes(algorithm.id)
                                  ? prev.filter(id => id !== algorithm.id)
                                  : [...prev, algorithm.id]
                              );
                              if (!selectedAlgorithm) {
                                setSelectedAlgorithm(algorithm.id);
                              }
                            }}
                            className="border-blue-400 mt-0.5"
                          />
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-1">
                              <h4 className="text-foreground font-medium">{algorithm.displayName}</h4>
                              {algorithm.isPostQuantum && (
                                <Badge variant="outline" className="text-xs bg-green-50 dark:bg-green-950/20 text-green-700 dark:text-green-400 border-green-300 dark:border-green-700">
                                  Quantum-Safe
                                </Badge>
                              )}
                              <Badge variant="outline" className="text-xs capitalize">
                                {algorithm.type}
                              </Badge>
                            </div>
                            <p className="text-muted-foreground text-sm">{algorithm.description}</p>
                          </div>
                        </Label>
                      ))}
                    </div>
                  </div>
                )}

                {/* All Available Algorithms */}
                <div>
                  <div className="flex items-center justify-between mb-4">
                    <Label className="text-foreground font-medium">All Available Algorithms</Label>
                    <span className="text-muted-foreground text-sm">
                      {userSelectedAlgorithms.length} selected
                    </span>
                  </div>
                  {algorithms && Array.isArray(algorithms) && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-96 overflow-y-auto">
                      {algorithms.map((algorithm: EncryptionAlgorithm) => (
                        <Label 
                          key={algorithm.id}
                          className={`flex items-start space-x-3 border rounded-lg p-4 cursor-pointer hover:bg-secondary transition-colors ${
                            Array.isArray(recommendedAlgorithms) && recommendedAlgorithms.some(rec => rec.id === algorithm.id) 
                              ? 'bg-blue-50 dark:bg-blue-950/20 border-blue-200 dark:border-blue-800'
                              : 'bg-card border-border'
                          }`}
                          data-testid={`algorithm-${algorithm.id}`}
                        >
                          <Checkbox
                            checked={userSelectedAlgorithms.includes(algorithm.id)}
                            onCheckedChange={() => {
                              setUserSelectedAlgorithms(prev => 
                                prev.includes(algorithm.id)
                                  ? prev.filter(id => id !== algorithm.id)
                                  : [...prev, algorithm.id]
                              );
                              if (!selectedAlgorithm) {
                                setSelectedAlgorithm(algorithm.id);
                              }
                            }}
                            className="border-border mt-0.5"
                          />
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-1">
                              <h4 className="text-foreground font-medium">{algorithm.displayName}</h4>
                              {algorithm.isPostQuantum && (
                                <Badge variant="outline" className="text-xs bg-green-50 dark:bg-green-950/20 text-green-700 dark:text-green-400 border-green-300 dark:border-green-700">
                                  Quantum-Safe
                                </Badge>
                              )}
                              <Badge variant="outline" className="text-xs capitalize">
                                {algorithm.type}
                              </Badge>
                              {Array.isArray(recommendedAlgorithms) && recommendedAlgorithms.some(rec => rec.id === algorithm.id) && (
                                <Badge variant="secondary" className="text-xs bg-yellow-100 dark:bg-yellow-950/20 text-yellow-700 dark:text-yellow-400">
                                  Recommended
                                </Badge>
                              )}
                            </div>
                            <p className="text-muted-foreground text-sm">{algorithm.description}</p>
                          </div>
                        </Label>
                      ))}
                    </div>
                  )}
                </div>

                {userSelectedAlgorithms.length === 0 && (
                  <div className="text-center p-6 bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-800 rounded-lg">
                    <p className="text-amber-800 dark:text-amber-400 text-sm">
                      Please select at least one encryption algorithm to continue.
                    </p>
                  </div>
                )}
              </div>
            )}

            {step === 4 && (
              <div className="space-y-8">
                <div className="text-center mb-6">
                  <h3 className="text-lg font-semibold text-foreground mb-2">Programming Languages</h3>
                  <p className="text-muted-foreground text-sm">Select all languages you need SDKs for</p>
                </div>

                {/* Language Selection */}
                <div>
                  <div className="mb-4">
                    <Label className="text-foreground font-medium block">
                      Target Programming Languages *
                    </Label>
                    <span className="text-muted-foreground text-sm font-normal">
                      (Select multiple languages to generate SDKs for each)
                    </span>
                  </div>
                  <div className="space-y-6">
                    {Object.entries(getLanguagesByCategory()).map(([category, categoryLanguages]) => (
                      <div key={category} className="space-y-3">
                        <h4 className="text-sm font-medium text-muted-foreground border-b border-border pb-1">
                          {category}
                        </h4>
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                          {categoryLanguages.map((language) => (
                            <Label 
                              key={language.id}
                              className="flex items-center space-x-3 bg-card border border-border rounded-lg p-3 cursor-pointer hover:bg-secondary transition-colors"
                              data-testid={`language-${language.id}`}
                            >
                              <Checkbox
                                checked={selectedLanguages.includes(language.id)}
                                onCheckedChange={() => handleLanguageToggle(language.id)}
                                className="border-border"
                              />
                              <div className="flex items-center space-x-2">
                                <span className="text-lg">{language.icon}</span>
                                <span className="text-foreground font-medium text-sm">{language.name}</span>
                              </div>
                            </Label>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {step === 5 && (
              <div className="space-y-8">
                <div className="text-center mb-6">
                  <h3 className="text-lg font-semibold text-foreground mb-2">Advanced Features</h3>
                  <p className="text-muted-foreground text-sm">Choose additional security and monitoring features</p>
                </div>

                {/* Security Features */}
                <div>
                  <Label className="text-foreground font-medium mb-4 block">Security Features</Label>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {features.map((feature) => (
                      <Label 
                        key={feature.id}
                        className="flex items-center space-x-3 bg-card border border-border rounded-lg p-4 cursor-pointer hover:bg-secondary transition-colors"
                        data-testid={`feature-${feature.id}`}
                      >
                        <Checkbox 
                          checked={selectedFeatures.includes(feature.id)}
                          onCheckedChange={() => handleFeatureToggle(feature.id)}
                          className="border-border"
                        />
                        <div>
                          <h4 className="text-foreground font-medium">{feature.name}</h4>
                          <p className="text-muted-foreground text-sm">{feature.description}</p>
                        </div>
                      </Label>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {step === 6 && (
              <div className="space-y-8">
                <div className="text-center mb-6">
                  <h3 className="text-lg font-semibold text-foreground mb-2">Review & Generate</h3>
                  <p className="text-muted-foreground text-sm">Review your configuration before generating the SDK</p>
                </div>

                <div className="bg-secondary rounded-lg p-6 space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <h4 className="text-foreground font-semibold mb-3">Application Details</h4>
                      <div className="space-y-2 text-sm">
                        <p><strong>Name:</strong> {sdkName}</p>
                        <p><strong>Type:</strong> {applicationTypes.find(t => t.id === applicationType)?.name}</p>
                        <p><strong>Environment:</strong> {deploymentEnvironments.find(e => e.id === deploymentEnvironment)?.name}</p>
                        <p><strong>Security Level:</strong> {securityLevels.find(s => s.id === securityLevel)?.name}</p>
                      </div>
                    </div>
                    
                    <div>
                      <h4 className="text-foreground font-semibold mb-3">Data & Compliance</h4>
                      <div className="space-y-2 text-sm">
                        <p><strong>Data Types:</strong> {dataTypes.map(id => dataTypeOptions.find(d => d.id === id)?.name).join(', ')}</p>
                        <p><strong>Compliance:</strong> {complianceRequirements.length > 0 ? complianceRequirements.map(id => complianceStandards.find(c => c.id === id)?.name).join(', ') : 'None specified'}</p>
                      </div>
                    </div>
                    
                    <div>
                      <h4 className="text-foreground font-semibold mb-3">Technical Details</h4>
                      <div className="space-y-2 text-sm">
                        <p><strong>Algorithm:</strong> {Array.isArray(algorithms) ? algorithms?.find((a: any) => a.id === selectedAlgorithm)?.displayName || 'N/A' : 'N/A'}</p>
                        <p><strong>Languages:</strong> {selectedLanguages.map(id => languages.find(l => l.id === id)?.name).filter(Boolean).join(', ')}</p>
                      </div>
                    </div>
                    
                    <div>
                      <h4 className="text-foreground font-semibold mb-3">Features</h4>
                      <div className="space-y-1 text-sm">
                        {selectedFeatures.map(id => (
                          <p key={id}>• {features.find(f => f.id === id)?.name}</p>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Action Buttons */}
            {step < 6 && (
              <div className="flex justify-between mt-8">
                <Button 
                  onClick={handlePrevious}
                  disabled={step === 1}
                  variant="outline"
                  className="border-border text-foreground hover:bg-secondary"
                  data-testid="button-previous"
                >
                  <ArrowLeft className="w-4 h-4 mr-2" />
                  Previous
                </Button>
                <Button 
                  onClick={handleNext}
                  disabled={generateSDKMutation.isPending}
                  className="bg-blue-500 hover:bg-blue-600 text-white"
                  data-testid="button-next"
                >
                  {step === 5 ? (generateSDKMutation.isPending ? 'Generating...' : 'Generate SDK') : 'Next'}
                  <ArrowRight className="w-4 h-4 ml-2" />
                </Button>
              </div>
            )}

            {/* Success Step */}
            {step === 6 && (
              <div className="text-center space-y-6 mt-8">
                <div className="w-16 h-16 bg-green-500 bg-opacity-20 rounded-full flex items-center justify-center mx-auto">
                  <Download className="w-8 h-8 text-green-500" />
                </div>
                <div>
                  <h3 className="text-2xl font-bold text-foreground mb-2">SDK Generated Successfully!</h3>
                  <p className="text-muted-foreground">Your custom encryption SDK is ready for download and integration.</p>
                </div>
                <Button 
                  className="bg-blue-500 hover:bg-blue-600 text-white"
                  data-testid="button-download-sdk"
                >
                  <Download className="w-4 h-4 mr-2" />
                  Download SDK
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
