import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Download, Sparkles, Shield, Zap, ChevronLeft, ChevronRight } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { apiRequest } from '@/lib/queryClient';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { isUnauthorizedError } from '@/lib/authUtils';

interface EncryptionAlgorithm {
  id: string;
  name: string;
  type: string;
  securityLevel: string;
  description: string;
  quantumSafe: boolean;
  performance: string;
  useCases: string[];
}

const applicationTypes = [
  { id: 'web-application', name: 'Web Application', description: 'Traditional web apps, SPAs, PWAs' },
  { id: 'mobile-application', name: 'Mobile Application', description: 'iOS, Android, React Native, Flutter' },
  { id: 'api-service', name: 'API/Service', description: 'REST APIs, GraphQL, microservices' },
  { id: 'desktop-application', name: 'Desktop Application', description: 'Electron, native desktop apps' },
  { id: 'iot-device', name: 'IoT Device', description: 'Embedded systems, smart devices' },
  { id: 'database-system', name: 'Database System', description: 'SQL, NoSQL, data warehouses' },
  { id: 'video-conferencing', name: 'Video Conferencing', description: 'Real-time video/audio communication' },
  { id: 'chat-messaging', name: 'Chat/Messaging', description: 'Instant messaging, chat platforms' },
  { id: 'social-media', name: 'Social Media', description: 'Social networks, content sharing' },
  { id: 'gaming-platform', name: 'Gaming Platform', description: 'Online games, gaming services' },
  { id: 'fintech-application', name: 'Fintech Application', description: 'Banking, payments, trading' },
  { id: 'healthcare-system', name: 'Healthcare System', description: 'Medical records, telemedicine' },
  { id: 'education-platform', name: 'Education Platform', description: 'E-learning, online courses' },
  { id: 'e-commerce', name: 'E-commerce', description: 'Online stores, marketplaces' },
  { id: 'blockchain-application', name: 'Blockchain Application', description: 'DeFi, NFTs, crypto wallets' },
  { id: 'cloud-infrastructure', name: 'Cloud Infrastructure', description: 'AWS, Azure, GCP services' },
  { id: 'analytics-platform', name: 'Analytics Platform', description: 'Business intelligence, data analysis' },
  { id: 'communication-tools', name: 'Communication Tools', description: 'Email, VoIP, collaboration' },
];

const languages = [
  { id: 'javascript', name: 'JavaScript', category: 'Frontend' },
  { id: 'typescript', name: 'TypeScript', category: 'Frontend' },
  { id: 'python', name: 'Python', category: 'Backend' },
  { id: 'java', name: 'Java', category: 'Enterprise' },
  { id: 'csharp', name: 'C#', category: 'Enterprise' },
  { id: 'go', name: 'Go', category: 'Systems' },
  { id: 'rust', name: 'Rust', category: 'Systems' },
  { id: 'php', name: 'PHP', category: 'Web' },
  { id: 'ruby', name: 'Ruby', category: 'Web' },
  { id: 'swift', name: 'Swift', category: 'Mobile' },
  { id: 'kotlin', name: 'Kotlin', category: 'Mobile' },
  { id: 'cpp', name: 'C++', category: 'Systems' },
];

const deploymentOptions = [
  { id: 'cloud', name: 'Cloud (AWS/Azure/GCP)', description: 'Scalable cloud deployment' },
  { id: 'on-premise', name: 'On-Premise', description: 'Private server infrastructure' },
  { id: 'hybrid', name: 'Hybrid Cloud', description: 'Mixed cloud and on-premise' },
  { id: 'edge', name: 'Edge Computing', description: 'Distributed edge nodes' },
];

const securityLevels = [
  { id: 'standard', name: 'Standard Security', description: 'Basic encryption for general use' },
  { id: 'high', name: 'High Security', description: 'Enhanced security for sensitive data' },
  { id: 'military', name: 'Military Grade', description: 'Top-secret government standards' },
  { id: 'quantum-safe', name: 'Quantum Safe', description: 'Future-proof quantum resistance' },
];

const complianceStandards = [
  { id: 'gdpr', name: 'GDPR', description: 'EU General Data Protection Regulation' },
  { id: 'hipaa', name: 'HIPAA', description: 'Health Insurance Portability and Accountability Act' },
  { id: 'pci-dss', name: 'PCI DSS', description: 'Payment Card Industry Data Security Standard' },
  { id: 'sox', name: 'SOX', description: 'Sarbanes-Oxley Act' },
  { id: 'iso27001', name: 'ISO 27001', description: 'Information Security Management' },
  { id: 'fips140', name: 'FIPS 140-2', description: 'Federal Information Processing Standard' },
];

const dataTypeCategories = [
  { id: 'personal', name: 'Personal Information', description: 'Names, addresses, phone numbers, emails' },
  { id: 'financial', name: 'Financial Data', description: 'Credit cards, bank accounts, transactions' },
  { id: 'medical', name: 'Medical Records', description: 'Patient data, diagnoses, prescriptions' },
  { id: 'business', name: 'Business Intelligence', description: 'Trade secrets, strategies, analytics' },
  { id: 'communication', name: 'Communications', description: 'Messages, emails, call logs' },
  { id: 'authentication', name: 'Authentication', description: 'Passwords, tokens, credentials, sessions' },
  { id: 'biometric', name: 'Biometric Data', description: 'Fingerprints, facial recognition, voice patterns' },
  { id: 'location', name: 'Location Data', description: 'GPS coordinates, geolocation, tracking data' },
  { id: 'analytics', name: 'Analytics/Metrics', description: 'User behavior, performance data, statistics' },
  { id: 'media', name: 'Media Content', description: 'Videos, audio, images, streaming content' },
  { id: 'social', name: 'Social Data', description: 'Posts, likes, connections, social graphs' },
  { id: 'iot', name: 'IoT/Sensor Data', description: 'Device data, sensor readings, telemetry' },
  { id: 'blockchain', name: 'Blockchain/Crypto', description: 'Wallet data, transactions, smart contracts' },
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
  const [selectedAlgorithms, setSelectedAlgorithms] = useState<string[]>([]);
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
  const [generatedSDK, setGeneratedSDK] = useState<any>(null);
  
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
          console.log('Recommended algorithms received:', response);
          setRecommendedAlgorithms(response);
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
  }, [step, applicationType, securityLevel, complianceRequirements, deploymentEnvironment]);

  // Auto-select recommended algorithms when they change
  useEffect(() => {
    if (Array.isArray(recommendedAlgorithms) && recommendedAlgorithms.length > 0 && step === 3) {
      const algorithmIds = recommendedAlgorithms.map((alg: EncryptionAlgorithm) => alg.id);
      console.log('Auto-selecting recommended algorithms on step 3:', algorithmIds);
      console.log('Recommended algorithms:', recommendedAlgorithms);
      // Always pre-select ALL recommended algorithms immediately
      console.log('Auto-selecting all recommended algorithms');
      setSelectedAlgorithms(algorithmIds);
    }
  }, [recommendedAlgorithms, step]);

  const generateSDKMutation = useMutation({
    mutationFn: async (data: any) => {
      return await apiRequest('POST', '/api/sdks/generate', data);
    },
    onSuccess: (data) => {
      toast({
        title: "Success",
        description: "SDK generated successfully!",
      });
      setGeneratedSDK(data);
      setStep(6);
      queryClient.invalidateQueries({ queryKey: ['/api/dashboard/stats'] });
      queryClient.invalidateQueries({ queryKey: ['/api/dashboard/activities'] });
    },
    onError: (error) => {
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
        toast({
          title: "Error",
          description: "Failed to generate SDK",
          variant: "destructive",
        });
      }
    },
  });

  const handleGenerate = () => {
    if (!sdkName || !applicationType || !deploymentEnvironment || !securityLevel || !dataTypes.length || !selectedLanguages.length || !selectedAlgorithms.length) {
      toast({
        title: "Missing Information",
        description: "Please fill in all required fields",
        variant: "destructive",
      });
      return;
    }

    const sdkData = {
      name: sdkName,
      applicationType,
      deploymentEnvironment,
      securityLevel,
      dataTypes,
      languages: selectedLanguages,
      algorithms: selectedAlgorithms,
      features: selectedFeatures,
      complianceRequirements,
    };

    generateSDKMutation.mutate(sdkData);
  };

  const nextStep = () => {
    if (step < 6) setStep(step + 1);
  };

  const prevStep = () => {
    if (step > 1) setStep(step - 1);
  };

  const toggleLanguage = (languageId: string) => {
    setSelectedLanguages(prev => 
      prev.includes(languageId) 
        ? prev.filter(id => id !== languageId)
        : [...prev, languageId]
    );
  };

  const toggleAlgorithm = (algorithmId: string) => {
    setSelectedAlgorithms(prev => 
      prev.includes(algorithmId) 
        ? prev.filter(id => id !== algorithmId)
        : [...prev, algorithmId]
    );
  };

  const toggleFeature = (featureId: string) => {
    setSelectedFeatures(prev => 
      prev.includes(featureId) 
        ? prev.filter(id => id !== featureId)
        : [...prev, featureId]
    );
  };

  const toggleDataType = (dataTypeId: string) => {
    setDataTypes(prev => 
      prev.includes(dataTypeId) 
        ? prev.filter(id => id !== dataTypeId)
        : [...prev, dataTypeId]
    );
  };

  const toggleComplianceRequirement = (complianceId: string) => {
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
                        />
                        <div className="flex-1">
                          <div className="font-medium text-foreground">{type.name}</div>
                          <div className="text-xs text-muted-foreground">{type.description}</div>
                        </div>
                      </Label>
                    ))}
                  </div>
                </div>

                {/* Deployment Environment */}
                <div>
                  <Label className="text-foreground font-medium mb-4 block">Deployment Environment *</Label>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {deploymentOptions.map((option) => (
                      <Label 
                        key={option.id}
                        className="flex items-center space-x-3 bg-card border border-border rounded-lg p-4 cursor-pointer hover:bg-secondary transition-colors"
                        data-testid={`deployment-${option.id}`}
                      >
                        <Checkbox
                          checked={deploymentEnvironment === option.id}
                          onCheckedChange={() => setDeploymentEnvironment(option.id)}
                        />
                        <div className="flex-1">
                          <div className="font-medium text-foreground">{option.name}</div>
                          <div className="text-xs text-muted-foreground">{option.description}</div>
                        </div>
                      </Label>
                    ))}
                  </div>
                </div>

                {/* Security Level */}
                <div>
                  <Label className="text-foreground font-medium mb-4 block">Security Level *</Label>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {securityLevels.map((level) => (
                      <Label 
                        key={level.id}
                        className="flex items-center space-x-3 bg-card border border-border rounded-lg p-4 cursor-pointer hover:bg-secondary transition-colors"
                        data-testid={`security-${level.id}`}
                      >
                        <Checkbox
                          checked={securityLevel === level.id}
                          onCheckedChange={() => setSecurityLevel(level.id)}
                        />
                        <div className="flex-1">
                          <div className="font-medium text-foreground">{level.name}</div>
                          <div className="text-xs text-muted-foreground">{level.description}</div>
                        </div>
                      </Label>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Continue with step 2... */}
            {step === 2 && (
              <div className="space-y-8">
                <div className="text-center mb-6">
                  <h3 className="text-lg font-semibold text-foreground mb-2">Data Types & Compliance</h3>
                  <p className="text-muted-foreground text-sm">What type of data will you be encrypting?</p>
                </div>

                {/* Data Types */}
                <div>
                  <Label className="text-foreground font-medium mb-4 block">Data Types * (Select all that apply)</Label>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {dataTypeCategories.map((dataType) => (
                      <Label 
                        key={dataType.id}
                        className="flex items-center space-x-3 bg-card border border-border rounded-lg p-4 cursor-pointer hover:bg-secondary transition-colors"
                        data-testid={`data-type-${dataType.id}`}
                      >
                        <Checkbox
                          checked={dataTypes.includes(dataType.id)}
                          onCheckedChange={() => toggleDataType(dataType.id)}
                        />
                        <div className="flex-1">
                          <div className="font-medium text-foreground">{dataType.name}</div>
                          <div className="text-xs text-muted-foreground">{dataType.description}</div>
                        </div>
                      </Label>
                    ))}
                  </div>
                </div>

                {/* Compliance Requirements */}
                <div>
                  <Label className="text-foreground font-medium mb-4 block">Compliance Requirements (Optional)</Label>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {complianceStandards.map((standard) => (
                      <Label 
                        key={standard.id}
                        className="flex items-center space-x-3 bg-card border border-border rounded-lg p-4 cursor-pointer hover:bg-secondary transition-colors"
                        data-testid={`compliance-${standard.id}`}
                      >
                        <Checkbox
                          checked={complianceRequirements.includes(standard.id)}
                          onCheckedChange={() => toggleComplianceRequirement(standard.id)}
                        />
                        <div className="flex-1">
                          <div className="font-medium text-foreground">{standard.name}</div>
                          <div className="text-xs text-muted-foreground">{standard.description}</div>
                        </div>
                      </Label>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Step 3 - Algorithm Selection */}
            {step === 3 && (
              <div className="space-y-8">
                <div className="text-center mb-6">
                  <h3 className="text-lg font-semibold text-foreground mb-2">Encryption Algorithms</h3>
                  <p className="text-muted-foreground text-sm">Choose your encryption algorithms</p>
                </div>

                {/* Recommended Algorithms */}
                {recommendedAlgorithms.length > 0 && (
                  <div className="bg-blue-50 dark:bg-blue-950/30 border border-blue-200 dark:border-blue-800 rounded-lg p-6">
                    <div className="flex items-center gap-3 mb-4">
                      <Sparkles className="h-5 w-5 text-blue-600" />
                      <h4 className="font-semibold text-blue-900 dark:text-blue-100">Recommended for Your Application</h4>
                    </div>
                    <div className="grid grid-cols-1 gap-3">
                      {recommendedAlgorithms.map((algorithm) => (
                        <Label 
                          key={algorithm.id}
                          className="flex items-center space-x-3 bg-white dark:bg-gray-900 border border-blue-200 dark:border-blue-700 rounded-lg p-4 cursor-pointer hover:bg-blue-50 dark:hover:bg-blue-950/50 transition-colors"
                          data-testid={`algorithm-${algorithm.id}`}
                        >
                          <Checkbox
                            checked={selectedAlgorithms.includes(algorithm.id)}
                            onCheckedChange={() => toggleAlgorithm(algorithm.id)}
                          />
                          <div className="flex-1">
                            <div className="flex items-center gap-2">
                              <span className="font-medium text-foreground">{algorithm.name}</span>
                              {algorithm.quantumSafe && (
                                <Badge variant="secondary" className="text-xs">
                                  <Shield className="h-3 w-3 mr-1" />
                                  Quantum Safe
                                </Badge>
                              )}
                              <Badge variant="outline" className="text-xs">{algorithm.type}</Badge>
                            </div>
                            <div className="text-sm text-muted-foreground mt-1">{algorithm.description}</div>
                            <div className="text-xs text-muted-foreground mt-1">
                              Security: {algorithm.securityLevel} | Performance: {algorithm.performance}
                            </div>
                          </div>
                        </Label>
                      ))}
                    </div>
                  </div>
                )}

                {/* All Available Algorithms */}
                <div>
                  <h4 className="font-semibold text-foreground mb-4">All Available Algorithms</h4>
                  <div className="grid grid-cols-1 gap-3">
                    {algorithms.filter((alg: any) => !recommendedAlgorithms.some(rec => rec.id === alg.id)).map((algorithm: any) => (
                      <Label 
                        key={algorithm.id}
                        className="flex items-center space-x-3 bg-card border border-border rounded-lg p-4 cursor-pointer hover:bg-secondary transition-colors"
                        data-testid={`algorithm-${algorithm.id}`}
                      >
                        <Checkbox
                          checked={selectedAlgorithms.includes(algorithm.id)}
                          onCheckedChange={() => toggleAlgorithm(algorithm.id)}
                        />
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <span className="font-medium text-foreground">{algorithm.name}</span>
                            {algorithm.quantumSafe && (
                              <Badge variant="secondary" className="text-xs">
                                <Shield className="h-3 w-3 mr-1" />
                                Quantum Safe
                              </Badge>
                            )}
                            <Badge variant="outline" className="text-xs">{algorithm.type}</Badge>
                          </div>
                          <div className="text-sm text-muted-foreground mt-1">{algorithm.description}</div>
                          <div className="text-xs text-muted-foreground mt-1">
                            Security: {algorithm.securityLevel} | Performance: {algorithm.performance}
                          </div>
                        </div>
                      </Label>
                    ))}
                  </div>
                </div>

                {selectedAlgorithms.length > 0 && (
                  <div className="bg-green-50 dark:bg-green-950/30 border border-green-200 dark:border-green-800 rounded-lg p-4">
                    <div className="text-sm text-green-800 dark:text-green-200">
                      Selected: {selectedAlgorithms.length} algorithm{selectedAlgorithms.length !== 1 ? 's' : ''}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Step 4 - Languages */}
            {step === 4 && (
              <div className="space-y-8">
                <div className="text-center mb-6">
                  <h3 className="text-lg font-semibold text-foreground mb-2">Programming Languages</h3>
                  <p className="text-muted-foreground text-sm">Select the languages for your SDK</p>
                </div>

                {Object.entries(getLanguagesByCategory()).map(([category, langs]) => (
                  <div key={category}>
                    <h4 className="font-semibold text-foreground mb-3">{category}</h4>
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                      {langs.map((language) => (
                        <Label 
                          key={language.id}
                          className="flex items-center space-x-3 bg-card border border-border rounded-lg p-4 cursor-pointer hover:bg-secondary transition-colors"
                          data-testid={`language-${language.id}`}
                        >
                          <Checkbox
                            checked={selectedLanguages.includes(language.id)}
                            onCheckedChange={() => toggleLanguage(language.id)}
                          />
                          <span className="font-medium text-foreground">{language.name}</span>
                        </Label>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Step 5 - Features */}
            {step === 5 && (
              <div className="space-y-8">
                <div className="text-center mb-6">
                  <h3 className="text-lg font-semibold text-foreground mb-2">Advanced Features</h3>
                  <p className="text-muted-foreground text-sm">Choose additional capabilities for your SDK</p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {features.map((feature) => (
                    <Label 
                      key={feature.id}
                      className="flex items-start space-x-3 bg-card border border-border rounded-lg p-4 cursor-pointer hover:bg-secondary transition-colors"
                      data-testid={`feature-${feature.id}`}
                    >
                      <Checkbox
                        checked={selectedFeatures.includes(feature.id)}
                        onCheckedChange={() => toggleFeature(feature.id)}
                        className="mt-1"
                      />
                      <div className="flex-1">
                        <div className="font-medium text-foreground">{feature.name}</div>
                        <div className="text-sm text-muted-foreground mt-1">{feature.description}</div>
                      </div>
                    </Label>
                  ))}
                </div>
              </div>
            )}

            {/* Step 6 - Generate/Review */}
            {step === 6 && !generatedSDK && (
              <div className="space-y-8">
                <div className="text-center mb-6">
                  <h3 className="text-lg font-semibold text-foreground mb-2">Review & Generate</h3>
                  <p className="text-muted-foreground text-sm">Review your configuration and generate your SDK</p>
                </div>

                <div className="space-y-6">
                  <div className="bg-muted rounded-lg p-6">
                    <h4 className="font-semibold text-foreground mb-3">Configuration Summary</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                      <div>
                        <span className="text-muted-foreground">Application:</span> {sdkName}
                      </div>
                      <div>
                        <span className="text-muted-foreground">Type:</span> {applicationTypes.find(t => t.id === applicationType)?.name}
                      </div>
                      <div>
                        <span className="text-muted-foreground">Security:</span> {securityLevels.find(s => s.id === securityLevel)?.name}
                      </div>
                      <div>
                        <span className="text-muted-foreground">Environment:</span> {deploymentOptions.find(d => d.id === deploymentEnvironment)?.name}
                      </div>
                      <div>
                        <span className="text-muted-foreground">Languages:</span> {selectedLanguages.length} selected
                      </div>
                      <div>
                        <span className="text-muted-foreground">Algorithms:</span> {selectedAlgorithms.length} selected
                      </div>
                    </div>
                  </div>

                  <Button 
                    onClick={handleGenerate}
                    disabled={generateSDKMutation.isPending}
                    className="w-full bg-primary hover:bg-primary/90 text-primary-foreground"
                    data-testid="button-generate-sdk"
                  >
                    {generateSDKMutation.isPending ? (
                      <>
                        <Zap className="mr-2 h-4 w-4 animate-spin" />
                        Generating SDK...
                      </>
                    ) : (
                      <>
                        <Zap className="mr-2 h-4 w-4" />
                        Generate SDK
                      </>
                    )}
                  </Button>
                </div>
              </div>
            )}

            {/* Step 6 - Generated SDK */}
            {step === 6 && generatedSDK && (
              <div className="space-y-8">
                <div className="text-center mb-6">
                  <h3 className="text-lg font-semibold text-foreground mb-2">SDK Generated Successfully!</h3>
                  <p className="text-muted-foreground text-sm">Your custom encryption SDK is ready for download</p>
                </div>

                <div className="bg-green-50 dark:bg-green-950/30 border border-green-200 dark:border-green-800 rounded-lg p-6">
                  <div className="flex items-center gap-4">
                    <div className="flex-1">
                      <h4 className="font-semibold text-green-900 dark:text-green-100 mb-2">{generatedSDK.name}</h4>
                      <p className="text-sm text-green-800 dark:text-green-200 mb-2">Version: {generatedSDK.version}</p>
                      <div className="text-xs text-green-700 dark:text-green-300">
                        Languages: {JSON.parse(generatedSDK.languages || '[]').join(', ')}
                      </div>
                      <div className="text-xs text-green-700 dark:text-green-300">
                        Algorithms: {JSON.parse(generatedSDK.algorithms || '[]').length} included
                      </div>
                    </div>
                  </div>
                </div>
                <Button 
                  className="bg-blue-500 hover:bg-blue-600 text-white"
                  onClick={async () => {
                    console.log('Downloading SDK from:', generatedSDK.downloadUrl);
                    try {
                      const response = await fetch(generatedSDK.downloadUrl, {
                        method: 'GET',
                        credentials: 'include', // Include cookies for authentication
                      });
                      
                      if (!response.ok) {
                        throw new Error(`Download failed: ${response.status}`);
                      }
                      
                      const blob = await response.blob();
                      const url = window.URL.createObjectURL(blob);
                      const link = document.createElement('a');
                      link.href = url;
                      link.download = `${generatedSDK.name}-v${generatedSDK.version}.zip`;
                      document.body.appendChild(link);
                      link.click();
                      document.body.removeChild(link);
                      window.URL.revokeObjectURL(url);
                    } catch (error) {
                      console.error('Download error:', error);
                      toast({
                        title: "Download Failed",
                        description: "Failed to download SDK. Please try again.",
                        variant: "destructive",
                      });
                    }
                  }}
                  data-testid="button-download-sdk"
                >
                  <Download className="mr-2 h-4 w-4" />
                  Download SDK
                </Button>
                
                <div className="pt-4 border-t">
                  <div className="flex gap-4">
                    <Button 
                      variant="outline" 
                      onClick={() => setStep(5)}
                      data-testid="button-previous"
                    >
                      <ChevronLeft className="mr-2 h-4 w-4" />
                      Previous
                    </Button>
                    <Button 
                      onClick={() => {
                        setStep(1);
                        setGeneratedSDK(null);
                        setSelectedAlgorithms([]);
                      }}
                      data-testid="button-generate-new"
                    >
                      Generate New SDK
                    </Button>
                  </div>
                </div>
              </div>
            )}

            {/* Navigation */}
            {step < 6 && (
              <div className="flex justify-between pt-8">
                <Button 
                  variant="outline" 
                  onClick={prevStep}
                  disabled={step === 1}
                  data-testid="button-previous"
                >
                  <ChevronLeft className="mr-2 h-4 w-4" />
                  Previous
                </Button>
                <Button 
                  onClick={nextStep}
                  disabled={
                    (step === 1 && (!sdkName || !applicationType || !deploymentEnvironment || !securityLevel)) ||
                    (step === 2 && !dataTypes.length) ||
                    (step === 3 && !selectedAlgorithms.length) ||
                    (step === 4 && !selectedLanguages.length)
                  }
                  data-testid="button-next"
                >
                  Next
                  <ChevronRight className="ml-2 h-4 w-4" />
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}