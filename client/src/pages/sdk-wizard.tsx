import { useState } from "react";
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
import { ArrowLeft, ArrowRight, Download } from "lucide-react";

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

const features = [
  { id: 'autoRotation', name: 'Auto Key Rotation', description: 'Automatic key rotation every 30 days' },
  { id: 'selfHealing', name: 'Self-Healing', description: 'Automatic threat detection and response' },
  { id: 'zeroKnowledge', name: 'Zero-Knowledge', description: 'Server cannot access your encryption keys' },
  { id: 'telemetry', name: 'Telemetry', description: 'Real-time monitoring and analytics' },
];

export default function SdkWizard() {
  const [step, setStep] = useState(1);
  const [sdkName, setSdkName] = useState('');
  const [selectedLanguages, setSelectedLanguages] = useState<string[]>([]);
  const [selectedAlgorithm, setSelectedAlgorithm] = useState('');
  const [selectedFeatures, setSelectedFeatures] = useState<string[]>(['autoRotation', 'selfHealing', 'telemetry']);
  
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: algorithms = [], isLoading: algorithmsLoading } = useQuery({
    queryKey: ["/api/algorithms"],
    retry: false,
  });

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
    if (step === 1 && (!sdkName || selectedLanguages.length === 0 || !selectedAlgorithm)) {
      toast({
        title: "Missing Information",
        description: "Please fill in all required fields and select at least one programming language.",
        variant: "destructive",
      });
      return;
    }
    
    if (step === 2) {
      handleGenerateSDK();
      return;
    }
    
    setStep(step + 1);
  };

  const handlePrevious = () => {
    setStep(step - 1);
  };

  const handleGenerateSDK = () => {
    generateSDKMutation.mutate({
      name: sdkName,
      languages: selectedLanguages,
      algorithmId: selectedAlgorithm,
      configuration: {},
      features: Object.fromEntries(
        features.map(feature => [
          feature.id, 
          selectedFeatures.includes(feature.id)
        ])
      ),
    });
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

  const getLanguagesByCategory = () => {
    const categories = languages.reduce((acc, lang) => {
      if (!acc[lang.category]) {
        acc[lang.category] = [];
      }
      acc[lang.category].push(lang);
      return acc;
    }, {} as Record<string, Array<(typeof languages)[0]>>);
    
    return categories;
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
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <div className={`w-8 h-8 rounded-full flex items-center justify-center font-semibold ${
                step >= 1 ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground'
              }`}>
                1
              </div>
              <span className={step >= 1 ? 'text-foreground font-medium' : 'text-muted-foreground font-medium'}>
                Algorithm Selection
              </span>
            </div>
            <div className="flex-1 h-px bg-border mx-4"></div>
            <div className="flex items-center space-x-2">
              <div className={`w-8 h-8 rounded-full flex items-center justify-center font-semibold ${
                step >= 2 ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground'
              }`}>
                2
              </div>
              <span className={step >= 2 ? 'text-foreground font-medium' : 'text-muted-foreground font-medium'}>
                Configuration
              </span>
            </div>
            <div className="flex-1 h-px bg-border mx-4"></div>
            <div className="flex items-center space-x-2">
              <div className={`w-8 h-8 rounded-full flex items-center justify-center font-semibold ${
                step >= 3 ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground'
              }`}>
                3
              </div>
              <span className={step >= 3 ? 'text-foreground font-medium' : 'text-muted-foreground font-medium'}>
                Generation
              </span>
            </div>
          </div>
        </div>

        <Card className="bg-card border-border">
          <CardHeader>
            <CardTitle className="text-foreground text-2xl">Create Your Encryption SDK</CardTitle>
          </CardHeader>
          <CardContent className="p-8">
            {step === 1 && (
              <div className="space-y-8">
                {/* SDK Name */}
                <div>
                  <Label htmlFor="sdkName" className="text-foreground font-medium mb-2 block">
                    SDK Name
                  </Label>
                  <Input
                    id="sdkName"
                    value={sdkName}
                    onChange={(e) => setSdkName(e.target.value)}
                    placeholder="My Encryption SDK"
                    className="bg-background border-border text-foreground"
                    data-testid="input-sdk-name"
                  />
                </div>

                {/* Language Selection */}
                <div>
                  <div className="mb-4">
                    <Label className="text-foreground font-medium block">
                      Target Programming Languages 
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

                {/* Algorithm Selection */}
                {algorithms && Array.isArray(algorithms) && (
                  <AlgorithmSelector
                    algorithms={algorithms}
                    selectedAlgorithm={selectedAlgorithm}
                    onAlgorithmChange={setSelectedAlgorithm}
                  />
                )}
              </div>
            )}

            {step === 2 && (
              <div className="space-y-8">
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

            {step === 3 && (
              <div className="text-center space-y-6">
                <div className="w-16 h-16 bg-green-500 bg-opacity-20 rounded-full flex items-center justify-center mx-auto">
                  <Download className="w-8 h-8 text-green-500" />
                </div>
                <div>
                  <h3 className="text-2xl font-bold text-foreground mb-2">SDK Generated Successfully!</h3>
                  <p className="text-muted-foreground">Your custom encryption SDK is ready for download and integration.</p>
                </div>
                <div className="bg-secondary rounded-lg p-4">
                  <div className="text-left space-y-2">
                    <p className="text-foreground font-medium">SDK Details:</p>
                    <p className="text-muted-foreground">Name: {sdkName}</p>
                    <p className="text-muted-foreground">Languages: {selectedLanguages.map(id => languages.find(l => l.id === id)?.name).filter(Boolean).join(', ')}</p>
                    <p className="text-muted-foreground">Algorithm: {Array.isArray(algorithms) ? algorithms?.find((a: any) => a.id === selectedAlgorithm)?.displayName || 'N/A' : 'N/A'}</p>
                  </div>
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

            {/* Action Buttons */}
            {step < 3 && (
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
                  {generateSDKMutation.isPending ? 'Generating...' : 
                   step === 2 ? 'Generate SDK' : 'Next Step'}
                  <ArrowRight className="w-4 h-4 ml-2" />
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
