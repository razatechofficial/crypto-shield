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
  { id: 'javascript', name: 'JavaScript', icon: '📜' },
  { id: 'python', name: 'Python', icon: '🐍' },
  { id: 'java', name: 'Java', icon: '☕' },
  { id: 'csharp', name: 'C#', icon: '#️⃣' },
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
  const [selectedLanguage, setSelectedLanguage] = useState('');
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
    if (step === 1 && (!sdkName || !selectedLanguage || !selectedAlgorithm)) {
      toast({
        title: "Missing Information",
        description: "Please fill in all required fields.",
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
      language: selectedLanguage,
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
                step >= 1 ? 'bg-blue-500 text-white' : 'bg-slate-600 text-slate-400'
              }`}>
                1
              </div>
              <span className={step >= 1 ? 'text-white font-medium' : 'text-slate-400 font-medium'}>
                Algorithm Selection
              </span>
            </div>
            <div className="flex-1 h-px bg-slate-700 mx-4"></div>
            <div className="flex items-center space-x-2">
              <div className={`w-8 h-8 rounded-full flex items-center justify-center font-semibold ${
                step >= 2 ? 'bg-blue-500 text-white' : 'bg-slate-600 text-slate-400'
              }`}>
                2
              </div>
              <span className={step >= 2 ? 'text-white font-medium' : 'text-slate-400 font-medium'}>
                Configuration
              </span>
            </div>
            <div className="flex-1 h-px bg-slate-700 mx-4"></div>
            <div className="flex items-center space-x-2">
              <div className={`w-8 h-8 rounded-full flex items-center justify-center font-semibold ${
                step >= 3 ? 'bg-blue-500 text-white' : 'bg-slate-600 text-slate-400'
              }`}>
                3
              </div>
              <span className={step >= 3 ? 'text-white font-medium' : 'text-slate-400 font-medium'}>
                Generation
              </span>
            </div>
          </div>
        </div>

        <Card className="bg-slate-800 border-slate-700">
          <CardHeader>
            <CardTitle className="text-white text-2xl">Create Your Encryption SDK</CardTitle>
          </CardHeader>
          <CardContent className="p-8">
            {step === 1 && (
              <div className="space-y-8">
                {/* SDK Name */}
                <div>
                  <Label htmlFor="sdkName" className="text-white font-medium mb-2 block">
                    SDK Name
                  </Label>
                  <Input
                    id="sdkName"
                    value={sdkName}
                    onChange={(e) => setSdkName(e.target.value)}
                    placeholder="My Encryption SDK"
                    className="bg-slate-700 border-slate-600 text-white"
                    data-testid="input-sdk-name"
                  />
                </div>

                {/* Language Selection */}
                <div>
                  <Label className="text-white font-medium mb-4 block">Target Programming Language</Label>
                  <RadioGroup value={selectedLanguage} onValueChange={setSelectedLanguage}>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      {languages.map((language) => (
                        <div key={language.id}>
                          <RadioGroupItem value={language.id} id={language.id} className="sr-only peer" />
                          <Label htmlFor={language.id} className="cursor-pointer" data-testid={`language-${language.id}`}>
                            <Card className="bg-slate-700 border-slate-600 peer-checked:border-blue-500 peer-checked:bg-slate-600 hover:bg-slate-600 transition-colors">
                              <CardContent className="p-4 text-center">
                                <div className="text-3xl mb-2">{language.icon}</div>
                                <p className="text-white font-medium">{language.name}</p>
                              </CardContent>
                            </Card>
                          </Label>
                        </div>
                      ))}
                    </div>
                  </RadioGroup>
                </div>

                {/* Algorithm Selection */}
                {algorithms && (
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
                  <Label className="text-white font-medium mb-4 block">Security Features</Label>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {features.map((feature) => (
                      <Label 
                        key={feature.id}
                        className="flex items-center space-x-3 bg-slate-700 border border-slate-600 rounded-lg p-4 cursor-pointer hover:bg-slate-600 transition-colors"
                        data-testid={`feature-${feature.id}`}
                      >
                        <Checkbox 
                          checked={selectedFeatures.includes(feature.id)}
                          onCheckedChange={() => handleFeatureToggle(feature.id)}
                          className="border-slate-500"
                        />
                        <div>
                          <h4 className="text-white font-medium">{feature.name}</h4>
                          <p className="text-slate-400 text-sm">{feature.description}</p>
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
                  <h3 className="text-2xl font-bold text-white mb-2">SDK Generated Successfully!</h3>
                  <p className="text-slate-400">Your custom encryption SDK is ready for download and integration.</p>
                </div>
                <div className="bg-slate-700 rounded-lg p-4">
                  <div className="text-left space-y-2">
                    <p className="text-white font-medium">SDK Details:</p>
                    <p className="text-slate-300">Name: {sdkName}</p>
                    <p className="text-slate-300">Language: {languages.find(l => l.id === selectedLanguage)?.name}</p>
                    <p className="text-slate-300">Algorithm: {algorithms?.find((a: any) => a.id === selectedAlgorithm)?.displayName}</p>
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
                  className="border-slate-600 text-slate-300 hover:bg-slate-700"
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
