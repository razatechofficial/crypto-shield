import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Shield, Cpu, Zap, AlertTriangle, CheckCircle, Globe, Lock, Download, FileText } from "lucide-react";
import { useState } from "react";

export default function QuantumSecurity() {
  const { toast } = useToast();
  const [migrationStarted, setMigrationStarted] = useState(false);
  const [assessmentResults, setAssessmentResults] = useState<any>(null);
  
  // Fetch quantum readiness data
  const { data: quantumReadiness, isLoading: readinessLoading } = useQuery({
    queryKey: ["/api/quantum/readiness"],
    retry: false,
  });

  // Real migration assessment mutation
  const startMigrationMutation = useMutation({
    mutationFn: async () => {
      const response = await apiRequest('POST', '/api/quantum/migration/start', {});
      return await response.json();
    },
    onSuccess: (data) => {
      setMigrationStarted(true);
      
      if (data.status === 'completed' && data.assessment) {
        // Real assessment completed immediately
        const { assessment, summary } = data;
        toast({
          title: "Real Assessment Completed",
          description: `Risk Level: ${summary.riskLevel} | Quantum Readiness: ${summary.quantumReadiness} | Estimated Cost: ${summary.migrationCost}`,
        });
        
        // Store assessment results for display
        setAssessmentResults(data);
      } else {
        toast({
          title: "Assessment In Progress",
          description: "Real quantum security assessment is analyzing your infrastructure...",
        });
      }
    },
    onError: (error) => {
      toast({
        title: "Assessment Failed", 
        description: "Unable to complete quantum migration assessment. Please try again.",
        variant: "destructive",
      });
    },
  });

  // Download migration guide mutation
  const downloadGuideMutation = useMutation({
    mutationFn: async () => {
      const response = await fetch('/api/quantum/migration/guide', {
        method: 'GET',
        credentials: 'include',
        headers: {
          'Accept': 'application/pdf, text/plain',
        },
      });
      
      if (!response.ok) {
        throw new Error(`Download failed: ${response.status}`);
      }
      
      // Check content type and create proper download
      const contentType = response.headers.get('content-type');
      const blob = await response.blob();
      
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      
      // Set appropriate filename based on content type
      if (contentType?.includes('application/pdf')) {
        link.download = 'Averox-Quantum-Migration-Guide.pdf';
      } else {
        link.download = 'Averox-Quantum-Migration-Guide.txt';
      }
      
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
      
      return { contentType };
    },
    onSuccess: (data) => {
      const fileType = data?.contentType?.includes('pdf') ? 'PDF document' : 'text document';
      toast({
        title: "Migration Guide Downloaded",
        description: `The comprehensive quantum security migration guide (${fileType}) has been downloaded successfully.`,
      });
    },
    onError: (error) => {
      console.error('Download error:', error);
      toast({
        title: "Download Failed",
        description: "Unable to download migration guide. Please try again.",
        variant: "destructive",
      });
    },
  });
  const postQuantumAlgorithms = [
    {
      name: "ML-KEM-512",
      type: "Key Encapsulation",
      status: "FIPS 203 Standard",
      securityLevel: 128,
      description: "NIST Post-Quantum Key Encapsulation Mechanism (Level 1 security)",
      available: true,
      fipsStatus: "FIPS 203"
    },
    {
      name: "ML-KEM-768",
      type: "Key Encapsulation",
      status: "FIPS 203 Standard",
      securityLevel: 192,
      description: "NIST Post-Quantum Key Encapsulation Mechanism (Level 3 security)",
      available: true,
      fipsStatus: "FIPS 203"
    },
    {
      name: "ML-KEM-1024",
      type: "Key Encapsulation",
      status: "FIPS 203 Standard",
      securityLevel: 256,
      description: "NIST Post-Quantum Key Encapsulation Mechanism (Level 5 security)",
      available: true,
      fipsStatus: "FIPS 203"
    },
    {
      name: "ML-DSA-44",
      type: "Digital Signature",
      status: "FIPS 204 Standard",
      securityLevel: 128,
      description: "NIST Post-Quantum Digital Signature Algorithm (Dilithium2)",
      available: true,
      fipsStatus: "FIPS 204"
    },
    {
      name: "ML-DSA-65",
      type: "Digital Signature",
      status: "FIPS 204 Standard",
      securityLevel: 192,
      description: "NIST Post-Quantum Digital Signature Algorithm (Dilithium3)",
      available: true,
      fipsStatus: "FIPS 204"
    },
    {
      name: "ML-DSA-87",
      type: "Digital Signature",
      status: "FIPS 204 Standard",
      securityLevel: 256,
      description: "NIST Post-Quantum Digital Signature Algorithm (Dilithium5)",
      available: true,
      fipsStatus: "FIPS 204"
    },
    {
      name: "SLH-DSA-SHA2-128s",
      type: "Hash-based Signature",
      status: "FIPS 205 Standard",
      securityLevel: 128,
      description: "NIST Stateless Hash-based Digital Signature (SPHINCS+)",
      available: true,
      fipsStatus: "FIPS 205"
    },
    {
      name: "SLH-DSA-SHAKE-128f",
      type: "Hash-based Signature",
      status: "FIPS 205 Standard",
      securityLevel: 128,
      description: "NIST Stateless Hash-based Digital Signature (SPHINCS+ Fast)",
      available: true,
      fipsStatus: "FIPS 205"
    }
  ];

  const quantumThreats = [
    {
      algorithm: "RSA-2048",
      currentSecurity: "Secure",
      quantumVulnerable: "Completely Broken",
      timeframe: "~2030-2040",
      severity: "Critical"
    },
    {
      algorithm: "ECDSA P-256",
      currentSecurity: "Secure", 
      quantumVulnerable: "Completely Broken",
      timeframe: "~2030-2040",
      severity: "Critical"
    },
    {
      algorithm: "AES-256",
      currentSecurity: "Secure",
      quantumVulnerable: "Weakened to AES-128",
      timeframe: "~2040+",
      severity: "Moderate"
    },
    {
      algorithm: "SHA-256",
      currentSecurity: "Secure",
      quantumVulnerable: "Weakened",
      timeframe: "~2050+", 
      severity: "Low"
    }
  ];

  return (
    <div className="space-y-6 p-6 bg-background text-foreground">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Quantum Security Center</h1>
          <p className="text-muted-foreground">Post-quantum cryptography readiness and migration planning</p>
        </div>
        <Badge className="bg-purple-600 dark:bg-purple-700 text-white">
          <Shield className="w-4 h-4 mr-1" />
          Quantum-Safe Ready
        </Badge>
      </div>

      <Tabs defaultValue="overview" className="w-full">
        <TabsList className="grid w-full grid-cols-4 bg-muted text-muted-foreground">
          <TabsTrigger value="overview" className="data-[state=active]:bg-purple-600 data-[state=active]:text-white">
            <Globe className="w-4 h-4 mr-2" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="algorithms" className="data-[state=active]:bg-purple-600 data-[state=active]:text-white">
            <Lock className="w-4 h-4 mr-2" />
            Algorithms  
          </TabsTrigger>
          <TabsTrigger value="threats" className="data-[state=active]:bg-purple-600 data-[state=active]:text-white">
            <AlertTriangle className="w-4 h-4 mr-2" />
            Threat Assessment
          </TabsTrigger>
          <TabsTrigger value="migration" className="data-[state=active]:bg-purple-600 data-[state=active]:text-white">
            <Zap className="w-4 h-4 mr-2" />
            Migration
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card className="bg-card border-border">
              <CardHeader className="pb-3">
                <CardTitle className="text-card-foreground flex items-center">
                  <Cpu className="w-5 h-5 mr-2 text-purple-600 dark:text-purple-400" />
                  Quantum Timeline
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Current Year</span>
                    <span className="text-foreground">2025</span>
                  </div>
                  <Progress value={25} className="h-2" />
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Est. Quantum Threat</span>
                    <span className="text-orange-600 dark:text-orange-400">2030-2040</span>
                  </div>
                  <p className="text-xs text-muted-foreground mt-2">
                    Migration to post-quantum algorithms recommended within 5 years
                  </p>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-card border-border">
              <CardHeader className="pb-3">
                <CardTitle className="text-card-foreground flex items-center">
                  <Shield className="w-5 h-5 mr-2 text-green-600 dark:text-green-400" />
                  Readiness Status
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">NIST Standards</span>
                    <CheckCircle className="w-4 h-4 text-green-600 dark:text-green-400" />
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Kyber Integration</span>
                    <CheckCircle className="w-4 h-4 text-green-600 dark:text-green-400" />
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Hybrid Mode</span>
                    <div className="w-2 h-2 rounded-full bg-yellow-500 dark:bg-yellow-400"></div>
                  </div>
                  <Progress value={75} className="h-2" />
                  <p className="text-xs text-muted-foreground">75% quantum-ready</p>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-card border-border">
              <CardHeader className="pb-3">
                <CardTitle className="text-card-foreground flex items-center">
                  <AlertTriangle className="w-5 h-5 mr-2 text-red-600 dark:text-red-400" />
                  Risk Assessment
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div className="flex justify-between">
                    <span className="text-sm text-muted-foreground">Critical Risk</span>
                    <Badge variant="destructive" className="text-xs">RSA/ECDSA</Badge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-muted-foreground">Moderate Risk</span>
                    <Badge className="text-xs bg-orange-600 dark:bg-orange-500 text-white">AES-256</Badge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-muted-foreground">Low Risk</span>
                    <Badge className="text-xs bg-green-600 dark:bg-green-500 text-white">Hash Functions</Badge>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="algorithms" className="space-y-4">
          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="text-card-foreground">NIST Post-Quantum Standards</CardTitle>
              <p className="text-muted-foreground">Quantum-resistant algorithms for enterprise deployment</p>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {postQuantumAlgorithms.map((algo, index) => (
                  <div key={index} className="flex items-center justify-between p-4 bg-muted/50 border border-border rounded-lg" data-testid={`algorithm-${algo.name.toLowerCase().replace(/[^a-z0-9]/g, '-')}`}>
                    <div className="flex-1">
                      <div className="flex items-center space-x-3">
                        <h3 className="font-semibold text-foreground">{algo.name}</h3>
                        <Badge className={algo.available ? "bg-green-600 dark:bg-green-500 text-white" : "bg-gray-600 dark:bg-gray-500 text-white"}>
                          {algo.available ? "Available" : "Coming Soon"}
                        </Badge>
                        <Badge variant="outline" className="text-purple-600 dark:text-purple-400 border-purple-600 dark:border-purple-400">
                          {algo.status}
                        </Badge>
                      </div>
                      <p className="text-sm text-muted-foreground mt-1">{algo.type}</p>
                      <p className="text-xs text-muted-foreground mt-1">{algo.description}</p>
                    </div>
                    <div className="text-right">
                      <div className="text-sm text-foreground">{algo.securityLevel}-bit</div>
                      <div className="text-xs text-muted-foreground">Security Level</div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="threats" className="space-y-4">
          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="text-card-foreground">Quantum Threat Timeline</CardTitle>
              <p className="text-muted-foreground">Impact assessment of quantum computers on current cryptography</p>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {quantumThreats.map((threat, index) => (
                  <div key={index} className="p-4 bg-muted/50 border border-border rounded-lg" data-testid={`threat-${threat.algorithm.toLowerCase().replace(/[^a-z0-9]/g, '-')}`}>
                    <div className="flex items-center justify-between mb-2">
                      <h3 className="font-semibold text-foreground">{threat.algorithm}</h3>
                      <Badge className={
                        threat.severity === 'Critical' ? 'bg-red-600 dark:bg-red-500 text-white' :
                        threat.severity === 'Moderate' ? 'bg-orange-600 dark:bg-orange-500 text-white' : 'bg-green-600 dark:bg-green-500 text-white'
                      }>
                        {threat.severity} Risk
                      </Badge>
                    </div>
                    <div className="grid grid-cols-3 gap-4 text-sm">
                      <div>
                        <div className="text-muted-foreground">Current Status</div>
                        <div className="text-green-600 dark:text-green-400">{threat.currentSecurity}</div>
                      </div>
                      <div>
                        <div className="text-muted-foreground">Post-Quantum</div>
                        <div className={threat.quantumVulnerable.includes('Broken') ? 'text-red-600 dark:text-red-400' : 'text-orange-600 dark:text-orange-400'}>
                          {threat.quantumVulnerable}
                        </div>
                      </div>
                      <div>
                        <div className="text-muted-foreground">Timeline</div>
                        <div className="text-foreground">{threat.timeframe}</div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="migration" className="space-y-4">
          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="text-card-foreground">Migration Roadmap</CardTitle>
              <p className="text-muted-foreground">Strategic plan for post-quantum cryptography adoption</p>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold text-foreground">Phase 1: Assessment (6 months)</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="p-4 bg-muted/50 border border-border rounded-lg">
                      <h4 className="font-medium text-foreground mb-2">Cryptographic Inventory</h4>
                      <ul className="text-sm text-muted-foreground space-y-1">
                        <li>• Identify all cryptographic implementations</li>
                        <li>• Map key exchange mechanisms</li>
                        <li>• Document signature algorithms</li>
                      </ul>
                    </div>
                    <div className="p-4 bg-muted/50 border border-border rounded-lg">
                      <h4 className="font-medium text-foreground mb-2">Risk Analysis</h4>
                      <ul className="text-sm text-muted-foreground space-y-1">
                        <li>• Prioritize critical systems</li>
                        <li>• Assess quantum threat timeline</li>
                        <li>• Evaluate business impact</li>
                      </ul>
                    </div>
                  </div>
                </div>

                <div className="space-y-4">
                  <h3 className="text-lg font-semibold text-foreground">Phase 2: Hybrid Implementation (12 months)</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="p-4 bg-muted/50 border border-border rounded-lg">
                      <h4 className="font-medium text-foreground mb-2">Algorithm Integration</h4>
                      <ul className="text-sm text-muted-foreground space-y-1">
                        <li>• Deploy CRYSTALS-Kyber for key exchange</li>
                        <li>• Implement CRYSTALS-Dilithium signatures</li>
                        <li>• Enable hybrid classical+post-quantum mode</li>
                      </ul>
                    </div>
                    <div className="p-4 bg-muted/50 border border-border rounded-lg">
                      <h4 className="font-medium text-foreground mb-2">Testing & Validation</h4>
                      <ul className="text-sm text-muted-foreground space-y-1">
                        <li>• Performance benchmarking</li>
                        <li>• Interoperability testing</li>
                        <li>• Security validation</li>
                      </ul>
                    </div>
                  </div>
                </div>

                <div className="space-y-4">
                  <h3 className="text-lg font-semibold text-foreground">Phase 3: Full Migration (18 months)</h3>
                  <div className="p-4 bg-muted/50 border border-border rounded-lg">
                    <h4 className="font-medium text-foreground mb-2">Complete Transition</h4>
                    <ul className="text-sm text-muted-foreground space-y-1">
                      <li>• Retire classical algorithms in high-risk scenarios</li>
                      <li>• Deploy pure post-quantum configurations</li>
                      <li>• Maintain hybrid support for legacy systems</li>
                      <li>• Continuous monitoring and updates</li>
                    </ul>
                  </div>
                </div>

                <div className="flex space-x-4">
                  <Button 
                    className="bg-purple-600 hover:bg-purple-700 dark:bg-purple-700 dark:hover:bg-purple-600" 
                    onClick={() => startMigrationMutation.mutate()}
                    disabled={startMigrationMutation.isPending || migrationStarted}
                    data-testid="button-start-migration"
                  >
                    <Zap className="w-4 h-4 mr-2" />
                    {startMigrationMutation.isPending 
                      ? "Starting Assessment..." 
                      : migrationStarted 
                        ? "Assessment In Progress" 
                        : "Start Migration Assessment"
                    }
                  </Button>
                  <Button 
                    variant="outline" 
                    className="border-border text-foreground hover:bg-muted"
                    onClick={() => downloadGuideMutation.mutate()}
                    disabled={downloadGuideMutation.isPending}
                    data-testid="button-download-guide"
                  >
                    <Download className="w-4 h-4 mr-2" />
                    {downloadGuideMutation.isPending ? "Downloading..." : "Download Migration Guide"}
                  </Button>
                </div>

                {migrationStarted && assessmentResults && (
                  <div className="mt-6 space-y-4">
                    {/* Real Assessment Results */}
                    <div className="p-4 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg">
                      <div className="flex items-center space-x-2">
                        <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400" />
                        <h4 className="font-medium text-green-800 dark:text-green-200">Real Assessment Completed</h4>
                      </div>
                      <div className="mt-3 grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div className="text-center p-3 bg-white dark:bg-gray-800 rounded border">
                          <div className="text-2xl font-bold text-foreground">{assessmentResults.summary?.riskLevel || 'N/A'}</div>
                          <div className="text-xs text-muted-foreground">Risk Level</div>
                        </div>
                        <div className="text-center p-3 bg-white dark:bg-gray-800 rounded border">
                          <div className="text-2xl font-bold text-foreground">{assessmentResults.summary?.quantumReadiness || '0%'}</div>
                          <div className="text-xs text-muted-foreground">Quantum Ready</div>
                        </div>
                        <div className="text-center p-3 bg-white dark:bg-gray-800 rounded border">
                          <div className="text-2xl font-bold text-foreground">{assessmentResults.summary?.migrationCost || '$0'}</div>
                          <div className="text-xs text-muted-foreground">Migration Cost</div>
                        </div>
                      </div>
                    </div>

                    {/* Detailed Assessment Results */}
                    {assessmentResults.assessment && (
                      <div className="p-4 bg-muted/50 border border-border rounded-lg">
                        <h5 className="font-medium text-foreground mb-3">Infrastructure Analysis</h5>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                          <div>
                            <div className="font-medium text-foreground">{assessmentResults.assessment.infrastructure.totalSDKs}</div>
                            <div className="text-muted-foreground">Total SDKs</div>
                          </div>
                          <div>
                            <div className="font-medium text-foreground">{assessmentResults.assessment.infrastructure.totalAlgorithms}</div>
                            <div className="text-muted-foreground">Total Algorithms</div>
                          </div>
                          <div>
                            <div className="font-medium text-red-600 dark:text-red-400">{assessmentResults.assessment.infrastructure.quantumVulnerableOperations}</div>
                            <div className="text-muted-foreground">Vulnerable Operations</div>
                          </div>
                          <div>
                            <div className="font-medium text-green-600 dark:text-green-400">{assessmentResults.assessment.infrastructure.quantumSafeOperations}</div>
                            <div className="text-muted-foreground">Quantum-Safe Operations</div>
                          </div>
                        </div>
                        
                        {assessmentResults.assessment.riskAssessment.complianceIssues.length > 0 && (
                          <div className="mt-4">
                            <h6 className="font-medium text-foreground mb-2">Compliance Issues:</h6>
                            <ul className="text-sm text-muted-foreground space-y-1">
                              {assessmentResults.assessment.riskAssessment.complianceIssues.map((issue: string, index: number) => (
                                <li key={index} className="flex items-start space-x-2">
                                  <AlertTriangle className="w-4 h-4 text-orange-500 flex-shrink-0 mt-0.5" />
                                  <span>{issue}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {migrationStarted && !assessmentResults && (
                  <div className="mt-6 p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
                    <div className="flex items-center space-x-2">
                      <div className="w-5 h-5 border-2 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
                      <h4 className="font-medium text-blue-800 dark:text-blue-200">Real Assessment Running...</h4>
                    </div>
                    <p className="text-sm text-blue-700 dark:text-blue-300 mt-2">
                      Analyzing your actual cryptographic infrastructure...
                    </p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}