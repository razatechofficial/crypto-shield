import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Shield, Cpu, Zap, AlertTriangle, CheckCircle, Globe, Lock } from "lucide-react";

export default function QuantumSecurity() {
  const postQuantumAlgorithms = [
    {
      name: "CRYSTALS-Kyber",
      type: "Key Encapsulation",
      status: "NIST Standard",
      securityLevel: 128,
      description: "Lattice-based key encapsulation for quantum-safe key exchange",
      available: true
    },
    {
      name: "CRYSTALS-Dilithium", 
      type: "Digital Signature",
      status: "NIST Standard",
      securityLevel: 128,
      description: "Lattice-based signature scheme resistant to quantum attacks",
      available: true
    },
    {
      name: "FALCON",
      type: "Digital Signature", 
      status: "NIST Standard",
      securityLevel: 128,
      description: "Compact lattice-based signatures for constrained environments",
      available: false
    },
    {
      name: "SPHINCS+",
      type: "Digital Signature",
      status: "NIST Standard", 
      securityLevel: 128,
      description: "Hash-based signatures with minimal security assumptions",
      available: false
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
                    data-testid="button-start-migration"
                  >
                    <Zap className="w-4 h-4 mr-2" />
                    Start Migration Assessment
                  </Button>
                  <Button 
                    variant="outline" 
                    className="border-border text-foreground hover:bg-muted"
                    data-testid="button-download-guide"
                  >
                    Download Migration Guide
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}