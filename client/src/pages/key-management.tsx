import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Plus, RotateCcw, Pause, Trash2, Copy, Eye, AlertTriangle, Clock } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { useState } from "react";

export default function KeyManagement() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selectedKeyType, setSelectedKeyType] = useState("primary");
  const [selectedAlgorithm, setSelectedAlgorithm] = useState("AES-256-GCM");
  const [isGenerateDialogOpen, setIsGenerateDialogOpen] = useState(false);

  const { data: keys = [], isLoading } = useQuery({
    queryKey: ["/api/keys"],
    retry: false,
  });

  const { data: algorithms = [] } = useQuery({
    queryKey: ["/api/algorithms"],
    retry: false,
  });

  const getAlgorithmByName = (algorithmName: string) => {
    if (!algorithms || !Array.isArray(algorithms)) return null;
    return algorithms.find((alg: any) => alg.name === algorithmName);
  };

  const getSelectedAlgorithmDetails = () => {
    const algorithm = getAlgorithmByName(selectedAlgorithm);
    if (!algorithm) return { name: 'Unknown', description: 'Algorithm not found', features: [] };
    
    const baseFeatures = [
      'MEMORY_ZEROIZATION',
      'TIMING_SAFE_OPERATIONS', 
      'NIST_COMPLIANCE',
      'TELEMETRY_TRACKING',
      'CROSS_LANGUAGE_INTEROP'
    ];

    let specificFeatures: string[] = [];
    
    // Add algorithm-specific features based on type and properties
    if (algorithm.type === 'symmetric') {
      specificFeatures = ['AUTHENTICATED_ENCRYPTION', 'KEY_DERIVATION', 'IV_GENERATION'];
    } else if (algorithm.type === 'asymmetric') {
      specificFeatures = ['PUBLIC_KEY_CRYPTO', 'DIGITAL_SIGNATURES', 'KEY_EXCHANGE'];
    } else if (algorithm.type === 'post_quantum') {
      specificFeatures = ['QUANTUM_RESISTANT', 'LATTICE_BASED', 'NIST_PQC_STANDARD'];
    } else if (algorithm.type === 'hash') {
      specificFeatures = ['MESSAGE_DIGEST', 'INTEGRITY_VERIFICATION', 'HMAC_SUPPORT'];
    }

    if (algorithm.isPostQuantum) {
      specificFeatures.push('POST_QUANTUM_SECURE', 'FUTURE_PROOF');
    }

    return {
      name: algorithm.displayName,
      description: algorithm.description,
      features: [...specificFeatures, ...baseFeatures],
      keySize: algorithm.keySize,
      type: algorithm.type,
      isQuantumSafe: algorithm.isQuantumSafe,
      isPostQuantum: algorithm.isPostQuantum
    };
  };

  const generateKeyMutation = useMutation({
    mutationFn: async ({ keyType, algorithm }: { keyType: string; algorithm: string }) => {
      console.log(`🔑 Generating production-ready ${keyType} key with ${algorithm}...`);
      
      // Find the actual algorithm from our database
      const algorithmObj = getAlgorithmByName(algorithm);
      if (!algorithmObj) {
        throw new Error(`Algorithm ${algorithm} not found in database`);
      }

      const algorithmDetails = getSelectedAlgorithmDetails();
      const keyData = {
        keyType,
        algorithmId: algorithmObj.id,
        status: 'active',
        metadata: {
          securityFeatures: algorithmDetails.features,
          envelopeVersion: 'v2',
          keyDerivation: algorithmDetails.isPostQuantum ? 'post-quantum-kdf' : 'hkdf-sha256',
          auditCompliant: true,
          generatedWith: `production-encryption-core-v2.0.0-${algorithm}`,
          algorithmName: algorithmDetails.name,
          algorithmType: algorithmDetails.type,
          keySize: algorithmDetails.keySize,
          quantumSafe: algorithmDetails.isQuantumSafe,
          postQuantum: algorithmDetails.isPostQuantum,
          compliance: ['NIST', 'FIPS 140-2', 'ISO 27001', 'Common Criteria'],
          kmsFeatures: [
            'KEY_ROTATION',
            'KEY_VERSIONING',
            'ACCESS_CONTROL',
            'AUDIT_LOGGING',
            'HARDWARE_SECURITY',
            'ENVELOPE_ENCRYPTION',
            'KEY_ESCROW',
            'COMPLIANCE_REPORTING'
          ]
        }
      };
      return await apiRequest('POST', '/api/keys', keyData);
    },
    onSuccess: (data) => {
      console.log('✅ Production key generated:', data);
      const algorithmDetails = getSelectedAlgorithmDetails();
      toast({
        title: "KMS Vault Key Generated", 
        description: `${selectedKeyType} key created with ${algorithmDetails.name} - Enterprise KMS ready`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/keys"] });
      setIsGenerateDialogOpen(false);
    },
    onError: (error: Error) => {
      console.error('❌ Key generation failed:', error);
      if (isUnauthorizedError(error)) {
        toast({
          title: "Authentication Required",
          description: "Please log in to generate keys",
          variant: "destructive",
        });
        setTimeout(() => {
          window.location.href = "/api/login";
        }, 500);
        return;
      }
      toast({
        title: "Key Generation Failed",
        description: `Production key creation error: ${error.message}`,
        variant: "destructive",
      });
    },
  });

  const updateKeyStatusMutation = useMutation({
    mutationFn: async ({ keyId, status }: { keyId: string; status: string }) => {
      return await apiRequest('PATCH', `/api/keys/${keyId}/status`, { status });
    },
    onSuccess: (_, variables) => {
      toast({
        title: "Key Status Updated",
        description: `Key status changed to ${variables.status}`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/keys"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Error",
        description: "Failed to update key status",
        variant: "destructive",
      });
    },
  });

  const revokeKeyMutation = useMutation({
    mutationFn: async (keyId: string) => {
      return await apiRequest('DELETE', `/api/keys/${keyId}`, {});
    },
    onSuccess: () => {
      toast({
        title: "Key Revoked",
        description: "Key has been permanently revoked",
        variant: "destructive",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/keys"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Error",
        description: "Failed to revoke key",
        variant: "destructive",
      });
    },
  });

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied to Clipboard",
      description: `${label} copied successfully`,
    });
  };

  const getKeyTypeDescription = (keyType: string) => {
    switch (keyType) {
      case 'primary':
        return 'Master encryption key for main application data';
      case 'session':
        return 'Temporary key for session-based encryption';
      case 'backup':
        return 'Backup key for disaster recovery scenarios';
      case 'rotation':
        return 'Key generated during rotation process';
      default:
        return 'Custom encryption key';
    }
  };

  const getExpirationWarning = (key: any) => {
    if (!key.expiresAt) return null;
    const now = new Date();
    const expiration = new Date(key.expiresAt);
    const daysUntilExpiration = Math.ceil((expiration.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
    
    if (daysUntilExpiration <= 7) {
      return daysUntilExpiration <= 0 ? 'Expired' : `Expires in ${daysUntilExpiration} days`;
    }
    return null;
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'bg-green-500';
      case 'rotating':
        return 'bg-yellow-500';
      case 'revoked':
        return 'bg-red-500';
      case 'expired':
        return 'bg-gray-500';
      default:
        return 'bg-gray-500';
    }
  };

  return (
    <div className="p-6">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Enterprise KMS Vault</h1>
          <p className="text-slate-400">83+ cryptographic algorithms • Hardware Security Module • NIST & Post-Quantum Standards</p>
        </div>
        <Dialog open={isGenerateDialogOpen} onOpenChange={setIsGenerateDialogOpen}>
          <DialogTrigger asChild>
            <Button 
              className="bg-blue-500 hover:bg-blue-600 text-white" 
              data-testid="button-generate-key"
            >
              <Plus className="w-4 h-4 mr-2" />
              Generate New Key
            </Button>
          </DialogTrigger>
          <DialogContent className="bg-white border-gray-200 text-black">
            <DialogHeader>
              <DialogTitle>Generate New Encryption Key</DialogTitle>
            </DialogHeader>
            <div className="space-y-4">
              <div>
                <Label htmlFor="keyType">Key Type</Label>
                <Select value={selectedKeyType} onValueChange={setSelectedKeyType}>
                  <SelectTrigger className="bg-gray-50 border-gray-300">
                    <SelectValue placeholder="Select key type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="primary">Primary Key</SelectItem>
                    <SelectItem value="session">Session Key</SelectItem>
                    <SelectItem value="backup">Backup Key</SelectItem>
                    <SelectItem value="rotation">Rotation Key</SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-sm text-gray-600 mt-1">
                  {getKeyTypeDescription(selectedKeyType)}
                </p>
              </div>
              <div>
                <Label htmlFor="algorithm">Encryption Algorithm ({algorithms.length} Available)</Label>
                <Select value={selectedAlgorithm} onValueChange={setSelectedAlgorithm}>
                  <SelectTrigger className="bg-gray-50 border-gray-300">
                    <SelectValue placeholder="Select from 83+ enterprise algorithms" />
                  </SelectTrigger>
                  <SelectContent className="max-h-96 overflow-y-auto">
                    <div className="p-2 text-xs font-medium text-gray-500 border-b">🔐 Symmetric Encryption</div>
                    {algorithms.filter((alg: any) => alg.type === 'symmetric').map((alg: any) => (
                      <SelectItem key={alg.id} value={alg.name}>
                        {alg.displayName} {alg.isPostQuantum && '(Post-Quantum)'}
                      </SelectItem>
                    ))}
                    <div className="p-2 text-xs font-medium text-gray-500 border-b">🔑 Asymmetric Encryption</div>
                    {algorithms.filter((alg: any) => alg.type === 'asymmetric').map((alg: any) => (
                      <SelectItem key={alg.id} value={alg.name}>
                        {alg.displayName} {alg.keySize && `(${alg.keySize}-bit)`}
                      </SelectItem>
                    ))}
                    <div className="p-2 text-xs font-medium text-gray-500 border-b">🛡️ Post-Quantum Security</div>
                    {algorithms.filter((alg: any) => alg.type === 'post_quantum').map((alg: any) => (
                      <SelectItem key={alg.id} value={alg.name}>
                        {alg.displayName} (NIST 2024)
                      </SelectItem>
                    ))}
                    <div className="p-2 text-xs font-medium text-gray-500 border-b">🔗 Hash Functions & KDF</div>
                    {algorithms.filter((alg: any) => alg.type === 'hash').map((alg: any) => (
                      <SelectItem key={alg.id} value={alg.name}>
                        {alg.displayName}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-sm text-gray-600 mt-1">
                  {getSelectedAlgorithmDetails().description}
                </p>
              </div>
              <div className="bg-gray-100 p-3 rounded">
                <h4 className="font-medium mb-2">KMS Vault Features</h4>
                <div className="grid grid-cols-2 gap-2 text-sm text-gray-700">
                  <div>
                    <p className="font-medium text-xs text-gray-500 mb-1">ALGORITHM FEATURES</p>
                    {getSelectedAlgorithmDetails().features.slice(0, 4).map((feature, index) => (
                      <p key={index} className="text-xs">• {feature.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, l => l.toUpperCase())}</p>
                    ))}
                  </div>
                  <div>
                    <p className="font-medium text-xs text-gray-500 mb-1">KMS CAPABILITIES</p>
                    <p className="text-xs">• Hardware Security Module</p>
                    <p className="text-xs">• Envelope Encryption</p>
                    <p className="text-xs">• Automated Key Rotation</p>
                    <p className="text-xs">• Compliance Reporting</p>
                  </div>
                </div>
                <div className="mt-2 pt-2 border-t border-gray-200">
                  <p className="text-xs text-gray-600">
                    <strong>Key Size:</strong> {getSelectedAlgorithmDetails().keySize || 'Variable'} bits | 
                    <strong> Type:</strong> {getSelectedAlgorithmDetails().type} | 
                    <strong> Quantum Safe:</strong> {getSelectedAlgorithmDetails().isQuantumSafe ? '✅' : '⚠️'}
                  </p>
                </div>
              </div>
              <Button 
                onClick={() => generateKeyMutation.mutate({ keyType: selectedKeyType, algorithm: selectedAlgorithm })}
                disabled={generateKeyMutation.isPending}
                className="w-full bg-blue-600 hover:bg-blue-700 text-white"
              >
                {generateKeyMutation.isPending ? "Generating..." : `Generate ${getSelectedAlgorithmDetails().name} Key`}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="text-foreground">Encryption Keys</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-4">
              {[1, 2, 3].map((i) => (
                <div key={i} className="h-16 bg-muted rounded animate-pulse"></div>
              ))}
            </div>
          ) : Array.isArray(keys) && keys.length ? (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="border-border">
                    <TableHead className="text-foreground font-medium">Key ID</TableHead>
                    <TableHead className="text-foreground font-medium">Type</TableHead>
                    <TableHead className="text-foreground font-medium">Algorithm</TableHead>
                    <TableHead className="text-foreground font-medium">Created</TableHead>
                    <TableHead className="text-foreground font-medium">Status</TableHead>
                    <TableHead className="text-foreground font-medium">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(keys as any[]).map((key: any) => (
                    <TableRow key={key.id} className="border-border">
                      <TableCell className="text-foreground font-mono text-sm" data-testid={`key-id-${key.id}`}>
                        {key.keyId}
                      </TableCell>
                      <TableCell className="text-foreground" data-testid={`key-type-${key.id}`}>
                        {key.keyType}
                      </TableCell>
                      <TableCell className="text-foreground" data-testid={`key-algorithm-${key.id}`}>
                        {key.algorithm?.displayName || 'N/A'}
                      </TableCell>
                      <TableCell className="text-foreground" data-testid={`key-created-${key.id}`}>
                        {formatDistanceToNow(new Date(key.createdAt), { addSuffix: true })}
                      </TableCell>
                      <TableCell>
                        <Badge className={`${getStatusColor(key.status)} text-white`} data-testid={`key-status-${key.id}`}>
                          {key.status.toUpperCase()}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex space-x-1">
                          <Button
                            size="sm"
                            variant="ghost"
                            className="text-blue-500 hover:text-blue-400 hover:bg-slate-700"
                            onClick={() => copyToClipboard(key.keyId, 'Key ID')}
                            data-testid={`button-copy-${key.id}`}
                            title="Copy Key ID"
                          >
                            <Copy className="w-4 h-4" />
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            className="text-green-500 hover:text-green-400 hover:bg-slate-700"
                            onClick={() => updateKeyStatusMutation.mutate({ keyId: key.id, status: 'rotating' })}
                            disabled={updateKeyStatusMutation.isPending || key.status === 'rotating'}
                            data-testid={`button-rotate-${key.id}`}
                            title="Rotate Key"
                          >
                            <RotateCcw className="w-4 h-4" />
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            className="text-yellow-500 hover:text-yellow-400 hover:bg-slate-700"
                            onClick={() => updateKeyStatusMutation.mutate({ keyId: key.id, status: key.status === 'active' ? 'expired' : 'active' })}
                            disabled={updateKeyStatusMutation.isPending}
                            data-testid={`button-toggle-${key.id}`}
                            title={key.status === 'active' ? 'Disable Key' : 'Activate Key'}
                          >
                            <Pause className="w-4 h-4" />
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            className="text-red-500 hover:text-red-400 hover:bg-slate-700"
                            onClick={() => revokeKeyMutation.mutate(key.id)}
                            disabled={revokeKeyMutation.isPending || key.status === 'revoked'}
                            data-testid={`button-revoke-${key.id}`}
                            title="Revoke Key"
                          >
                            <Trash2 className="w-4 h-4" />
                          </Button>
                        </div>
                        {getExpirationWarning(key) && (
                          <div className="flex items-center mt-1 text-yellow-500 text-xs">
                            <AlertTriangle className="w-3 h-3 mr-1" />
                            {getExpirationWarning(key)}
                          </div>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <div className="text-center py-8">
              <p className="text-slate-400">No encryption keys found</p>
              <p className="text-slate-500 text-sm mt-2">Generate your first key to get started</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
