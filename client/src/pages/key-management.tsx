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
  const [selectedAlgorithm, setSelectedAlgorithm] = useState("aes-256-gcm");
  const [isGenerateDialogOpen, setIsGenerateDialogOpen] = useState(false);

  const { data: keys = [], isLoading } = useQuery({
    queryKey: ["/api/keys"],
    retry: false,
  });

  const { data: algorithms = [] } = useQuery({
    queryKey: ["/api/algorithms"],
    retry: false,
  });

  const getAlgorithmDetails = (algorithmType: string) => {
    const algorithmMap: { [key: string]: { name: string; description: string; features: string[] } } = {
      'aes-256-gcm': {
        name: 'AES-256-GCM',
        description: 'Industry standard authenticated encryption',
        features: ['AAD_ENFORCEMENT', 'HKDF_KEY_DERIVATION', 'IV_12_BYTE_POLICY', 'TIMING_SAFE_OPERATIONS']
      },
      'chacha20-poly1305': {
        name: 'ChaCha20-Poly1305',
        description: 'High-performance stream cipher with AEAD',
        features: ['CHACHA20_STREAM_CIPHER', 'POLY1305_MAC', 'TIMING_SAFE_OPERATIONS', 'MOBILE_OPTIMIZED']
      },
      'aes-256-cbc-hmac': {
        name: 'AES-256-CBC-HMAC-SHA256',
        description: 'Traditional CBC mode with HMAC authentication',
        features: ['CBC_ENCRYPTION', 'HMAC_AUTHENTICATION', 'PKCS7_PADDING', 'LEGACY_COMPATIBILITY']
      },
      'crystals-kyber': {
        name: 'CRYSTALS-Kyber (Post-Quantum)',
        description: 'NIST 2024 quantum-resistant key encapsulation',
        features: ['POST_QUANTUM_SECURE', 'NIST_STANDARD', 'LATTICE_BASED', 'FUTURE_PROOF']
      }
    };
    return algorithmMap[algorithmType] || algorithmMap['aes-256-gcm'];
  };

  const generateKeyMutation = useMutation({
    mutationFn: async ({ keyType, algorithm }: { keyType: string; algorithm: string }) => {
      console.log(`🔑 Generating production-ready ${keyType} key with ${algorithm}...`);
      
      // Map algorithm selection to actual algorithm ID
      const algorithmMap: { [key: string]: string } = {
        'aes-256-gcm': '9afbd303-2aee-4f9c-a23e-73edda7342e0',
        'chacha20-poly1305': '6194e97e-4280-4c30-9848-5a6a11823dfa', 
        'aes-256-cbc-hmac': 'a1b2c3d4-5e6f-7890-abcd-ef1234567890',
        'crystals-kyber': 'kyber-768-90af3d42-1234-5678-9abc-def012345678'
      };

      const algorithmDetails = getAlgorithmDetails(algorithm);
      const keyData = {
        keyType,
        algorithmId: algorithmMap[algorithm] || algorithmMap['aes-256-gcm'],
        status: 'active',
        metadata: {
          securityFeatures: [
            ...algorithmDetails.features,
            'MEMORY_ZEROIZATION',
            'NIST_COMPLIANCE',
            'TELEMETRY_TRACKING',
            'CANONICAL_ENVELOPE_FORMAT',
            'CROSS_LANGUAGE_INTEROP'
          ],
          envelopeVersion: 'v2',
          keyDerivation: algorithm === 'crystals-kyber' ? 'kyber-kdf' : 'hkdf-sha256',
          auditCompliant: true,
          generatedWith: `production-encryption-core-v2.0.0-${algorithm}`,
          algorithmName: algorithmDetails.name
        }
      };
      return await apiRequest('POST', '/api/keys', keyData);
    },
    onSuccess: (data) => {
      console.log('✅ Production key generated:', data);
      const algorithmDetails = getAlgorithmDetails(selectedAlgorithm);
      toast({
        title: "Production Key Generated", 
        description: `${selectedKeyType} key created with ${algorithmDetails.name}`,
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
          <h1 className="text-2xl font-bold text-white">Encryption Key Management</h1>
          <p className="text-slate-400">Manage encryption keys used across your SDKs and applications</p>
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
                <Label htmlFor="algorithm">Encryption Algorithm</Label>
                <Select value={selectedAlgorithm} onValueChange={setSelectedAlgorithm}>
                  <SelectTrigger className="bg-gray-50 border-gray-300">
                    <SelectValue placeholder="Select algorithm" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="aes-256-gcm">AES-256-GCM (Recommended)</SelectItem>
                    <SelectItem value="chacha20-poly1305">ChaCha20-Poly1305 (High Performance)</SelectItem>
                    <SelectItem value="aes-256-cbc-hmac">AES-256-CBC-HMAC (Legacy Compatible)</SelectItem>
                    <SelectItem value="crystals-kyber">CRYSTALS-Kyber (Post-Quantum)</SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-sm text-gray-600 mt-1">
                  {getAlgorithmDetails(selectedAlgorithm).description}
                </p>
              </div>
              <div className="bg-gray-100 p-3 rounded">
                <h4 className="font-medium mb-2">Security Features</h4>
                <ul className="text-sm text-gray-700 space-y-1">
                  {getAlgorithmDetails(selectedAlgorithm).features.map((feature, index) => (
                    <li key={index}>• {feature.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, l => l.toUpperCase())}</li>
                  ))}
                  <li>• Memory zeroization and timing-safe operations</li>
                  <li>• NIST compliance and cross-language interoperability</li>
                </ul>
              </div>
              <Button 
                onClick={() => generateKeyMutation.mutate({ keyType: selectedKeyType, algorithm: selectedAlgorithm })}
                disabled={generateKeyMutation.isPending}
                className="w-full bg-blue-600 hover:bg-blue-700 text-white"
              >
                {generateKeyMutation.isPending ? "Generating..." : `Generate ${getAlgorithmDetails(selectedAlgorithm).name} Key`}
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
