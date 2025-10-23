import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import {
  Plus,
  RotateCcw,
  Pause,
  Trash2,
  Copy,
  Eye,
  AlertTriangle,
  Clock,
  Shield,
  Zap,
  History,
  Lock,
  Unlock,
  Key,
  RefreshCw,
  Hash,
  CheckCircle,
  XCircle,
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { useState, useEffect, useMemo, useRef } from "react";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";

export default function KeyManagement() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selectedKeyType, setSelectedKeyType] = useState("primary");
  const [selectedAlgorithm, setSelectedAlgorithm] = useState("AES-256-GCM");
  const [keyBits, setKeyBits] = useState("256");
  const [rotationInterval, setRotationInterval] = useState("30");
  const [enableHSM, setEnableHSM] = useState(true);
  const [enableAuditLogging, setEnableAuditLogging] = useState(true);
  const [isGenerateDialogOpen, setIsGenerateDialogOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedKeys, setSelectedKeys] = useState<string[]>([]);
  const [statusFilter, setStatusFilter] = useState("all");
  const [selectedKeyDetails, setSelectedKeyDetails] = useState<any>(null);
  const [isKeyDetailsOpen, setIsKeyDetailsOpen] = useState(false);
  const [vaultKekInfo, setVaultKekInfo] = useState<any>(null);
  const [isVaultKekLoading, setIsVaultKekLoading] = useState(false);
  const [rotationHistory, setRotationHistory] = useState<any[]>([]);
  const loadedUsageStats = useRef<Set<string>>(new Set());

  // Use Vault KEKs instead of database keys
  const { data: keys = [], isLoading } = useQuery({
    queryKey: ["/api/vault/keys/all"],
    retry: false,
  });

  const { data: algorithms = [] } = useQuery({
    queryKey: ["/api/algorithms"],
    retry: false,
  });

  // Vault KEK information query
  const { data: vaultKekData, refetch: refetchVaultKek } = useQuery({
    queryKey: ["/api/vault/keys"],
    retry: false,
  });

  // Key rotation history query
  const { data: rotationHistoryData } = useQuery({
    queryKey: ["/api/keys/rotation-history"],
    retry: false,
  });

  // Vault KEKs query - get all KEKs for the tenant
  const {
    data: vaultKeks = [],
    isLoading: vaultKeksLoading,
    refetch: refetchVaultKeks,
    error: vaultKeksError,
  } = useQuery({
    queryKey: ["/api/vault/keys/all"],
    retry: false,
    queryFn: async () => {
      try {
        const response = await apiRequest("GET", "/api/vault/keys/all");
        if (!response.ok) {
          const errorText = await response.text();
          console.error("API Error Response:", errorText);
          throw new Error(
            `HTTP ${response.status}: ${errorText.substring(0, 100)}...`
          );
        }
        return await response.json();
      } catch (error) {
        console.error("Vault KEKs query error:", error);
        throw error;
      }
    },
  });

  // Debug query to list all keys in Vault
  const {
    data: debugKeys,
    refetch: refetchDebugKeys,
    error: debugError,
  } = useQuery({
    queryKey: ["/api/vault/keys/debug"],
    retry: false,
    enabled: false, // Only run when manually triggered
    queryFn: async () => {
      try {
        const response = await apiRequest("GET", "/api/vault/keys/debug");
        if (!response.ok) {
          const errorText = await response.text();
          console.error("Debug API Error Response:", errorText);
          throw new Error(
            `HTTP ${response.status}: ${errorText.substring(0, 100)}...`
          );
        }
        return await response.json();
      } catch (error) {
        console.error("Debug query error:", error);
        throw error;
      }
    },
  });

  // Update state when data changes
  useEffect(() => {
    if (vaultKekData) {
      setVaultKekInfo(vaultKekData);
    }
  }, [vaultKekData]);

  useEffect(() => {
    if (rotationHistoryData) {
      setRotationHistory(
        Array.isArray(rotationHistoryData) ? rotationHistoryData : []
      );
    }
  }, [rotationHistoryData]);

  const getAlgorithmByName = (algorithmName: string) => {
    if (!algorithms || !Array.isArray(algorithms)) return null;
    return (algorithms as any[]).find((alg: any) => alg.name === algorithmName);
  };

  const getSelectedAlgorithmDetails = () => {
    const algorithm = getAlgorithmByName(selectedAlgorithm);
    if (!algorithm)
      return {
        name: "Unknown",
        description: "Algorithm not found",
        features: [],
      };

    const baseFeatures = [
      "MEMORY_ZEROIZATION",
      "TIMING_SAFE_OPERATIONS",
      "NIST_COMPLIANCE",
      "TELEMETRY_TRACKING",
      "CROSS_LANGUAGE_INTEROP",
    ];

    let specificFeatures: string[] = [];

    // Add algorithm-specific features based on type and properties
    if (algorithm.type === "symmetric") {
      specificFeatures = [
        "AUTHENTICATED_ENCRYPTION",
        "KEY_DERIVATION",
        "IV_GENERATION",
      ];
    } else if (algorithm.type === "asymmetric") {
      specificFeatures = [
        "PUBLIC_KEY_CRYPTO",
        "DIGITAL_SIGNATURES",
        "KEY_EXCHANGE",
      ];
    } else if (algorithm.type === "post_quantum") {
      specificFeatures = [
        "QUANTUM_RESISTANT",
        "LATTICE_BASED",
        "NIST_PQC_STANDARD",
      ];
    } else if (algorithm.type === "hash") {
      specificFeatures = [
        "MESSAGE_DIGEST",
        "INTEGRITY_VERIFICATION",
        "HMAC_SUPPORT",
      ];
    }

    if (algorithm.isPostQuantum) {
      specificFeatures.push("POST_QUANTUM_SECURE", "FUTURE_PROOF");
    }

    return {
      name: algorithm.displayName,
      description: algorithm.description,
      features: [...specificFeatures, ...baseFeatures],
      keySize: algorithm.keySize,
      type: algorithm.type,
      isQuantumSafe: algorithm.isQuantumSafe,
      isPostQuantum: algorithm.isPostQuantum,
    };
  };

  const generateKeyMutation = useMutation({
    mutationFn: async ({
      keyType,
      algorithm,
      keyBits,
      rotationInterval,
      enableHSM,
      enableAuditLogging,
    }: {
      keyType: string;
      algorithm: string;
      keyBits: string;
      rotationInterval: string;
      enableHSM: boolean;
      enableAuditLogging: boolean;
    }) => {
      console.log(
        `🔑 Generating production-ready ${keyType} key with ${algorithm}...`
      );

      // Find the actual algorithm from our database
      const algorithmObj = getAlgorithmByName(algorithm);
      if (!algorithmObj) {
        throw new Error(`Algorithm ${algorithm} not found in database`);
      }

      const algorithmDetails = getSelectedAlgorithmDetails();
      const keyData = {
        keyId: `key_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        keyType,
        algorithmId: algorithmObj.id,
        status: "active",
        rotationInterval: parseInt(rotationInterval),
        metadata: {
          securityFeatures: algorithmDetails.features,
          envelopeVersion: "v2",
          keyDerivation: algorithmDetails.isPostQuantum
            ? "post-quantum-kdf"
            : "hkdf-sha256",
          auditCompliant: enableAuditLogging,
          generatedWith: `production-encryption-core-v2.0.0-${algorithm}`,
          algorithmName: algorithmDetails.name,
          algorithmType: algorithmDetails.type,
          keySize: parseInt(keyBits),
          customKeySize: parseInt(keyBits),
          quantumSafe: algorithmDetails.isQuantumSafe,
          postQuantum: algorithmDetails.isPostQuantum,
          hsmEnabled: enableHSM,
          auditLogging: enableAuditLogging,
          rotationPolicy: {
            interval: parseInt(rotationInterval),
            autoRotate: true,
            retainVersions: 5,
            vaultManaged: true,
          },
          vaultIntegration: {
            enabled: true,
            kekName: `kek-${Date.now()}`, // Will be set by backend
            algorithm: algorithmDetails.isPostQuantum
              ? "chacha20-poly1305"
              : "aes256-gcm96",
            envelopeEncryption: true,
            transitEngine: "transit",
          },
          compliance: ["NIST", "FIPS 140-2", "ISO 27001", "Common Criteria"],
          kmsFeatures: [
            "KEY_ROTATION",
            "KEY_VERSIONING",
            "ACCESS_CONTROL",
            enableAuditLogging ? "AUDIT_LOGGING" : null,
            enableHSM ? "HARDWARE_SECURITY" : "SOFTWARE_SECURITY",
            "ENVELOPE_ENCRYPTION",
            "KEY_ESCROW",
            "COMPLIANCE_REPORTING",
            "VAULT_KMS_INTEGRATION",
            "AUTOMATED_ROTATION",
            "ENVELOPE_V2",
          ].filter(Boolean),
        },
      };
      // Create KEK in Vault instead of database
      const vaultResponse = await apiRequest("POST", "/api/vault/keys", {
        algorithm: algorithmDetails.isPostQuantum
          ? "chacha20-poly1305"
          : "aes256-gcm96",
        keyType,
      });

      if (!vaultResponse.ok) {
        throw new Error("Failed to create KEK in Vault");
      }

      const vaultResult = await vaultResponse.json();
      return vaultResult;
    },
    onSuccess: (data) => {
      console.log("✅ Production key generated:", data);
      const algorithmDetails = getSelectedAlgorithmDetails();
      toast({
        title: "Vault KEK Created",
        description: `${selectedKeyType} KEK created in HashiCorp Vault with ${algorithmDetails.name} - Ready for encryption operations`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/vault/keys/all"] });
      refetchVaultKek(); // Refresh Vault KEK information
      queryClient.invalidateQueries({
        queryKey: ["/api/keys/rotation-history"],
      });
      setIsGenerateDialogOpen(false);
    },
    onError: (error: Error) => {
      console.error("❌ Key generation failed:", error);
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
    mutationFn: async ({
      keyId,
      status,
    }: {
      keyId: string;
      status: string;
    }) => {
      return await apiRequest("PATCH", `/api/keys/${keyId}/status`, { status });
    },
    mutationKey: ["updateKeyStatus"],
    onSuccess: (_, variables) => {
      setActiveRotate(null);
      setActiveToggle(null);
      toast({
        title: "Key Status Updated",
        description: `Key status changed to ${variables.status}`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/keys"] });
    },
    onError: (error: Error) => {
      setActiveRotate(null);
      setActiveToggle(null);
      toast({
        title: "Error",
        description: "Failed to update key status",
        variant: "destructive",
      });
    },
  });

  const revokeKeyMutation = useMutation({
    mutationFn: async (keyId: string) => {
      return await apiRequest("DELETE", `/api/keys/${keyId}`, {});
    },
    mutationKey: ["revokeKey"],
    onSuccess: () => {
      setActiveRevoke(null);
      toast({
        title: "Key Revoked",
        description: "Key has been permanently revoked",
        variant: "destructive",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/keys"] });
    },
    onError: (error: Error) => {
      setActiveRevoke(null);
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

  const [activeDownload, setActiveDownload] = useState<string | null>(null);
  const [activeRotate, setActiveRotate] = useState<string | null>(null);
  const [activeToggle, setActiveToggle] = useState<string | null>(null);
  const [activeRevoke, setActiveRevoke] = useState<string | null>(null);
  const [isRotatingKek, setIsRotatingKek] = useState(false);
  const [isEmergencyRotating, setIsEmergencyRotating] = useState(false);
  const [keyUsageStats, setKeyUsageStats] = useState<Record<string, any>>({});

  const downloadKeyMutation = useMutation({
    mutationFn: async (keyId: string) => {
      setActiveDownload(keyId);
      console.log(`🔑 Downloading production key: ${keyId}`);
      const response = await fetch(`/api/keys/${keyId}/download`, {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
        },
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      return await response.json();
    },
    mutationKey: ["downloadKey"],
    onSuccess: (data, keyId) => {
      setActiveDownload(null);
      // Create downloadable file with key data
      const keyData = {
        keyId: data.keyId,
        keyMaterial: data.keyMaterial,
        algorithm: data.algorithm,
        keySize: data.keySize,
        format: data.format || "PEM",
        createdAt: data.createdAt,
        metadata: {
          ...data.metadata,
          downloadedAt: new Date().toISOString(),
          downloadedBy: "current-user",
        },
      };

      const blob = new Blob([JSON.stringify(keyData, null, 2)], {
        type: "application/json",
      });

      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${data.keyId}-key.json`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);

      toast({
        title: "Key Downloaded",
        description: `Production key ${data.keyId} downloaded successfully`,
      });
    },
    onError: (error: Error, keyId) => {
      setActiveDownload(null);
      console.error("❌ Key download failed:", error);
      toast({
        title: "Download Failed",
        description: `Failed to download key: ${error.message}`,
        variant: "destructive",
      });
    },
  });

  // Vault KEK rotation mutation
  const rotateKekMutation = useMutation({
    mutationFn: async (kekName: string) => {
      setIsRotatingKek(true);
      const response = await apiRequest(
        "POST",
        `/api/vault/keys/${encodeURIComponent(kekName)}/rotate`
      );
      if (!response.ok) {
        throw new Error("Failed to rotate KEK");
      }
      return await response.json();
    },
    onSuccess: (data) => {
      setIsRotatingKek(false);
      toast({
        title: "KEK Rotated",
        description: `KEK rotated to version ${data.newVersion}`,
      });
      refetchVaultKek();
      queryClient.invalidateQueries({
        queryKey: ["/api/keys/rotation-history"],
      });
    },
    onError: (error: Error) => {
      setIsRotatingKek(false);
      console.error("KEK rotation error:", error);
      toast({
        title: "Rotation Failed",
        description: "Failed to rotate KEK",
        variant: "destructive",
      });
    },
  });

  // Emergency KEK rotation mutation
  const emergencyRotateKekMutation = useMutation({
    mutationFn: async () => {
      setIsEmergencyRotating(true);
      const response = await apiRequest(
        "POST",
        "/api/vault/keys/emergency-rotate"
      );
      if (!response.ok) {
        throw new Error("Failed to perform emergency KEK rotation");
      }
      return await response.json();
    },
    onSuccess: (data) => {
      setIsEmergencyRotating(false);
      toast({
        title: "Emergency Rotation Complete",
        description: `Emergency KEK rotation to version ${data.newVersion} completed`,
        variant: "default",
      });
      refetchVaultKek();
      queryClient.invalidateQueries({
        queryKey: ["/api/keys/rotation-history"],
      });
    },
    onError: (error: Error) => {
      setIsEmergencyRotating(false);
      console.error("Emergency KEK rotation error:", error);
      toast({
        title: "Emergency Rotation Failed",
        description: "Failed to perform emergency KEK rotation",
        variant: "destructive",
      });
    },
  });

  // Key usage statistics mutation
  const fetchKeyUsageMutation = useMutation({
    mutationFn: async (keyId: string) => {
      const response = await apiRequest("GET", `/api/keys/usage/${keyId}`);
      if (!response.ok) {
        throw new Error("Failed to fetch key usage statistics");
      }
      return await response.json();
    },
    onSuccess: (data, keyId) => {
      setKeyUsageStats((prev) => ({
        ...prev,
        [keyId]: data,
      }));
    },
    onError: (error: Error) => {
      console.error("Error fetching key usage:", error);
    },
  });

  // Increment key usage mutation
  const incrementKeyUsageMutation = useMutation({
    mutationFn: async (keyId: string) => {
      const response = await apiRequest("POST", "/api/keys/usage/increment", {
        keyId,
      });
      if (!response.ok) {
        throw new Error("Failed to increment key usage");
      }
      return await response.json();
    },
    onSuccess: (data, keyId) => {
      // Refresh usage stats after incrementing
      fetchKeyUsageMutation.mutate(keyId);
    },
    onError: (error: Error) => {
      console.error("Error incrementing key usage:", error);
    },
  });

  // Delete Vault KEK mutation
  const deleteKekMutation = useMutation({
    mutationFn: async (kekName: string) => {
      const response = await apiRequest("DELETE", `/api/vault/keys/${kekName}`);
      if (!response.ok) {
        throw new Error("Failed to delete KEK");
      }
      return await response.json();
    },
    onSuccess: (data) => {
      toast({
        title: "KEK Deleted",
        description: `KEK ${data.kekName} has been permanently deleted`,
        variant: "destructive",
      });
      refetchVaultKeks();
      queryClient.invalidateQueries({ queryKey: ["/api/vault/keys/all"] });
    },
    onError: (error: Error) => {
      console.error("Error deleting KEK:", error);
      toast({
        title: "Delete Failed",
        description: "Failed to delete KEK",
        variant: "destructive",
      });
    },
  });

  // Filter and search logic - memoized to prevent unnecessary re-renders
  const filteredKeys = useMemo(() => {
    return Array.isArray(keys)
      ? keys.filter((key: any) => {
          const matchesSearch =
            !searchQuery ||
            key.keyId?.toLowerCase().includes(searchQuery.toLowerCase()) ||
            key.keyType?.toLowerCase().includes(searchQuery.toLowerCase()) ||
            key.algorithm?.displayName
              ?.toLowerCase()
              .includes(searchQuery.toLowerCase());

          const matchesStatus =
            statusFilter === "all" || key.status === statusFilter;

          return matchesSearch && matchesStatus;
        })
      : [];
  }, [keys, searchQuery, statusFilter]);

  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      setSelectedKeys(filteredKeys.map((key: any) => key.id));
    } else {
      setSelectedKeys([]);
    }
  };

  const handleSelectKey = (keyId: string, checked: boolean) => {
    if (checked) {
      setSelectedKeys([...selectedKeys, keyId]);
    } else {
      setSelectedKeys(selectedKeys.filter((id) => id !== keyId));
    }
  };

  const handleKeyClick = (key: any) => {
    setSelectedKeyDetails(key);
    setIsKeyDetailsOpen(true);
    // Load usage stats for the selected key
    if (!keyUsageStats[key.id] && !loadedUsageStats.current.has(key.id)) {
      loadedUsageStats.current.add(key.id);
      fetchKeyUsageMutation.mutate(key.id);
    }
  };

  // Load usage stats for all keys when component mounts
  useEffect(() => {
    if (filteredKeys.length > 0) {
      filteredKeys.forEach((key: any) => {
        if (!keyUsageStats[key.id] && !loadedUsageStats.current.has(key.id)) {
          loadedUsageStats.current.add(key.id);
          fetchKeyUsageMutation.mutate(key.id);
        }
      });
    }
  }, [filteredKeys.length, keys]); // Only depend on length and keys, not the entire filteredKeys array

  const getKeyTypeDescription = (keyType: string) => {
    switch (keyType) {
      case "primary":
        return "Master encryption key for main application data";
      case "session":
        return "Temporary key for session-based encryption";
      case "backup":
        return "Backup key for disaster recovery scenarios";
      case "rotation":
        return "Key generated during rotation process";
      default:
        return "Custom encryption key";
    }
  };

  const getExpirationWarning = (key: any) => {
    if (!key.expiresAt) return null;
    const now = new Date();
    const expiration = new Date(key.expiresAt);
    const daysUntilExpiration = Math.ceil(
      (expiration.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
    );

    if (daysUntilExpiration <= 7) {
      return daysUntilExpiration <= 0
        ? "Expired"
        : `Expires in ${daysUntilExpiration} days`;
    }
    return null;
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "active":
        return "bg-green-500";
      case "rotating":
        return "bg-yellow-500";
      case "revoked":
        return "bg-red-500";
      case "expired":
        return "bg-gray-500";
      default:
        return "bg-gray-500";
    }
  };

  return (
    <div className="p-6">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">
            Enterprise KMS Vault
          </h1>
          <p className="text-slate-400">
            83+ cryptographic algorithms • Hardware Security Module • NIST &
            Post-Quantum Standards
          </p>
        </div>
        <Dialog
          open={isGenerateDialogOpen}
          onOpenChange={setIsGenerateDialogOpen}
        >
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
                <Select
                  value={selectedKeyType}
                  onValueChange={setSelectedKeyType}
                >
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
                <Label htmlFor="algorithm">
                  Encryption Algorithm (
                  {Array.isArray(algorithms) ? algorithms.length : 0} Available)
                </Label>
                <Select
                  value={selectedAlgorithm}
                  onValueChange={setSelectedAlgorithm}
                >
                  <SelectTrigger className="bg-gray-50 border-gray-300">
                    <SelectValue placeholder="Select from 83+ enterprise algorithms" />
                  </SelectTrigger>
                  <SelectContent className="max-h-96 overflow-y-auto">
                    <div className="p-2 text-xs font-medium text-gray-500 border-b">
                      🔐 Symmetric Encryption
                    </div>
                    {((algorithms as any[]) || [])
                      .filter((alg: any) => alg.type === "symmetric")
                      .map((alg: any) => (
                        <SelectItem key={alg.id} value={alg.name}>
                          {alg.displayName}{" "}
                          {alg.isPostQuantum && "(Post-Quantum)"}
                        </SelectItem>
                      ))}
                    <div className="p-2 text-xs font-medium text-gray-500 border-b">
                      🔑 Asymmetric Encryption
                    </div>
                    {((algorithms as any[]) || [])
                      .filter((alg: any) => alg.type === "asymmetric")
                      .map((alg: any) => (
                        <SelectItem key={alg.id} value={alg.name}>
                          {alg.displayName}{" "}
                          {alg.keySize && `(${alg.keySize}-bit)`}
                        </SelectItem>
                      ))}
                    <div className="p-2 text-xs font-medium text-gray-500 border-b">
                      🛡️ Post-Quantum Security
                    </div>
                    {((algorithms as any[]) || [])
                      .filter((alg: any) => alg.type === "post_quantum")
                      .map((alg: any) => (
                        <SelectItem key={alg.id} value={alg.name}>
                          {alg.displayName} (NIST 2024)
                        </SelectItem>
                      ))}
                    <div className="p-2 text-xs font-medium text-gray-500 border-b">
                      🔗 Hash Functions & KDF
                    </div>
                    {((algorithms as any[]) || [])
                      .filter((alg: any) => alg.type === "hash")
                      .map((alg: any) => (
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
                    <p className="font-medium text-xs text-gray-500 mb-1">
                      ALGORITHM FEATURES
                    </p>
                    {getSelectedAlgorithmDetails()
                      .features.slice(0, 4)
                      .map((feature, index) => (
                        <p key={index} className="text-xs">
                          •{" "}
                          {feature
                            .replace(/_/g, " ")
                            .toLowerCase()
                            .replace(/\b\w/g, (l) => l.toUpperCase())}
                        </p>
                      ))}
                  </div>
                  <div>
                    <p className="font-medium text-xs text-gray-500 mb-1">
                      KMS CAPABILITIES
                    </p>
                    <p className="text-xs">• Hardware Security Module</p>
                    <p className="text-xs">• Envelope Encryption</p>
                    <p className="text-xs">• Automated Key Rotation</p>
                    <p className="text-xs">• Compliance Reporting</p>
                  </div>
                </div>
                <div className="mt-2 pt-2 border-t border-gray-200">
                  <p className="text-xs text-gray-600">
                    <strong>Key Size:</strong>{" "}
                    {getSelectedAlgorithmDetails().keySize || "Variable"} bits |
                    <strong> Type:</strong> {getSelectedAlgorithmDetails().type}{" "}
                    |<strong> Quantum Safe:</strong>{" "}
                    {getSelectedAlgorithmDetails().isQuantumSafe ? "✅" : "⚠️"}
                  </p>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="keyBits">Key Size (bits)</Label>
                  <Select value={keyBits} onValueChange={setKeyBits}>
                    <SelectTrigger className="bg-gray-50 border-gray-300">
                      <SelectValue placeholder="Select key size" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="128">128 bits (Fast)</SelectItem>
                      <SelectItem value="192">192 bits (Balanced)</SelectItem>
                      <SelectItem value="256">
                        256 bits (Secure - Recommended)
                      </SelectItem>
                      <SelectItem value="384">
                        384 bits (High Security)
                      </SelectItem>
                      <SelectItem value="512">
                        512 bits (Maximum Security)
                      </SelectItem>
                      <SelectItem value="768">
                        768 bits (Post-Quantum)
                      </SelectItem>
                      <SelectItem value="1024">
                        1024 bits (Legacy RSA)
                      </SelectItem>
                      <SelectItem value="2048">
                        2048 bits (RSA Standard)
                      </SelectItem>
                      <SelectItem value="4096">
                        4096 bits (RSA High Security)
                      </SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label htmlFor="rotation">Rotation Interval (days)</Label>
                  <Select
                    value={rotationInterval}
                    onValueChange={setRotationInterval}
                  >
                    <SelectTrigger className="bg-gray-50 border-gray-300">
                      <SelectValue placeholder="Select rotation" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="7">7 days (High Security)</SelectItem>
                      <SelectItem value="30">30 days (Standard)</SelectItem>
                      <SelectItem value="90">90 days (Quarterly)</SelectItem>
                      <SelectItem value="180">
                        180 days (Semi-Annual)
                      </SelectItem>
                      <SelectItem value="365">365 days (Annual)</SelectItem>
                      <SelectItem value="0">Manual Only</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="space-y-4">
                <div className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    id="hsm"
                    checked={enableHSM}
                    onChange={(e) => setEnableHSM(e.target.checked)}
                    className="rounded border-gray-300"
                  />
                  <Label htmlFor="hsm" className="text-sm">
                    Hardware Security Module (HSM) Protection
                  </Label>
                </div>

                {enableHSM && (
                  <div className="ml-6 space-y-3 p-3 bg-blue-50 rounded border border-blue-200">
                    <div>
                      <Label
                        htmlFor="hsmProvider"
                        className="text-sm font-medium"
                      >
                        HSM Provider
                      </Label>
                      <Select defaultValue="thales">
                        <SelectTrigger className="bg-white border-blue-300">
                          <SelectValue placeholder="Select HSM provider" />
                        </SelectTrigger>
                        <SelectContent>
                          <div className="p-2 text-xs font-medium text-gray-500 border-b">
                            🏛️ Enterprise HSMs
                          </div>
                          <SelectItem value="thales">
                            Thales Luna HSM (FIPS 140-2 Level 3)
                          </SelectItem>
                          <SelectItem value="safenet">
                            SafeNet Network Attached HSM
                          </SelectItem>
                          <SelectItem value="utimaco">
                            Utimaco CryptoServer (Common Criteria EAL4+)
                          </SelectItem>
                          <SelectItem value="gemalto">
                            Gemalto ProtectServer HSM
                          </SelectItem>
                          <SelectItem value="ncipher">
                            nCipher nShield HSM
                          </SelectItem>
                          <div className="p-2 text-xs font-medium text-gray-500 border-b">
                            ☁️ Cloud HSMs
                          </div>
                          <SelectItem value="aws_cloudhsm">
                            AWS CloudHSM (FIPS 140-2 Level 3)
                          </SelectItem>
                          <SelectItem value="azure_dedicated_hsm">
                            Azure Dedicated HSM
                          </SelectItem>
                          <div className="p-2 text-xs font-medium text-gray-500 border-b">
                            🔐 Smart Tokens
                          </div>
                          <SelectItem value="yubico">
                            YubiKey HSM (PIV/FIDO2)
                          </SelectItem>
                          <SelectItem value="nitrokey">Nitrokey HSM</SelectItem>
                          <SelectItem value="securenet">
                            SecureNet Token
                          </SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="text-xs text-blue-700 space-y-1">
                      <p>
                        <strong>HSM Features:</strong> Hardware-backed key
                        generation, tamper resistance, FIPS compliance
                      </p>
                      <p>
                        <strong>Protocols:</strong> PKCS#11, KMIP 2.1, REST
                        APIs, Smart Card (PIV/CAC)
                      </p>
                      <p>
                        <strong>Government:</strong> FIPS 140-2 Level 3, Common
                        Criteria, Federal PKI approved
                      </p>
                    </div>
                  </div>
                )}
              </div>

              <div className="space-y-3">
                <div className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    id="audit"
                    checked={enableAuditLogging}
                    onChange={(e) => setEnableAuditLogging(e.target.checked)}
                    className="rounded border-gray-300"
                  />
                  <Label htmlFor="audit" className="text-sm">
                    Enterprise Audit Logging & Compliance
                  </Label>
                </div>
              </div>

              <Button
                onClick={() =>
                  generateKeyMutation.mutate({
                    keyType: selectedKeyType,
                    algorithm: selectedAlgorithm,
                    keyBits,
                    rotationInterval,
                    enableHSM,
                    enableAuditLogging,
                  })
                }
                disabled={generateKeyMutation.isPending}
                className="w-full bg-blue-600 hover:bg-blue-700 text-white"
              >
                {generateKeyMutation.isPending
                  ? "Generating..."
                  : `Generate ${getSelectedAlgorithmDetails().name} Key`}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {/* Vault KEK Management Section */}
      {vaultKekInfo && (
        <Card className="mb-6 bg-gradient-to-r from-blue-900/20 to-purple-900/20 border-blue-500/30">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <Shield className="w-6 h-6 text-blue-400" />
                <div>
                  <CardTitle className="text-white">
                    Vault KEK Management
                  </CardTitle>
                  <p className="text-slate-400 text-sm">
                    Key Encryption Key: {vaultKekInfo.kekName} • Version:{" "}
                    {vaultKekInfo.keyVersion}
                  </p>
                </div>
              </div>
              <div className="flex items-center space-x-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => rotateKekMutation.mutate(vaultKekInfo.kekName)}
                  disabled={isRotatingKek}
                  className="border-blue-400 text-blue-400 hover:bg-blue-400/10"
                >
                  <RotateCcw className="w-4 h-4 mr-2" />
                  {isRotatingKek ? "Rotating..." : "Rotate KEK"}
                </Button>
                <Button
                  size="sm"
                  variant="destructive"
                  onClick={() => {
                    if (
                      confirm(
                        "Are you sure you want to perform an emergency KEK rotation? This will immediately invalidate all existing encrypted data."
                      )
                    ) {
                      emergencyRotateKekMutation.mutate();
                    }
                  }}
                  disabled={isEmergencyRotating}
                  className="bg-red-600 hover:bg-red-700"
                >
                  <Zap className="w-4 h-4 mr-2" />
                  {isEmergencyRotating ? "Emergency..." : "Emergency Rotation"}
                </Button>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-slate-800/50 p-3 rounded-lg">
                <p className="text-xs text-slate-400 mb-1">Algorithm</p>
                <p className="text-white font-medium">
                  {vaultKekInfo.algorithm}
                </p>
              </div>
              <div className="bg-slate-800/50 p-3 rounded-lg">
                <p className="text-xs text-slate-400 mb-1">Current Version</p>
                <p className="text-white font-medium">
                  v{vaultKekInfo.keyVersion}
                </p>
              </div>
              <div className="bg-slate-800/50 p-3 rounded-lg">
                <p className="text-xs text-slate-400 mb-1">
                  Supports Encryption
                </p>
                <p className="text-white font-medium">
                  {vaultKekInfo.supportsEncryption ? "✅ Yes" : "❌ No"}
                </p>
              </div>
              <div className="bg-slate-800/50 p-3 rounded-lg">
                <p className="text-xs text-slate-400 mb-1">Created</p>
                <p className="text-white font-medium">
                  {vaultKekInfo.createdAt
                    ? formatDistanceToNow(new Date(vaultKekInfo.createdAt), {
                        addSuffix: true,
                      })
                    : "Unknown"}
                </p>
              </div>
            </div>

            {rotationHistory.length > 0 && (
              <div className="mt-4 pt-4 border-t border-slate-700">
                <div className="flex items-center space-x-2 mb-3">
                  <History className="w-4 h-4 text-slate-400" />
                  <p className="text-sm text-slate-400">
                    Recent Rotation History
                  </p>
                </div>
                <div className="space-y-2">
                  {rotationHistory.slice(0, 3).map((rotation, index) => (
                    <div
                      key={index}
                      className="flex items-center justify-between bg-slate-800/30 p-2 rounded text-sm"
                    >
                      <span className="text-slate-300">
                        Version {rotation.newVersion} • {rotation.trigger}
                      </span>
                      <span className="text-slate-400">
                        {formatDistanceToNow(new Date(rotation.rotatedAt), {
                          addSuffix: true,
                        })}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      <Card className="bg-card border-border">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-foreground">
              Vault KEKs ({Array.isArray(keys) ? keys.length : 0})
            </CardTitle>
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <input
                  type="text"
                  placeholder="Search KEKs..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="px-3 py-1 border border-gray-300 rounded text-sm bg-white"
                  data-testid="search-keys"
                />
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => refetchDebugKeys()}
                  className="text-xs"
                >
                  Debug Vault
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={async () => {
                    try {
                      console.log("Testing API connectivity...");
                      const response = await apiRequest(
                        "GET",
                        "/api/vault/test"
                      );
                      console.log("Response status:", response.status);
                      console.log("Response headers:", response.headers);

                      if (!response.ok) {
                        const errorText = await response.text();
                        console.error("Error response:", errorText);
                        alert(
                          `API Error ${response.status}: ${errorText.substring(
                            0,
                            200
                          )}`
                        );
                        return;
                      }

                      const data = await response.json();
                      console.log("Test endpoint response:", data);
                      alert(`Test successful: ${data.message}`);
                    } catch (error) {
                      console.error("Test endpoint error:", error);
                      alert(
                        `Test failed: ${
                          error instanceof Error ? error.message : String(error)
                        }`
                      );
                    }
                  }}
                  className="text-xs"
                >
                  Test API
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={async () => {
                    try {
                      console.log("Testing public API endpoint...");
                      const response = await fetch("/api/vault/test-public");
                      console.log(
                        "Public API response status:",
                        response.status
                      );

                      if (!response.ok) {
                        const errorText = await response.text();
                        console.error("Public API error response:", errorText);
                        alert(
                          `Public API Error ${
                            response.status
                          }: ${errorText.substring(0, 200)}`
                        );
                        return;
                      }

                      const data = await response.json();
                      console.log("Public API response:", data);
                      alert(`Public API working: ${data.message}`);
                    } catch (error) {
                      console.error("Public API error:", error);
                      alert(
                        `Public API failed: ${
                          error instanceof Error ? error.message : String(error)
                        }`
                      );
                    }
                  }}
                  className="text-xs"
                >
                  Test Public API
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={async () => {
                    try {
                      console.log("Testing Vault configuration...");
                      const response = await fetch("/api/vault/config-test");
                      console.log(
                        "Vault config response status:",
                        response.status
                      );

                      if (!response.ok) {
                        const errorText = await response.text();
                        console.error(
                          "Vault config error response:",
                          errorText
                        );
                        alert(
                          `Vault Config Error ${
                            response.status
                          }: ${errorText.substring(0, 200)}`
                        );
                        return;
                      }

                      const data = await response.json();
                      console.log("Vault config response:", data);
                      alert(
                        `Vault Config: ${data.message}\nHealth Check: ${
                          data.healthCheck
                        }\nConfig: ${JSON.stringify(data.config, null, 2)}`
                      );
                    } catch (error) {
                      console.error("Vault config error:", error);
                      alert(
                        `Vault config failed: ${
                          error instanceof Error ? error.message : String(error)
                        }`
                      );
                    }
                  }}
                  className="text-xs"
                >
                  Test Vault Config
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={async () => {
                    try {
                      console.log("Testing existing API endpoint...");
                      const response = await apiRequest(
                        "GET",
                        "/api/algorithms"
                      );
                      console.log(
                        "Algorithms response status:",
                        response.status
                      );

                      if (!response.ok) {
                        const errorText = await response.text();
                        console.error("Algorithms error response:", errorText);
                        alert(
                          `Algorithms API Error ${
                            response.status
                          }: ${errorText.substring(0, 200)}`
                        );
                        return;
                      }

                      const data = await response.json();
                      console.log("Algorithms response:", data);
                      alert(
                        `Algorithms API working: ${
                          Array.isArray(data) ? data.length : "unknown"
                        } algorithms`
                      );
                    } catch (error) {
                      console.error("Algorithms API error:", error);
                      alert(
                        `Algorithms API failed: ${
                          error instanceof Error ? error.message : String(error)
                        }`
                      );
                    }
                  }}
                  className="text-xs"
                >
                  Test Existing API
                </Button>
                <Select value={statusFilter} onValueChange={setStatusFilter}>
                  <SelectTrigger className="w-32 bg-white border-gray-300">
                    <SelectValue placeholder="Filter" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Status</SelectItem>
                    <SelectItem value="active">Active</SelectItem>
                    <SelectItem value="expired">Expired</SelectItem>
                    <SelectItem value="rotating">Rotating</SelectItem>
                    <SelectItem value="revoked">Revoked</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              {selectedKeys.length > 0 && (
                <div className="flex items-center space-x-2">
                  <span className="text-sm text-gray-600">
                    {selectedKeys.length} selected
                  </span>
                  <Button
                    size="sm"
                    variant="destructive"
                    onClick={() => {
                      if (
                        confirm(
                          `Delete ${selectedKeys.length} selected keys? This action cannot be undone.`
                        )
                      ) {
                        // TODO: Implement bulk delete
                        toast({
                          title: "Bulk Delete",
                          description: `${selectedKeys.length} keys marked for deletion`,
                        });
                        setSelectedKeys([]);
                      }
                    }}
                    data-testid="bulk-delete-keys"
                  >
                    Delete Selected
                  </Button>
                </div>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {/* Debug Information */}
          {vaultKeksError && (
            <div className="mb-4 p-3 bg-red-100 border border-red-300 rounded text-red-700 text-sm">
              <strong>Error loading KEKs:</strong> {vaultKeksError.message}
            </div>
          )}

          {debugKeys && (
            <div className="mb-4 p-3 bg-blue-100 border border-blue-300 rounded text-blue-700 text-sm">
              <strong>Debug Info:</strong> Found {debugKeys.totalKeys} total
              keys in Vault: {debugKeys.keys?.join(", ")}
            </div>
          )}

          {debugError && (
            <div className="mb-4 p-3 bg-red-100 border border-red-300 rounded text-red-700 text-sm">
              <strong>Debug Error:</strong> {debugError.message}
            </div>
          )}

          {isLoading ? (
            <div className="space-y-4">
              {[1, 2, 3].map((i) => (
                <div
                  key={i}
                  className="h-16 bg-muted rounded animate-pulse"
                ></div>
              ))}
            </div>
          ) : filteredKeys.length ? (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="border-border">
                    <TableHead className="text-foreground font-medium w-12">
                      <input
                        type="checkbox"
                        checked={
                          selectedKeys.length === filteredKeys.length &&
                          filteredKeys.length > 0
                        }
                        onChange={(e) => handleSelectAll(e.target.checked)}
                        className="rounded border-gray-300"
                        data-testid="select-all-keys"
                      />
                    </TableHead>
                    <TableHead className="text-foreground font-medium">
                      KEK Name
                    </TableHead>
                    <TableHead className="text-foreground font-medium">
                      Algorithm
                    </TableHead>
                    <TableHead className="text-foreground font-medium">
                      Version
                    </TableHead>
                    <TableHead className="text-foreground font-medium">
                      Capabilities
                    </TableHead>
                    <TableHead className="text-foreground font-medium">
                      Created
                    </TableHead>
                    <TableHead className="text-foreground font-medium">
                      Status
                    </TableHead>
                    <TableHead className="text-foreground font-medium">
                      Actions
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredKeys.map((key: any) => (
                    <TableRow
                      key={key.id}
                      className="border-border cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800"
                      onClick={() => handleKeyClick(key)}
                      data-testid={`row-key-${key.id}`}
                    >
                      <TableCell
                        className="text-foreground w-12"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <input
                          type="checkbox"
                          checked={selectedKeys.includes(key.id)}
                          onChange={(e) =>
                            handleSelectKey(key.id, e.target.checked)
                          }
                          className="rounded border-gray-300"
                          data-testid={`select-key-${key.id}`}
                        />
                      </TableCell>
                      <TableCell
                        className="text-foreground font-mono text-sm"
                        data-testid={`kek-name-${key.id}`}
                      >
                        {key.kekName}
                      </TableCell>
                      <TableCell
                        className="text-foreground"
                        data-testid={`kek-algorithm-${key.id}`}
                      >
                        {key.algorithm || "N/A"}
                      </TableCell>
                      <TableCell
                        className="text-foreground"
                        data-testid={`kek-version-${key.id}`}
                      >
                        v{key.keyVersion}
                      </TableCell>
                      <TableCell
                        className="text-foreground"
                        data-testid={`kek-capabilities-${key.id}`}
                      >
                        <div className="flex flex-wrap gap-1">
                          {key.supportsEncryption && (
                            <Badge variant="outline" className="text-xs">
                              Encrypt
                            </Badge>
                          )}
                          {key.supportsDecryption && (
                            <Badge variant="outline" className="text-xs">
                              Decrypt
                            </Badge>
                          )}
                          {key.supportsSigning && (
                            <Badge variant="outline" className="text-xs">
                              Sign
                            </Badge>
                          )}
                          {key.supportsDerivation && (
                            <Badge variant="outline" className="text-xs">
                              Derive
                            </Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell
                        className="text-foreground"
                        data-testid={`key-created-${key.id}`}
                      >
                        {(() => {
                          try {
                            const date = new Date(key.createdAt);
                            if (isNaN(date.getTime())) {
                              return "Unknown";
                            }
                            return formatDistanceToNow(date, {
                              addSuffix: true,
                            });
                          } catch (error) {
                            console.warn(
                              "Invalid date for key:",
                              key.id,
                              key.createdAt,
                              error
                            );
                            return "Unknown";
                          }
                        })()}
                      </TableCell>
                      <TableCell>
                        <Badge
                          className={`${getStatusColor(key.status)} text-white`}
                          data-testid={`kek-status-${key.id}`}
                        >
                          {key.status.toUpperCase()}
                        </Badge>
                      </TableCell>
                      <TableCell onClick={(e) => e.stopPropagation()}>
                        <TooltipProvider>
                          <div className="flex space-x-1">
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  className="text-green-500 hover:text-green-400 hover:bg-slate-700"
                                  onClick={(e) => {
                                    e.preventDefault();
                                    e.stopPropagation();
                                    e.nativeEvent.stopImmediatePropagation();
                                    if (
                                      activeDownload !== key.id &&
                                      !activeDownload
                                    ) {
                                      downloadKeyMutation.mutate(key.id);
                                    }
                                  }}
                                  disabled={activeDownload === key.id}
                                  data-testid={`button-download-${key.id}`}
                                >
                                  {activeDownload === key.id ? "..." : "⬇"}
                                </Button>
                              </TooltipTrigger>
                              <TooltipContent>
                                <p>Download encryption key</p>
                              </TooltipContent>
                            </Tooltip>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  className="text-blue-500 hover:text-blue-400 hover:bg-slate-700"
                                  onClick={(e) => {
                                    e.preventDefault();
                                    e.stopPropagation();
                                    e.nativeEvent.stopImmediatePropagation();
                                    setTimeout(() => {
                                      copyToClipboard(key.keyId, "Key ID");
                                    }, 0);
                                  }}
                                  data-testid={`button-copy-${key.id}`}
                                >
                                  <Copy className="w-4 h-4" />
                                </Button>
                              </TooltipTrigger>
                              <TooltipContent>
                                <p>Copy key ID to clipboard</p>
                              </TooltipContent>
                            </Tooltip>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  className="text-green-500 hover:text-green-400 hover:bg-slate-700"
                                  onClick={(e) => {
                                    e.preventDefault();
                                    e.stopPropagation();
                                    e.nativeEvent.stopImmediatePropagation();
                                    if (
                                      activeRotate !== key.id &&
                                      !activeRotate &&
                                      key.status !== "rotating"
                                    ) {
                                      setActiveRotate(key.id);
                                      updateKeyStatusMutation.mutate({
                                        keyId: key.id,
                                        status: "rotating",
                                      });
                                    }
                                  }}
                                  disabled={
                                    activeRotate === key.id ||
                                    key.status === "rotating"
                                  }
                                  data-testid={`button-rotate-${key.id}`}
                                >
                                  <RotateCcw className="w-4 h-4" />
                                </Button>
                              </TooltipTrigger>
                              <TooltipContent>
                                <p>Rotate key to new version</p>
                              </TooltipContent>
                            </Tooltip>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  className="text-yellow-500 hover:text-yellow-400 hover:bg-slate-700"
                                  onClick={(e) => {
                                    e.preventDefault();
                                    e.stopPropagation();
                                    e.nativeEvent.stopImmediatePropagation();
                                    if (
                                      activeToggle !== key.id &&
                                      !activeToggle
                                    ) {
                                      setActiveToggle(key.id);
                                      updateKeyStatusMutation.mutate({
                                        keyId: key.id,
                                        status:
                                          key.status === "active"
                                            ? "expired"
                                            : "active",
                                      });
                                    }
                                  }}
                                  disabled={activeToggle === key.id}
                                  data-testid={`button-toggle-${key.id}`}
                                >
                                  <Pause className="w-4 h-4" />
                                </Button>
                              </TooltipTrigger>
                              <TooltipContent>
                                <p>
                                  {key.status === "active"
                                    ? "Disable key"
                                    : "Activate key"}
                                </p>
                              </TooltipContent>
                            </Tooltip>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  className="text-purple-500 hover:text-purple-400 hover:bg-slate-700"
                                  onClick={(e) => {
                                    e.preventDefault();
                                    e.stopPropagation();
                                    e.nativeEvent.stopImmediatePropagation();
                                    incrementKeyUsageMutation.mutate(key.id);
                                  }}
                                  data-testid={`button-test-${key.id}`}
                                >
                                  <Eye className="w-4 h-4" />
                                </Button>
                              </TooltipTrigger>
                              <TooltipContent>
                                <p>Test key (increment usage)</p>
                              </TooltipContent>
                            </Tooltip>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  className="text-red-500 hover:text-red-400 hover:bg-slate-700"
                                  onClick={(e) => {
                                    e.preventDefault();
                                    e.stopPropagation();
                                    e.nativeEvent.stopImmediatePropagation();
                                    if (
                                      activeRevoke !== key.id &&
                                      !activeRevoke &&
                                      key.status !== "revoked"
                                    ) {
                                      setActiveRevoke(key.id);
                                      revokeKeyMutation.mutate(key.id);
                                    }
                                  }}
                                  disabled={
                                    activeRevoke === key.id ||
                                    key.status === "revoked"
                                  }
                                  data-testid={`button-revoke-${key.id}`}
                                >
                                  <Trash2 className="w-4 h-4" />
                                </Button>
                              </TooltipTrigger>
                              <TooltipContent>
                                <p>Permanently revoke key</p>
                              </TooltipContent>
                            </Tooltip>
                          </div>
                        </TooltipProvider>
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
              <p className="text-slate-400">
                {searchQuery || statusFilter !== "all"
                  ? `No KEKs match your search criteria`
                  : "No Vault KEKs found"}
              </p>
              <p className="text-slate-500 text-sm mt-2">
                {searchQuery || statusFilter !== "all"
                  ? "Try adjusting your search or filter settings"
                  : "Generate your first SDK to create a KEK"}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Key Details Modal */}
      <Dialog open={isKeyDetailsOpen} onOpenChange={setIsKeyDetailsOpen}>
        <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Eye className="w-5 h-5" />
              Key Details
            </DialogTitle>
          </DialogHeader>

          {selectedKeyDetails && (
            <div className="space-y-6">
              {/* Basic Information */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Basic Information</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <Label className="text-sm font-medium text-muted-foreground">
                        KEK Name
                      </Label>
                      <div className="flex items-center gap-2">
                        <p className="font-mono text-sm bg-slate-100 dark:bg-slate-800 p-2 rounded">
                          {selectedKeyDetails.kekName}
                        </p>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() =>
                            copyToClipboard(
                              selectedKeyDetails.kekName,
                              "KEK Name"
                            )
                          }
                        >
                          <Copy className="w-4 h-4" />
                        </Button>
                      </div>
                    </div>
                    <div>
                      <Label className="text-sm font-medium text-muted-foreground">
                        Status
                      </Label>
                      <div className="mt-1">
                        <Badge
                          className={`${getStatusColor(
                            selectedKeyDetails.status
                          )} text-white`}
                        >
                          {selectedKeyDetails.status.toUpperCase()}
                        </Badge>
                      </div>
                    </div>
                    <div>
                      <Label className="text-sm font-medium text-muted-foreground">
                        Type
                      </Label>
                      <p className="text-sm">{selectedKeyDetails.keyType}</p>
                    </div>
                    <div>
                      <Label className="text-sm font-medium text-muted-foreground">
                        Algorithm
                      </Label>
                      <p className="text-sm">
                        {selectedKeyDetails.algorithm || "N/A"}
                      </p>
                    </div>
                    <div>
                      <Label className="text-sm font-medium text-muted-foreground">
                        Version
                      </Label>
                      <p className="text-sm">
                        v{selectedKeyDetails.keyVersion}
                      </p>
                    </div>
                    <div>
                      <Label className="text-sm font-medium text-muted-foreground">
                        Capabilities
                      </Label>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {selectedKeyDetails.supportsEncryption && (
                          <Badge variant="outline" className="text-xs">
                            Encrypt
                          </Badge>
                        )}
                        {selectedKeyDetails.supportsDecryption && (
                          <Badge variant="outline" className="text-xs">
                            Decrypt
                          </Badge>
                        )}
                        {selectedKeyDetails.supportsSigning && (
                          <Badge variant="outline" className="text-xs">
                            Sign
                          </Badge>
                        )}
                        {selectedKeyDetails.supportsDerivation && (
                          <Badge variant="outline" className="text-xs">
                            Derive
                          </Badge>
                        )}
                      </div>
                    </div>
                    <div>
                      <Label className="text-sm font-medium text-muted-foreground">
                        Usage Statistics
                      </Label>
                      <div className="mt-1">
                        {keyUsageStats[selectedKeyDetails.id] ? (
                          <div className="space-y-2">
                            <div className="flex items-center justify-between">
                              <span className="text-sm">Operations:</span>
                              <span className="text-sm font-medium">
                                {keyUsageStats[selectedKeyDetails.id]
                                  .usageCount || 0}
                              </span>
                            </div>
                            {keyUsageStats[selectedKeyDetails.id].maxUsage && (
                              <div className="flex items-center justify-between">
                                <span className="text-sm">Max Usage:</span>
                                <span className="text-sm font-medium">
                                  {
                                    keyUsageStats[selectedKeyDetails.id]
                                      .maxUsage
                                  }
                                </span>
                              </div>
                            )}
                            {keyUsageStats[selectedKeyDetails.id]
                              .usagePercentage && (
                              <div className="space-y-1">
                                <div className="flex items-center justify-between">
                                  <span className="text-sm">Usage %:</span>
                                  <span className="text-sm font-medium">
                                    {
                                      keyUsageStats[selectedKeyDetails.id]
                                        .usagePercentage
                                    }
                                    %
                                  </span>
                                </div>
                                <div className="w-full bg-gray-200 rounded-full h-2">
                                  <div
                                    className="bg-blue-600 h-2 rounded-full"
                                    style={{
                                      width: `${Math.min(
                                        keyUsageStats[selectedKeyDetails.id]
                                          .usagePercentage,
                                        100
                                      )}%`,
                                    }}
                                  ></div>
                                </div>
                              </div>
                            )}
                          </div>
                        ) : (
                          <p className="text-sm text-gray-400">
                            Loading usage stats...
                          </p>
                        )}
                      </div>
                    </div>
                    <div>
                      <Label className="text-sm font-medium text-muted-foreground">
                        Created
                      </Label>
                      <p className="text-sm">
                        {formatDistanceToNow(
                          new Date(selectedKeyDetails.createdAt),
                          { addSuffix: true }
                        )}
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Security Features */}
              {selectedKeyDetails.metadata?.securityFeatures && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg">Security Features</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 gap-2">
                      {selectedKeyDetails.metadata.securityFeatures.map(
                        (feature: string, index: number) => (
                          <div key={index} className="flex items-center gap-2">
                            <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                            <span className="text-sm">
                              {feature.replace(/_/g, " ")}
                            </span>
                          </div>
                        )
                      )}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Algorithm Details */}
              {selectedKeyDetails.algorithm && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg">Algorithm Details</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div>
                      <Label className="text-sm font-medium text-muted-foreground">
                        Name
                      </Label>
                      <p className="text-sm">
                        {selectedKeyDetails.algorithm.displayName}
                      </p>
                    </div>
                    <div>
                      <Label className="text-sm font-medium text-muted-foreground">
                        Type
                      </Label>
                      <p className="text-sm capitalize">
                        {selectedKeyDetails.algorithm.type}
                      </p>
                    </div>
                    <div>
                      <Label className="text-sm font-medium text-muted-foreground">
                        Description
                      </Label>
                      <p className="text-sm">
                        {selectedKeyDetails.algorithm.description}
                      </p>
                    </div>
                    <div className="flex gap-4">
                      <div className="flex items-center gap-2">
                        <div
                          className={`w-3 h-3 rounded-full ${
                            selectedKeyDetails.algorithm.isQuantumSafe
                              ? "bg-green-500"
                              : "bg-red-500"
                          }`}
                        ></div>
                        <span className="text-sm">
                          Quantum Safe:{" "}
                          {selectedKeyDetails.algorithm.isQuantumSafe
                            ? "Yes"
                            : "No"}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <div
                          className={`w-3 h-3 rounded-full ${
                            selectedKeyDetails.algorithm.isPostQuantum
                              ? "bg-green-500"
                              : "bg-yellow-500"
                          }`}
                        ></div>
                        <span className="text-sm">
                          Post-Quantum:{" "}
                          {selectedKeyDetails.algorithm.isPostQuantum
                            ? "Yes"
                            : "No"}
                        </span>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Rotation Information */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">
                    Rotation Information
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <Label className="text-sm font-medium text-muted-foreground">
                        Current Version
                      </Label>
                      <p className="text-sm">
                        {selectedKeyDetails.currentVersion || "1"}
                      </p>
                    </div>
                    <div>
                      <Label className="text-sm font-medium text-muted-foreground">
                        Version Status
                      </Label>
                      <p className="text-sm capitalize">
                        {selectedKeyDetails.versionStatus || "current"}
                      </p>
                    </div>
                    <div>
                      <Label className="text-sm font-medium text-muted-foreground">
                        Rotation Interval
                      </Label>
                      <p className="text-sm">
                        {selectedKeyDetails.rotationInterval || "N/A"} days
                      </p>
                    </div>
                    <div>
                      <Label className="text-sm font-medium text-muted-foreground">
                        Next Rotation
                      </Label>
                      <p className="text-sm">
                        {selectedKeyDetails.nextRotationAt
                          ? formatDistanceToNow(
                              new Date(selectedKeyDetails.nextRotationAt),
                              { addSuffix: true }
                            )
                          : "Not scheduled"}
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Advanced Metadata */}
              {selectedKeyDetails.metadata && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg">
                      Technical Metadata
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <pre className="text-xs bg-slate-100 dark:bg-slate-800 p-4 rounded overflow-x-auto">
                      {JSON.stringify(selectedKeyDetails.metadata, null, 2)}
                    </pre>
                  </CardContent>
                </Card>
              )}

              {/* Action Buttons */}
              <div className="flex gap-2 pt-4 border-t">
                <Button
                  variant="outline"
                  onClick={() =>
                    copyToClipboard(selectedKeyDetails.kekName, "KEK Name")
                  }
                  className="flex items-center gap-2"
                >
                  <Copy className="w-4 h-4" /> Copy KEK Name
                </Button>
                <Button
                  variant="outline"
                  onClick={() =>
                    rotateKekMutation.mutate(selectedKeyDetails.kekName)
                  }
                  disabled={isRotatingKek}
                  className="flex items-center gap-2"
                >
                  <RotateCcw className="w-4 h-4" />
                  {isRotatingKek ? "Rotating..." : "Rotate KEK"}
                </Button>
                <Button
                  variant="destructive"
                  onClick={() => {
                    if (
                      confirm(
                        `Are you sure you want to delete KEK ${selectedKeyDetails.kekName}? This action cannot be undone and will break all encrypted data.`
                      )
                    ) {
                      deleteKekMutation.mutate(selectedKeyDetails.kekName);
                    }
                  }}
                  className="flex items-center gap-2"
                >
                  <Trash2 className="w-4 h-4" /> Delete KEK
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Cryptographic Operations Section */}
      <div className="mt-8">
        <h2 className="text-xl font-semibold text-white mb-4">
          Cryptographic Operations
        </h2>
        <p className="text-slate-400 mb-6">
          Perform encryption, decryption, and other cryptographic operations
          using your Vault KEKs
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {/* Encrypt Operation */}
          <Card className="bg-slate-800 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Lock className="w-5 h-5 text-blue-400" />
                Encrypt Data
              </CardTitle>
            </CardHeader>
            <CardContent>
              <CryptoOperationForm
                operation="encrypt"
                kekNames={vaultKeks.map((k: any) => k.kekName)}
                onSuccess={(result) => {
                  toast({
                    title: "Data Encrypted",
                    description: "Data has been successfully encrypted",
                  });
                }}
              />
            </CardContent>
          </Card>

          {/* Decrypt Operation */}
          <Card className="bg-slate-800 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Unlock className="w-5 h-5 text-green-400" />
                Decrypt Data
              </CardTitle>
            </CardHeader>
            <CardContent>
              <CryptoOperationForm
                operation="decrypt"
                kekNames={vaultKeks.map((k: any) => k.kekName)}
                onSuccess={(result) => {
                  toast({
                    title: "Data Decrypted",
                    description: "Data has been successfully decrypted",
                  });
                }}
              />
            </CardContent>
          </Card>

          {/* Generate Data Key */}
          <Card className="bg-slate-800 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Key className="w-5 h-5 text-purple-400" />
                Generate Data Key
              </CardTitle>
            </CardHeader>
            <CardContent>
              <CryptoOperationForm
                operation="datakey"
                kekNames={vaultKeks.map((k: any) => k.kekName)}
                onSuccess={(result) => {
                  toast({
                    title: "Data Key Generated",
                    description: "New data encryption key has been generated",
                  });
                }}
              />
            </CardContent>
          </Card>

          {/* Rewrap Operation */}
          <Card className="bg-slate-800 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <RefreshCw className="w-5 h-5 text-orange-400" />
                Rewrap Ciphertext
              </CardTitle>
            </CardHeader>
            <CardContent>
              <CryptoOperationForm
                operation="rewrap"
                kekNames={vaultKeks.map((k: any) => k.kekName)}
                onSuccess={(result) => {
                  toast({
                    title: "Ciphertext Rewrapped",
                    description:
                      "Ciphertext has been re-encrypted with latest KEK version",
                  });
                }}
              />
            </CardContent>
          </Card>

          {/* Generate HMAC */}
          <Card className="bg-slate-800 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Hash className="w-5 h-5 text-cyan-400" />
                Generate HMAC
              </CardTitle>
            </CardHeader>
            <CardContent>
              <CryptoOperationForm
                operation="hmac"
                kekNames={vaultKeks.map((k: any) => k.kekName)}
                onSuccess={(result) => {
                  toast({
                    title: "HMAC Generated",
                    description: "HMAC has been generated for data integrity",
                  });
                }}
              />
            </CardContent>
          </Card>

          {/* Verify HMAC */}
          <Card className="bg-slate-800 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <CheckCircle className="w-5 h-5 text-emerald-400" />
                Verify HMAC
              </CardTitle>
            </CardHeader>
            <CardContent>
              <CryptoOperationForm
                operation="verify"
                kekNames={vaultKeks.map((k: any) => k.kekName)}
                onSuccess={(result) => {
                  toast({
                    title: "HMAC Verified",
                    description: result.valid
                      ? "HMAC is valid"
                      : "HMAC is invalid",
                    variant: result.valid ? "default" : "destructive",
                  });
                }}
              />
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

// Cryptographic Operation Form Component
function CryptoOperationForm({
  operation,
  kekNames,
  onSuccess,
}: {
  operation: string;
  kekNames: string[];
  onSuccess: (result: any) => void;
}) {
  const [selectedKek, setSelectedKek] = useState("");
  const [inputData, setInputData] = useState("");
  const [hmacValue, setHmacValue] = useState(""); // Separate field for HMAC verification
  const [context, setContext] = useState("");
  const [result, setResult] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedKek) {
      setError("Please select a KEK");
      return;
    }

    setIsLoading(true);
    setError("");
    setResult(null);

    try {
      const payload: any = {};

      if (
        operation === "encrypt" ||
        operation === "decrypt" ||
        operation === "rewrap"
      ) {
        if (!inputData.trim()) {
          setError("Input data is required");
          setIsLoading(false);
          return;
        }
        payload[operation === "encrypt" ? "plaintext" : "ciphertext"] =
          inputData;
      } else if (operation === "hmac" || operation === "verify") {
        if (!inputData.trim()) {
          setError("Data is required");
          setIsLoading(false);
          return;
        }
        payload.data = inputData;
        if (operation === "verify") {
          // For verify, use the separate HMAC field
          if (!hmacValue.trim()) {
            setError("HMAC value is required for verification");
            setIsLoading(false);
            return;
          }
          payload.hmac = hmacValue;
        }
      }

      if (context.trim()) {
        payload.context = context;
      }

      const response = await apiRequest(
        "POST",
        `/api/vault/test/${operation}`,
        { ...payload, kekName: selectedKek }
      );

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || `Failed to ${operation} data`);
      }

      const resultData = await response.json();
      setResult(resultData);
      onSuccess(resultData);
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred");
    } finally {
      setIsLoading(false);
    }
  };

  const getInputLabel = () => {
    switch (operation) {
      case "encrypt":
        return "Plaintext to encrypt";
      case "decrypt":
        return "Ciphertext to decrypt";
      case "rewrap":
        return "Ciphertext to rewrap";
      case "hmac":
        return "Data to generate HMAC for";
      case "verify":
        return "Enter the original data that was used to generate the HMAC";
      case "datakey":
        return "Optional context";
      default:
        return "Input data";
    }
  };

  const getInputPlaceholder = () => {
    switch (operation) {
      case "encrypt":
        return "Enter the data you want to encrypt...";
      case "decrypt":
        return "vault:v1:encrypted_data_here";
      case "rewrap":
        return "vault:v1:old_encrypted_data";
      case "hmac":
        return "Enter the data to generate HMAC for...";
      case "verify":
        return "Enter the original data that was used to generate the HMAC";
      case "datakey":
        return "Optional context for additional security";
      default:
        return "Enter data...";
    }
  };

  const showContextField = operation !== "datakey";

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <Label htmlFor="kek-select" className="text-white">
          Select KEK
        </Label>
        <Select value={selectedKek} onValueChange={setSelectedKek}>
          <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
            <SelectValue placeholder="Choose a KEK" />
          </SelectTrigger>
          <SelectContent>
            {kekNames.map((kek) => (
              <SelectItem key={kek} value={kek} className="text-white">
                {kek}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {operation !== "datakey" && (
        <div>
          <Label htmlFor="input-data" className="text-white">
            {getInputLabel()}
          </Label>
          <Textarea
            id="input-data"
            value={inputData}
            onChange={(e) => setInputData(e.target.value)}
            placeholder={getInputPlaceholder()}
            className="bg-slate-700 border-slate-600 text-white min-h-[100px]"
            rows={4}
          />
        </div>
      )}

      {operation === "verify" && (
        <div>
          <Label htmlFor="hmac-input" className="text-white">
            HMAC to Verify
          </Label>
          <Input
            id="hmac-input"
            value={hmacValue}
            onChange={(e) => setHmacValue(e.target.value)}
            placeholder="vault:v4:your-hmac-here"
            className="bg-slate-700 border-slate-600 text-white"
          />
        </div>
      )}

      {showContextField && (
        <div>
          <Label htmlFor="context" className="text-white">
            Context (Optional)
          </Label>
          <Input
            id="context"
            value={context}
            onChange={(e) => setContext(e.target.value)}
            placeholder="Additional context for security"
            className="bg-slate-700 border-slate-600 text-white"
          />
        </div>
      )}

      <Button
        type="submit"
        disabled={isLoading || !selectedKek}
        className="w-full bg-blue-600 hover:bg-blue-700 text-white"
      >
        {isLoading ? (
          <>
            <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
            Processing...
          </>
        ) : (
          <>
            {operation === "encrypt" && <Lock className="w-4 h-4 mr-2" />}
            {operation === "decrypt" && <Unlock className="w-4 h-4 mr-2" />}
            {operation === "datakey" && <Key className="w-4 h-4 mr-2" />}
            {operation === "rewrap" && <RefreshCw className="w-4 h-4 mr-2" />}
            {operation === "hmac" && <Hash className="w-4 h-4 mr-2" />}
            {operation === "verify" && <CheckCircle className="w-4 h-4 mr-2" />}
            {operation.charAt(0).toUpperCase() + operation.slice(1)}
          </>
        )}
      </Button>

      {error && (
        <div className="p-3 bg-red-900/20 border border-red-500/50 rounded text-red-300 text-sm">
          <XCircle className="w-4 h-4 inline mr-2" />
          {error}
        </div>
      )}

      {result && (
        <div className="p-3 bg-green-900/20 border border-green-500/50 rounded text-green-300 text-sm">
          <CheckCircle className="w-4 h-4 inline mr-2" />
          <div className="font-semibold mb-2">Result:</div>
          <div className="space-y-2">
            {operation === "encrypt" && (
              <div>
                <div className="font-medium">Ciphertext:</div>
                <div className="bg-slate-800 p-2 rounded text-xs font-mono break-all">
                  {result.ciphertext}
                </div>
              </div>
            )}
            {operation === "decrypt" && (
              <div className="space-y-2">
                <div>
                  <div className="font-medium">Plaintext (Base64):</div>
                  <div className="bg-slate-800 p-2 rounded text-xs font-mono break-all">
                    {result.plaintext}
                  </div>
                </div>
                <div>
                  <div className="font-medium">Plaintext (Raw Bytes):</div>
                  <div className="bg-slate-800 p-2 rounded text-xs font-mono break-all max-h-32 overflow-y-auto">
                    {(() => {
                      try {
                        // Decode base64 to get raw bytes
                        const binaryString = atob(result.plaintext);
                        return binaryString;
                      } catch (e) {
                        return "Unable to decode base64";
                      }
                    })()}
                  </div>
                </div>
                <div>
                  <div className="font-medium">Plaintext (Hex):</div>
                  <div className="bg-slate-800 p-2 rounded text-xs font-mono break-all">
                    {(() => {
                      try {
                        // Decode base64 to get raw bytes, then convert to hex
                        const binaryString = atob(result.plaintext);
                        return Array.from(binaryString)
                          .map((char: string) =>
                            char.charCodeAt(0).toString(16).padStart(2, "0")
                          )
                          .join(" ");
                      } catch (e) {
                        return "Unable to decode base64 to hex";
                      }
                    })()}
                  </div>
                </div>
                <div>
                  <div className="font-medium">Plaintext (UTF-8):</div>
                  <div className="bg-slate-800 p-2 rounded text-xs font-mono break-all">
                    {(() => {
                      try {
                        // Try to decode as UTF-8
                        const binaryString = atob(result.plaintext);
                        const decoder = new TextDecoder("utf-8");
                        const bytes = new Uint8Array(
                          Array.from(binaryString).map((char) =>
                            char.charCodeAt(0)
                          )
                        );
                        return decoder.decode(bytes);
                      } catch (e) {
                        return "Unable to decode as UTF-8";
                      }
                    })()}
                  </div>
                </div>
              </div>
            )}
            {operation === "datakey" && (
              <div className="space-y-2">
                <div>
                  <div className="font-medium">Plaintext DEK (Base64):</div>
                  <div className="bg-slate-800 p-2 rounded text-xs font-mono break-all">
                    {result.plaintext}
                  </div>
                </div>
                <div>
                  <div className="font-medium">Plaintext DEK (Hex):</div>
                  <div className="bg-slate-800 p-2 rounded text-xs font-mono break-all">
                    {(() => {
                      try {
                        return Array.from(atob(result.plaintext))
                          .map((char) =>
                            char.charCodeAt(0).toString(16).padStart(2, "0")
                          )
                          .join(" ");
                      } catch (e) {
                        return "Unable to decode Base64 to Hex";
                      }
                    })()}
                  </div>
                </div>
                <div>
                  <div className="font-medium">Encrypted DEK:</div>
                  <div className="bg-slate-800 p-2 rounded text-xs font-mono break-all">
                    {result.ciphertext}
                  </div>
                </div>
              </div>
            )}
            {operation === "rewrap" && (
              <div>
                <div className="font-medium">New Ciphertext:</div>
                <div className="bg-slate-800 p-2 rounded text-xs font-mono break-all">
                  {result.newCiphertext}
                </div>
              </div>
            )}
            {operation === "hmac" && (
              <div>
                <div className="font-medium">HMAC:</div>
                <div className="bg-slate-800 p-2 rounded text-xs font-mono break-all">
                  {result.hmac}
                </div>
              </div>
            )}
            {operation === "verify" && (
              <div>
                <div className="font-medium">Verification Result:</div>
                <div
                  className={`p-2 rounded text-sm font-semibold ${
                    result.valid
                      ? "bg-green-800 text-green-200"
                      : "bg-red-800 text-red-200"
                  }`}
                >
                  {result.valid ? "✓ Valid HMAC" : "✗ Invalid HMAC"}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </form>
  );
}
