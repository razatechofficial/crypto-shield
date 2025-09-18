import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery } from "@tanstack/react-query";
import { z } from "zod";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import {
  Upload,
  Key,
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  FileText,
  Lock,
  Database,
  Settings,
  Eye,
  EyeOff,
  RefreshCw,
  Download
} from "lucide-react";

// BYOK Import Schema
const byokImportSchema = z.object({
  keyName: z.string().min(1, "Key name is required").max(128, "Key name too long"),
  description: z.string().optional(),
  keyMaterial: z.string().min(1, "Key material is required"),
  keyFormat: z.enum(["raw", "pem", "der", "jwk"], {
    required_error: "Key format is required"
  }),
  keyType: z.enum(["aes-256", "aes-128", "rsa-2048", "rsa-4096", "ec-p256", "ec-p384", "ed25519"], {
    required_error: "Key type is required"
  }),
  keyUsage: z.array(z.enum(["encrypt", "decrypt", "sign", "verify", "derive", "unwrap", "wrap"])).min(1, "At least one usage is required"),
  providerId: z.string().min(1, "Provider is required"),
  enableAutoRotation: z.boolean().default(false),
  rotationInterval: z.number().min(30).max(365).optional(),
  compliance: z.object({
    fips140Level: z.enum(["none", "level-1", "level-2", "level-3", "level-4"]).default("none"),
    commonCriteria: z.boolean().default(false),
    soxCompliance: z.boolean().default(false),
    hipaaCompliance: z.boolean().default(false),
    pciDssCompliance: z.boolean().default(false)
  }).optional(),
  metadata: z.record(z.string()).optional()
});

type BYOKImport = z.infer<typeof byokImportSchema>;

interface ImportedKey {
  id: string;
  name: string;
  keyType: string;
  keyFormat: string;
  providerId: string;
  providerName: string;
  status: "importing" | "active" | "failed" | "validating";
  importedAt: string;
  lastRotated?: string;
  nextRotation?: string;
  keyUsage: string[];
  compliance: {
    fips140Level: string;
    commonCriteria: boolean;
    soxCompliance: boolean;
    hipaaCompliance: boolean;
    pciDssCompliance: boolean;
  };
  metadata?: Record<string, string>;
}

interface CloudProvider {
  id: string;
  name: string;
  provider: string;
  region: string;
  status: string;
}

export default function BYOKImportPage() {
  const [showKeyMaterial, setShowKeyMaterial] = useState(false);
  const [importProgress, setImportProgress] = useState(0);
  const [selectedTab, setSelectedTab] = useState("import");
  const { toast } = useToast();

  // Fetch available cloud providers
  const { data: providers = [], isLoading: providersLoading } = useQuery<CloudProvider[]>({
    queryKey: ["/api/cloud-providers"],
  });

  // Fetch imported keys
  const { data: importedKeys = [], isLoading: keysLoading } = useQuery<ImportedKey[]>({
    queryKey: ["/api/byok/imported-keys"],
  });

  // Form setup
  const form = useForm<BYOKImport>({
    resolver: zodResolver(byokImportSchema),
    defaultValues: {
      keyName: "",
      description: "",
      keyMaterial: "",
      keyFormat: "raw",
      keyType: "aes-256",
      keyUsage: ["encrypt", "decrypt"],
      enableAutoRotation: false,
      rotationInterval: 90,
      compliance: {
        fips140Level: "none",
        commonCriteria: false,
        soxCompliance: false,
        hipaaCompliance: false,
        pciDssCompliance: false
      },
      metadata: {}
    }
  });

  // Import mutation
  const importMutation = useMutation({
    mutationFn: async (data: BYOKImport) => {
      // Simulate progress updates
      setImportProgress(0);
      const progressInterval = setInterval(() => {
        setImportProgress(prev => Math.min(prev + 10, 90));
      }, 200);

      try {
        const response = await apiRequest("POST", "/api/byok/import", data);
        setImportProgress(100);
        clearInterval(progressInterval);
        return response.json();
      } catch (error) {
        clearInterval(progressInterval);
        setImportProgress(0);
        throw error;
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/byok/imported-keys"] });
      toast({
        title: "Key Import Successful",
        description: "Your key has been securely imported and is ready for use.",
      });
      form.reset();
      setSelectedTab("keys");
      setImportProgress(0);
    },
    onError: (error: any) => {
      toast({
        title: "Import Failed",
        description: error.message || "Failed to import key. Please verify the key format and try again.",
        variant: "destructive",
      });
      setImportProgress(0);
    },
  });

  // Validate key mutation
  const validateMutation = useMutation({
    mutationFn: async (keyMaterial: string) => {
      return apiRequest("POST", "/api/byok/validate", { keyMaterial, keyFormat: form.getValues("keyFormat") });
    },
    onSuccess: (data: any) => {
      toast({
        title: "Key Validation Successful",
        description: `Key is valid. Detected ${data.keyType} with ${data.keyLength}-bit length.`,
      });
    },
    onError: () => {
      toast({
        title: "Key Validation Failed",
        description: "Invalid key format or corrupted key material.",
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: BYOKImport) => {
    importMutation.mutate(data);
  };

  const handleValidateKey = () => {
    const keyMaterial = form.getValues("keyMaterial");
    if (!keyMaterial) {
      toast({
        title: "No Key Material",
        description: "Please provide key material to validate.",
        variant: "destructive",
      });
      return;
    }
    validateMutation.mutate(keyMaterial);
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "active":
        return <CheckCircle className="w-4 h-4 text-green-500" />;
      case "importing":
      case "validating":
        return <Clock className="w-4 h-4 text-yellow-500" />;
      case "failed":
        return <AlertTriangle className="w-4 h-4 text-red-500" />;
      default:
        return <Clock className="w-4 h-4 text-gray-500" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "active":
        return "bg-green-500";
      case "importing":
      case "validating":
        return "bg-yellow-500";
      case "failed":
        return "bg-red-500";
      default:
        return "bg-gray-500";
    }
  };

  return (
    <div className="p-6 space-y-6" data-testid="byok-import-page">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Bring Your Own Key (BYOK)</h1>
          <p className="text-muted-foreground">Import and manage your own encryption keys across cloud providers</p>
        </div>
      </div>

      <Tabs value={selectedTab} onValueChange={setSelectedTab} className="space-y-4">
        <TabsList data-testid="tabs-byok">
          <TabsTrigger value="import" data-testid="tab-import">Import Key</TabsTrigger>
          <TabsTrigger value="keys" data-testid="tab-keys">Imported Keys</TabsTrigger>
          <TabsTrigger value="compliance" data-testid="tab-compliance">Compliance</TabsTrigger>
        </TabsList>

        {/* Import Key Tab */}
        <TabsContent value="import" className="space-y-6">
          <Card data-testid="card-import-form">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Upload className="w-5 h-5" />
                Import Your Key
              </CardTitle>
              <CardDescription>
                Securely import your own encryption keys for use across cloud providers
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Form {...form}>
                <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Key Name */}
                    <FormField
                      control={form.control}
                      name="keyName"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Key Name</FormLabel>
                          <FormControl>
                            <Input 
                              placeholder="my-encryption-key" 
                              {...field} 
                              data-testid="input-key-name"
                            />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    {/* Provider */}
                    <FormField
                      control={form.control}
                      name="providerId"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Target Provider</FormLabel>
                          <Select onValueChange={field.onChange} defaultValue={field.value}>
                            <FormControl>
                              <SelectTrigger data-testid="select-provider">
                                <SelectValue placeholder="Select provider" />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              {providers.map((provider) => (
                                <SelectItem key={provider.id} value={provider.id}>
                                  {provider.name} ({provider.region})
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  </div>

                  {/* Description */}
                  <FormField
                    control={form.control}
                    name="description"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Description (Optional)</FormLabel>
                        <FormControl>
                          <Textarea 
                            placeholder="Describe the purpose of this key..." 
                            {...field} 
                            data-testid="input-description"
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Key Format */}
                    <FormField
                      control={form.control}
                      name="keyFormat"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Key Format</FormLabel>
                          <Select onValueChange={field.onChange} defaultValue={field.value}>
                            <FormControl>
                              <SelectTrigger data-testid="select-key-format">
                                <SelectValue />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              <SelectItem value="raw">Raw Binary</SelectItem>
                              <SelectItem value="pem">PEM Format</SelectItem>
                              <SelectItem value="der">DER Format</SelectItem>
                              <SelectItem value="jwk">JSON Web Key (JWK)</SelectItem>
                            </SelectContent>
                          </Select>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    {/* Key Type */}
                    <FormField
                      control={form.control}
                      name="keyType"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Key Type</FormLabel>
                          <Select onValueChange={field.onChange} defaultValue={field.value}>
                            <FormControl>
                              <SelectTrigger data-testid="select-key-type">
                                <SelectValue />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              <SelectItem value="aes-256">AES-256</SelectItem>
                              <SelectItem value="aes-128">AES-128</SelectItem>
                              <SelectItem value="rsa-2048">RSA-2048</SelectItem>
                              <SelectItem value="rsa-4096">RSA-4096</SelectItem>
                              <SelectItem value="ec-p256">EC P-256</SelectItem>
                              <SelectItem value="ec-p384">EC P-384</SelectItem>
                              <SelectItem value="ed25519">Ed25519</SelectItem>
                            </SelectContent>
                          </Select>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  </div>

                  {/* Key Material */}
                  <FormField
                    control={form.control}
                    name="keyMaterial"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Key Material</FormLabel>
                        <div className="space-y-2">
                          <div className="flex items-center gap-2">
                            <FormControl>
                              <Textarea
                                placeholder="Enter your key material (base64 encoded, PEM, or JWK)"
                                className={`font-mono text-sm ${!showKeyMaterial ? "text-security-disc" : ""}`}
                                style={!showKeyMaterial ? { WebkitTextSecurity: "disc", textSecurity: "disc" } : {}}
                                rows={6}
                                {...field}
                                data-testid="input-key-material"
                              />
                            </FormControl>
                            <div className="flex flex-col gap-2">
                              <Button
                                type="button"
                                variant="outline"
                                size="icon"
                                onClick={() => setShowKeyMaterial(!showKeyMaterial)}
                                data-testid="button-toggle-key-visibility"
                              >
                                {showKeyMaterial ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                              </Button>
                              <Button
                                type="button"
                                variant="outline"
                                size="icon"
                                onClick={handleValidateKey}
                                disabled={validateMutation.isPending}
                                data-testid="button-validate-key"
                              >
                                {validateMutation.isPending ? (
                                  <RefreshCw className="w-4 h-4 animate-spin" />
                                ) : (
                                  <Shield className="w-4 h-4" />
                                )}
                              </Button>
                            </div>
                          </div>
                          <FormDescription>
                            Paste your key material in the selected format. The key will be validated before import.
                          </FormDescription>
                        </div>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  {/* Import Progress */}
                  {importMutation.isPending && (
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span>Import Progress</span>
                        <span>{importProgress}%</span>
                      </div>
                      <Progress value={importProgress} className="h-2" />
                    </div>
                  )}

                  {/* Submit Button */}
                  <Button 
                    type="submit" 
                    className="w-full" 
                    disabled={importMutation.isPending}
                    data-testid="button-import-key"
                  >
                    {importMutation.isPending ? (
                      <>
                        <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                        Importing Key...
                      </>
                    ) : (
                      <>
                        <Upload className="w-4 h-4 mr-2" />
                        Import Key
                      </>
                    )}
                  </Button>
                </form>
              </Form>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Imported Keys Tab */}
        <TabsContent value="keys" className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold">Imported Keys</h2>
            <Button variant="outline" className="gap-2" data-testid="button-refresh-keys">
              <RefreshCw className="w-4 h-4" />
              Refresh
            </Button>
          </div>

          {keysLoading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {[...Array(4)].map((_, i) => (
                <Card key={i} className="animate-pulse">
                  <CardHeader>
                    <div className="w-32 h-5 bg-muted rounded" />
                    <div className="w-24 h-4 bg-muted rounded" />
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      <div className="w-full h-4 bg-muted rounded" />
                      <div className="w-3/4 h-4 bg-muted rounded" />
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : importedKeys.length === 0 ? (
            <Card data-testid="card-no-keys">
              <CardContent className="pt-6">
                <div className="text-center">
                  <Key className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                  <h3 className="text-lg font-semibold mb-2">No Keys Imported</h3>
                  <p className="text-muted-foreground mb-4">
                    Import your first encryption key to get started with BYOK
                  </p>
                  <Button onClick={() => setSelectedTab("import")} data-testid="button-import-first-key">
                    <Upload className="w-4 h-4 mr-2" />
                    Import Your First Key
                  </Button>
                </div>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {importedKeys.map((key) => (
                <Card key={key.id} data-testid={`card-key-${key.id}`}>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-lg">{key.name}</CardTitle>
                      <div className="flex items-center gap-2">
                        {getStatusIcon(key.status)}
                        <Badge 
                          variant="secondary" 
                          className={`${getStatusColor(key.status)} text-white`}
                          data-testid={`badge-status-${key.id}`}
                        >
                          {key.status}
                        </Badge>
                      </div>
                    </div>
                    <CardDescription>{key.providerName}</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <p className="text-muted-foreground">Key Type</p>
                        <p className="font-medium">{key.keyType}</p>
                      </div>
                      <div>
                        <p className="text-muted-foreground">Format</p>
                        <p className="font-medium">{key.keyFormat}</p>
                      </div>
                      <div>
                        <p className="text-muted-foreground">Usage</p>
                        <p className="font-medium">{key.keyUsage.join(", ")}</p>
                      </div>
                      <div>
                        <p className="text-muted-foreground">Imported</p>
                        <p className="font-medium">{new Date(key.importedAt).toLocaleDateString()}</p>
                      </div>
                    </div>

                    {key.nextRotation && (
                      <div className="text-sm">
                        <p className="text-muted-foreground">Next Rotation</p>
                        <p className="font-medium">{new Date(key.nextRotation).toLocaleDateString()}</p>
                      </div>
                    )}

                    <div className="flex gap-2">
                      <Button variant="outline" size="sm" data-testid={`button-view-${key.id}`}>
                        <Eye className="w-3 h-3 mr-1" />
                        View
                      </Button>
                      <Button variant="outline" size="sm" data-testid={`button-rotate-${key.id}`}>
                        <RefreshCw className="w-3 h-3 mr-1" />
                        Rotate
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* Compliance Tab */}
        <TabsContent value="compliance" className="space-y-4">
          <Card data-testid="card-compliance-overview">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="w-5 h-5" />
                Compliance Overview
              </CardTitle>
              <CardDescription>
                Security and compliance features for imported keys
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <div className="text-center p-4 border rounded-lg">
                  <Lock className="w-8 h-8 mx-auto mb-2 text-blue-500" />
                  <h3 className="font-semibold">FIPS 140-2</h3>
                  <p className="text-sm text-muted-foreground">
                    Hardware security module compliance
                  </p>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  <FileText className="w-8 h-8 mx-auto mb-2 text-green-500" />
                  <h3 className="font-semibold">Common Criteria</h3>
                  <p className="text-sm text-muted-foreground">
                    International security standard
                  </p>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  <Database className="w-8 h-8 mx-auto mb-2 text-purple-500" />
                  <h3 className="font-semibold">SOX Compliance</h3>
                  <p className="text-sm text-muted-foreground">
                    Financial data protection
                  </p>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  <Shield className="w-8 h-8 mx-auto mb-2 text-red-500" />
                  <h3 className="font-semibold">HIPAA</h3>
                  <p className="text-sm text-muted-foreground">
                    Healthcare data security
                  </p>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  <Settings className="w-8 h-8 mx-auto mb-2 text-orange-500" />
                  <h3 className="font-semibold">PCI DSS</h3>
                  <p className="text-sm text-muted-foreground">
                    Payment card security
                  </p>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  <Download className="w-8 h-8 mx-auto mb-2 text-indigo-500" />
                  <h3 className="font-semibold">Audit Reports</h3>
                  <p className="text-sm text-muted-foreground">
                    Compliance documentation
                  </p>
                </div>
              </div>

              <Alert data-testid="alert-compliance-info">
                <Shield className="w-4 h-4" />
                <AlertDescription>
                  Imported keys automatically inherit the compliance features of the target cloud provider.
                  Additional compliance controls can be configured during the import process.
                </AlertDescription>
              </Alert>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}