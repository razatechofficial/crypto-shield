import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Loader, TestTube, CheckCircle, AlertCircle } from "lucide-react";
import { Database, Lock, Shield as CloudShield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Checkbox } from "@/components/ui/checkbox";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";

const baseConfigSchema = z.object({
  name: z.string().min(1, "Provider name is required"),
  provider: z.enum(["aws_kms", "azure_key_vault", "gcp_kms"]),
  region: z.string().min(1, "Region is required"),
  description: z.string().optional(),
});

const awsConfigSchema = baseConfigSchema.extend({
  provider: z.literal("aws_kms"),
  accessKeyId: z.string().min(1, "Access Key ID is required"),
  secretAccessKey: z.string().min(1, "Secret Access Key is required"),
  roleArn: z.string().optional(),
});

const azureConfigSchema = baseConfigSchema.extend({
  provider: z.literal("azure_key_vault"),
  vaultUrl: z.string().url("Valid vault URL is required"),
  tenantId: z.string().min(1, "Tenant ID is required"),
  clientId: z.string().min(1, "Client ID is required"),
  clientSecret: z.string().min(1, "Client Secret is required"),
  useManagedIdentity: z.boolean().default(false),
});

const gcpConfigSchema = baseConfigSchema.extend({
  provider: z.literal("gcp_kms"),
  projectId: z.string().min(1, "Project ID is required"),
  keyRingId: z.string().min(1, "Key Ring ID is required"),
  location: z.string().min(1, "Location is required"),
  serviceAccountKey: z.string().optional(),
  useWorkloadIdentity: z.boolean().default(false),
});

type ProviderConfig = z.infer<typeof awsConfigSchema> | z.infer<typeof azureConfigSchema> | z.infer<typeof gcpConfigSchema>;

interface ProviderConfigFormProps {
  onSuccess: () => void;
}

export default function ProviderConfigForm({ onSuccess }: ProviderConfigFormProps) {
  const [selectedProvider, setSelectedProvider] = useState<"aws_kms" | "azure_key_vault" | "gcp_kms">("aws_kms");
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);
  const { toast } = useToast();

  const form = useForm<ProviderConfig>({
    resolver: zodResolver(
      selectedProvider === "aws_kms" ? awsConfigSchema :
      selectedProvider === "azure_key_vault" ? azureConfigSchema :
      gcpConfigSchema
    ),
    defaultValues: {
      name: "",
      provider: selectedProvider,
      region: "",
      description: "",
    } as ProviderConfig,
  });

  // Test connection mutation
  const testConnectionMutation = useMutation({
    mutationFn: async (config: Partial<ProviderConfig>) => {
      const response = await apiRequest("POST", "/api/cloud-providers/test", config);
      return response.json();
    },
    onSuccess: (data) => {
      setTestResult({ success: true, message: "Connection successful!" });
    },
    onError: (error: Error) => {
      setTestResult({ success: false, message: error.message });
    },
  });

  // Create provider mutation
  const createProviderMutation = useMutation({
    mutationFn: async (config: ProviderConfig) => {
      const response = await apiRequest("POST", "/api/cloud-providers", config);
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Provider Created",
        description: "Cloud provider has been configured successfully.",
      });
      onSuccess();
    },
    onError: (error: Error) => {
      toast({
        title: "Configuration Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: ProviderConfig) => {
    createProviderMutation.mutate(data);
  };

  const handleTestConnection = () => {
    const values = form.getValues();
    testConnectionMutation.mutate(values);
  };

  const handleProviderChange = (provider: "aws_kms" | "azure_key_vault" | "gcp_kms") => {
    setSelectedProvider(provider);
    setTestResult(null);
    form.reset({
      name: "",
      provider,
      region: "",
      description: "",
    } as ProviderConfig);
  };

  return (
    <div className="space-y-6">
      {/* Provider Selection */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          { id: "aws_kms", name: "AWS KMS", icon: Database, description: "Amazon Key Management Service" },
          { id: "azure_key_vault", name: "Azure Key Vault", icon: Lock, description: "Microsoft Azure Key Vault" },
          { id: "gcp_kms", name: "Google Cloud KMS", icon: CloudShield, description: "Google Cloud Key Management" },
        ].map((provider) => (
          <Card 
            key={provider.id}
            className={`cursor-pointer transition-all ${
              selectedProvider === provider.id 
                ? "ring-2 ring-primary border-primary" 
                : "hover:shadow-md"
            }`}
            onClick={() => handleProviderChange(provider.id as any)}
            data-testid={`provider-${provider.id}`}
          >
            <CardContent className="flex flex-col items-center text-center p-6">
              <div className="text-3xl mb-2 text-muted-foreground">
                {(() => {
                  const IconComponent = provider.icon;
                  return <IconComponent className="w-12 h-12" aria-label={provider.name} />;
                })()}
              </div>
              <h3 className="font-semibold">{provider.name}</h3>
              <p className="text-sm text-muted-foreground">{provider.description}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Configuration Form */}
      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
          {/* Basic Configuration */}
          <Card>
            <CardHeader>
              <CardTitle>Basic Configuration</CardTitle>
              <CardDescription>
                General settings for your {selectedProvider.replace('_', ' ').toUpperCase()} provider.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <FormField
                control={form.control}
                name="name"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Provider Name</FormLabel>
                    <FormControl>
                      <Input placeholder="e.g., Production AWS KMS" {...field} data-testid="input-name" />
                    </FormControl>
                    <FormDescription>
                      A friendly name to identify this provider configuration.
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="region"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Region</FormLabel>
                    <FormControl>
                      <Input 
                        placeholder={
                          selectedProvider === "aws_kms" ? "us-east-1" :
                          selectedProvider === "azure_key_vault" ? "eastus" :
                          "us-central1"
                        } 
                        {...field} 
                        data-testid="input-region"
                      />
                    </FormControl>
                    <FormDescription>
                      The primary region for this provider configuration.
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="description"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Description (Optional)</FormLabel>
                    <FormControl>
                      <Textarea 
                        placeholder="Additional details about this provider configuration..."
                        {...field} 
                        data-testid="input-description"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </CardContent>
          </Card>

          {/* Provider-Specific Configuration */}
          <Card>
            <CardHeader>
              <CardTitle>Authentication Configuration</CardTitle>
              <CardDescription>
                Security credentials and authentication settings for {selectedProvider.replace('_', ' ').toUpperCase()}.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {selectedProvider === "aws_kms" && (
                <>
                  <FormField
                    control={form.control}
                    name="accessKeyId"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Access Key ID</FormLabel>
                        <FormControl>
                          <Input placeholder="AKIA..." {...field} data-testid="input-access-key" />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="secretAccessKey"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Secret Access Key</FormLabel>
                        <FormControl>
                          <Input type="password" {...field} data-testid="input-secret-key" />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="roleArn"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Role ARN (Optional)</FormLabel>
                        <FormControl>
                          <Input placeholder="arn:aws:iam::123456789012:role/KMSRole" {...field} data-testid="input-role-arn" />
                        </FormControl>
                        <FormDescription>
                          For cross-account access or enhanced security.
                        </FormDescription>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </>
              )}

              {selectedProvider === "azure_key_vault" && (
                <>
                  <FormField
                    control={form.control}
                    name="vaultUrl"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Key Vault URL</FormLabel>
                        <FormControl>
                          <Input placeholder="https://your-vault.vault.azure.net/" {...field} data-testid="input-vault-url" />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="tenantId"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Tenant ID</FormLabel>
                        <FormControl>
                          <Input {...field} data-testid="input-tenant-id" />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="clientId"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Client ID</FormLabel>
                        <FormControl>
                          <Input {...field} data-testid="input-client-id" />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="clientSecret"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Client Secret</FormLabel>
                        <FormControl>
                          <Input type="password" {...field} data-testid="input-client-secret" />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="useManagedIdentity"
                    render={({ field }) => (
                      <FormItem className="flex flex-row items-start space-x-3 space-y-0">
                        <FormControl>
                          <Checkbox
                            checked={field.value}
                            onCheckedChange={field.onChange}
                            data-testid="checkbox-managed-identity"
                          />
                        </FormControl>
                        <div className="space-y-1 leading-none">
                          <FormLabel>Use Managed Identity</FormLabel>
                          <FormDescription>
                            Use Azure Managed Identity for authentication (recommended for Azure workloads).
                          </FormDescription>
                        </div>
                      </FormItem>
                    )}
                  />
                </>
              )}

              {selectedProvider === "gcp_kms" && (
                <>
                  <FormField
                    control={form.control}
                    name="projectId"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Project ID</FormLabel>
                        <FormControl>
                          <Input placeholder="my-gcp-project" {...field} data-testid="input-project-id" />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="keyRingId"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Key Ring ID</FormLabel>
                        <FormControl>
                          <Input placeholder="my-key-ring" {...field} data-testid="input-key-ring" />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="location"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Location</FormLabel>
                        <FormControl>
                          <Input placeholder="global" {...field} data-testid="input-location" />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="serviceAccountKey"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Service Account Key (JSON)</FormLabel>
                        <FormControl>
                          <Textarea 
                            placeholder="Paste your service account key JSON here..."
                            className="font-mono text-sm"
                            rows={4}
                            {...field} 
                            data-testid="input-service-account"
                          />
                        </FormControl>
                        <FormDescription>
                          Leave empty to use default application credentials.
                        </FormDescription>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="useWorkloadIdentity"
                    render={({ field }) => (
                      <FormItem className="flex flex-row items-start space-x-3 space-y-0">
                        <FormControl>
                          <Checkbox
                            checked={field.value}
                            onCheckedChange={field.onChange}
                            data-testid="checkbox-workload-identity"
                          />
                        </FormControl>
                        <div className="space-y-1 leading-none">
                          <FormLabel>Use Workload Identity</FormLabel>
                          <FormDescription>
                            Use GKE Workload Identity for authentication (recommended for GKE workloads).
                          </FormDescription>
                        </div>
                      </FormItem>
                    )}
                  />
                </>
              )}
            </CardContent>
          </Card>

          {/* Test Connection */}
          <Card>
            <CardHeader>
              <CardTitle>Connection Test</CardTitle>
              <CardDescription>
                Test the connection to ensure your configuration is correct before saving.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center space-x-4">
                <Button
                  type="button"
                  variant="outline"
                  onClick={handleTestConnection}
                  disabled={testConnectionMutation.isPending}
                  data-testid="button-test-connection"
                >
                  {testConnectionMutation.isPending ? (
                    <Loader className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <TestTube className="w-4 h-4 mr-2" />
                  )}
                  Test Connection
                </Button>

                {testResult && (
                  <div className={`flex items-center space-x-2 ${
                    testResult.success ? 'text-green-600' : 'text-red-600'
                  }`}>
                    {testResult.success ? (
                      <CheckCircle className="w-4 h-4" />
                    ) : (
                      <AlertCircle className="w-4 h-4" />
                    )}
                    <span className="text-sm">{testResult.message}</span>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Submit */}
          <div className="flex items-center justify-end space-x-4">
            <Button
              type="submit"
              disabled={createProviderMutation.isPending}
              data-testid="button-save-provider"
            >
              {createProviderMutation.isPending ? (
                <Loader className="w-4 h-4 mr-2 animate-spin" />
              ) : null}
              Save Provider Configuration
            </Button>
          </div>
        </form>
      </Form>
    </div>
  );
}