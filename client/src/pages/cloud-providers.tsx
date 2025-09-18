import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Plus, Cloud, Shield, AlertCircle, CheckCircle, Settings, Eye, Trash2, MoreHorizontal } from "lucide-react";
import { Database, Lock, Shield as CloudShield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { queryClient, apiRequest } from "@/lib/queryClient";

// Provider configuration component
import ProviderConfigForm from "@/components/ProviderConfigForm";

interface CloudProvider {
  id: string;
  name: string;
  provider: "aws_kms" | "azure_key_vault" | "gcp_kms";
  region: string;
  status: "connected" | "disconnected" | "error";
  lastHealthCheck: string;
  keysManaged: number;
  createdAt: string;
  description?: string;
}

const providerIcons = {
  aws_kms: Database,
  azure_key_vault: Lock, 
  gcp_kms: CloudShield
};

const providerNames = {
  aws_kms: "AWS KMS",
  azure_key_vault: "Azure Key Vault",
  gcp_kms: "Google Cloud KMS"
};

export default function CloudProviders() {
  const [isConfigDialogOpen, setIsConfigDialogOpen] = useState(false);
  const [selectedProvider, setSelectedProvider] = useState<CloudProvider | null>(null);
  const [activeTab, setActiveTab] = useState("overview");
  const { toast } = useToast();

  // Fetch cloud providers
  const { data: providers = [], isLoading, error } = useQuery<CloudProvider[]>({
    queryKey: ["/api/cloud-providers"],
  });

  // Delete provider mutation
  const deleteProviderMutation = useMutation({
    mutationFn: async (providerId: string) => {
      const response = await apiRequest("DELETE", `/api/cloud-providers/${providerId}`);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/cloud-providers"] });
      toast({
        title: "Provider Deleted",
        description: "Cloud provider configuration has been removed successfully.",
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Delete Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  // Test connection mutation
  const testConnectionMutation = useMutation({
    mutationFn: async (providerId: string) => {
      const response = await apiRequest("POST", `/api/cloud-providers/${providerId}/test`);
      return response.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/cloud-providers"] });
      toast({
        title: "Connection Test",
        description: data.success ? "Connection successful!" : "Connection failed",
        variant: data.success ? "default" : "destructive",
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Test Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const getStatusColor = (status: string) => {
    switch (status) {
      case "connected": return "text-green-600 bg-green-50 border-green-200";
      case "disconnected": return "text-yellow-600 bg-yellow-50 border-yellow-200";
      case "error": return "text-red-600 bg-red-50 border-red-200";
      default: return "text-gray-600 bg-gray-50 border-gray-200";
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "connected": return <CheckCircle className="w-4 h-4" />;
      case "disconnected": return <AlertCircle className="w-4 h-4" />;
      case "error": return <AlertCircle className="w-4 h-4" />;
      default: return <AlertCircle className="w-4 h-4" />;
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="text-muted-foreground">Loading cloud providers...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="text-red-600">Failed to load cloud providers</div>
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="page-cloud-providers">
      {/* Header Actions */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <Cloud className="w-6 h-6 text-blue-600" />
            <span className="text-lg font-semibold">Multi-Cloud KMS</span>
          </div>
          <Badge variant="outline" className="text-blue-600 border-blue-200">
            {providers.length} Provider{providers.length !== 1 ? 's' : ''} Configured
          </Badge>
        </div>
        
        <Dialog open={isConfigDialogOpen} onOpenChange={setIsConfigDialogOpen}>
          <DialogTrigger asChild>
            <Button data-testid="button-add-provider">
              <Plus className="w-4 h-4 mr-2" />
              Add Provider
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Configure Cloud Provider</DialogTitle>
              <DialogDescription>
                Add a new cloud KMS provider to manage encryption keys across multiple clouds.
              </DialogDescription>
            </DialogHeader>
            <ProviderConfigForm 
              onSuccess={() => {
                setIsConfigDialogOpen(false);
                queryClient.invalidateQueries({ queryKey: ["/api/cloud-providers"] });
              }} 
            />
          </DialogContent>
        </Dialog>
      </div>

      {/* Main Content */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview" data-testid="tab-overview">Overview</TabsTrigger>
          <TabsTrigger value="health" data-testid="tab-health">Health Status</TabsTrigger>
          <TabsTrigger value="configuration" data-testid="tab-configuration">Configuration</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          {providers.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-12">
                <Cloud className="w-12 h-12 text-muted-foreground mb-4" />
                <h3 className="text-lg font-semibold mb-2">No Cloud Providers Configured</h3>
                <p className="text-muted-foreground text-center mb-4">
                  Get started by adding your first cloud KMS provider to enable multi-cloud key management.
                </p>
                <Button onClick={() => setIsConfigDialogOpen(true)} data-testid="button-get-started">
                  <Plus className="w-4 h-4 mr-2" />
                  Add Your First Provider
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {providers.map((provider) => (
                <Card key={provider.id} className="hover:shadow-md transition-shadow" data-testid={`card-provider-${provider.id}`}>
                  <CardHeader className="pb-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <div className="text-2xl text-muted-foreground">
                          {(() => {
                            const IconComponent = providerIcons[provider.provider];
                            return <IconComponent className="w-8 h-8" aria-label={providerNames[provider.provider]} />;
                          })()}
                        </div>
                        <div>
                          <CardTitle className="text-lg">{provider.name}</CardTitle>
                          <CardDescription>{providerNames[provider.provider]}</CardDescription>
                        </div>
                      </div>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="sm" data-testid={`menu-provider-${provider.id}`}>
                            <MoreHorizontal className="w-4 h-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onClick={() => testConnectionMutation.mutate(provider.id)}>
                            <Eye className="w-4 h-4 mr-2" />
                            Test Connection
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => setSelectedProvider(provider)}>
                            <Settings className="w-4 h-4 mr-2" />
                            Configure
                          </DropdownMenuItem>
                          <DropdownMenuItem 
                            onClick={() => deleteProviderMutation.mutate(provider.id)}
                            className="text-red-600"
                          >
                            <Trash2 className="w-4 h-4 mr-2" />
                            Delete
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Status</span>
                      <Badge className={getStatusColor(provider.status)}>
                        {getStatusIcon(provider.status)}
                        <span className="ml-1 capitalize">{provider.status}</span>
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Region</span>
                      <span className="text-sm font-medium">{provider.region}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Keys Managed</span>
                      <span className="text-sm font-medium">{provider.keysManaged}</span>
                    </div>
                    <div className="text-xs text-muted-foreground">
                      Last check: {new Date(provider.lastHealthCheck).toLocaleString()}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="health" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Shield className="w-5 h-5" />
                <span>Provider Health Status</span>
              </CardTitle>
              <CardDescription>
                Monitor the health and connectivity of all configured cloud providers.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {providers.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  No providers configured to monitor.
                </div>
              ) : (
                <div className="space-y-4">
                  {providers.map((provider) => (
                    <div 
                      key={provider.id} 
                      className="flex items-center justify-between p-4 border rounded-lg"
                      data-testid={`health-${provider.id}`}
                    >
                      <div className="flex items-center space-x-4">
                        <div className="text-xl text-muted-foreground">
                          {(() => {
                            const IconComponent = providerIcons[provider.provider];
                            return <IconComponent className="w-6 h-6" aria-label={providerNames[provider.provider]} />;
                          })()}
                        </div>
                        <div>
                          <div className="font-medium">{provider.name}</div>
                          <div className="text-sm text-muted-foreground">
                            {providerNames[provider.provider]} • {provider.region}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center space-x-4">
                        <Badge className={getStatusColor(provider.status)}>
                          {getStatusIcon(provider.status)}
                          <span className="ml-1 capitalize">{provider.status}</span>
                        </Badge>
                        <Button 
                          variant="outline" 
                          size="sm"
                          onClick={() => testConnectionMutation.mutate(provider.id)}
                          disabled={testConnectionMutation.isPending}
                          data-testid={`test-${provider.id}`}
                        >
                          Test Connection
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="configuration" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Provider Configuration</CardTitle>
              <CardDescription>
                Manage authentication, regions, and security settings for your cloud providers.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {providers.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  No providers configured.
                </div>
              ) : (
                <div className="space-y-6">
                  {providers.map((provider) => (
                    <div 
                      key={provider.id} 
                      className="border rounded-lg p-6"
                      data-testid={`config-${provider.id}`}
                    >
                      <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center space-x-3">
                          <div className="text-xl text-muted-foreground">
                          {(() => {
                            const IconComponent = providerIcons[provider.provider];
                            return <IconComponent className="w-6 h-6" aria-label={providerNames[provider.provider]} />;
                          })()}
                        </div>
                          <div>
                            <h3 className="font-semibold">{provider.name}</h3>
                            <p className="text-sm text-muted-foreground">
                              {providerNames[provider.provider]}
                            </p>
                          </div>
                        </div>
                        <Button variant="outline" size="sm">
                          <Settings className="w-4 h-4 mr-2" />
                          Edit Configuration
                        </Button>
                      </div>
                      <div className="grid grid-cols-2 gap-4 text-sm">
                        <div>
                          <span className="text-muted-foreground">Region:</span>
                          <span className="ml-2 font-medium">{provider.region}</span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Created:</span>
                          <span className="ml-2 font-medium">
                            {new Date(provider.createdAt).toLocaleDateString()}
                          </span>
                        </div>
                        {provider.description && (
                          <div className="col-span-2">
                            <span className="text-muted-foreground">Description:</span>
                            <span className="ml-2">{provider.description}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}