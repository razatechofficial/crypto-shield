import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { GitBranch, RefreshCw, CheckCircle, AlertTriangle, Loader, Eye, Settings } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { queryClient, apiRequest } from "@/lib/queryClient";

interface KeyDistribution {
  id: string;
  keyId: string;
  providerConfigId: string;
  providerKeyId: string;
  distributionStatus: "synced" | "pending" | "failed" | "out_of_sync";
  lastSyncAt: string;
  syncError?: string;
  metadata: {
    keyName: string;
    providerName: string;
    providerType: string;
    region: string;
  };
}

interface KeyReplication {
  id: string;
  sourceKeyId: string;
  targetProviderConfigId: string;
  targetKeyId: string;
  replicationStatus: "active" | "failed" | "pending";
  lastReplicationAt: string;
  replicationError?: string;
  metadata: {
    sourceProvider: string;
    targetProvider: string;
    sourceRegion: string;
    targetRegion: string;
  };
}

const statusColors = {
  synced: "text-green-600 bg-green-50 border-green-200",
  pending: "text-yellow-600 bg-yellow-50 border-yellow-200", 
  failed: "text-red-600 bg-red-50 border-red-200",
  out_of_sync: "text-orange-600 bg-orange-50 border-orange-200",
  active: "text-green-600 bg-green-50 border-green-200"
};

const statusIcons = {
  synced: <CheckCircle className="w-4 h-4" />,
  pending: <Loader className="w-4 h-4 animate-spin" />,
  failed: <AlertTriangle className="w-4 h-4" />,
  out_of_sync: <AlertTriangle className="w-4 h-4" />,
  active: <CheckCircle className="w-4 h-4" />
};

export default function KeyDistribution() {
  const [activeTab, setActiveTab] = useState("distributions");
  const { toast } = useToast();

  // Fetch key distributions
  const { data: distributions = [], isLoading: distributionsLoading } = useQuery<KeyDistribution[]>({
    queryKey: ["/api/key-distributions"],
  });

  // Fetch key replications
  const { data: replications = [], isLoading: replicationsLoading } = useQuery<KeyReplication[]>({
    queryKey: ["/api/key-replications"],
  });

  // Sync mutation
  const syncMutation = useMutation({
    mutationFn: async (distributionId: string) => {
      const response = await apiRequest("POST", `/api/key-distributions/${distributionId}/sync`);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/key-distributions"] });
      toast({
        title: "Sync Initiated",
        description: "Key synchronization has been started.",
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Sync Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  // Sync all mutation
  const syncAllMutation = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("POST", "/api/key-distributions/sync-all");
      
      // Check if response is JSON before parsing
      const contentType = response.headers.get("content-type");
      if (contentType && contentType.includes("application/json")) {
        return await response.json();
      } else {
        // If not JSON, just return success indicator
        return { success: true, message: "Sync completed" };
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/key-distributions"] });
      queryClient.invalidateQueries({ queryKey: ["/api/key-replications"] });
      toast({
        title: "Global Sync Initiated",
        description: "All key distributions are being synchronized.",
      });
    },
    onError: (error: any) => {
      console.error("Sync error:", error);
      toast({
        title: "Global Sync Failed", 
        description: error?.message || "Failed to sync all distributions. Please try again.",
        variant: "destructive",
      });
    },
  });

  const isLoading = distributionsLoading || replicationsLoading;

  if (isLoading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="text-muted-foreground">Loading key distributions...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="page-key-distribution">
      {/* Header Actions */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <GitBranch className="w-6 h-6 text-blue-600" />
            <span className="text-lg font-semibold">Multi-Cloud Key Distribution</span>
          </div>
          <Badge variant="outline" className="text-blue-600 border-blue-200">
            {distributions.length} Distribution{distributions.length !== 1 ? 's' : ''}
          </Badge>
        </div>
        
        <Button 
          onClick={() => syncAllMutation.mutate()}
          disabled={syncAllMutation.isPending}
          data-testid="button-sync-all"
        >
          <RefreshCw className={`w-4 h-4 mr-2 ${syncAllMutation.isPending ? 'animate-spin' : ''}`} />
          Sync All
        </Button>
      </div>

      {/* Main Content */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="distributions" data-testid="tab-distributions">Key Distributions</TabsTrigger>
          <TabsTrigger value="replications" data-testid="tab-replications">Cross-Region Replications</TabsTrigger>
          <TabsTrigger value="analytics" data-testid="tab-analytics">Sync Analytics</TabsTrigger>
        </TabsList>

        <TabsContent value="distributions" className="space-y-6">
          {distributions.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-12">
                <GitBranch className="w-12 h-12 text-muted-foreground mb-4" />
                <h3 className="text-lg font-semibold mb-2">No Key Distributions Found</h3>
                <p className="text-muted-foreground text-center mb-4">
                  Key distributions will appear here once you configure cloud providers and distribute keys across them.
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              {distributions.map((distribution) => (
                <Card key={distribution.id} data-testid={`distribution-${distribution.id}`}>
                  <CardHeader className="pb-3">
                    <div className="flex items-center justify-between">
                      <div>
                        <CardTitle className="text-lg">{distribution.metadata.keyName}</CardTitle>
                        <CardDescription>
                          Distributed to {distribution.metadata.providerName} ({distribution.metadata.region})
                        </CardDescription>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Badge className={statusColors[distribution.distributionStatus]}>
                          {statusIcons[distribution.distributionStatus]}
                          <span className="ml-1 capitalize">{distribution.distributionStatus.replace('_', ' ')}</span>
                        </Badge>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => syncMutation.mutate(distribution.id)}
                          disabled={syncMutation.isPending}
                          data-testid={`sync-${distribution.id}`}
                        >
                          <RefreshCw className={`w-4 h-4 ${syncMutation.isPending ? 'animate-spin' : ''}`} />
                        </Button>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                      <div>
                        <span className="text-muted-foreground block">Key ID</span>
                        <span className="font-mono text-xs">{distribution.keyId}</span>
                      </div>
                      <div>
                        <span className="text-muted-foreground block">Provider Key ID</span>
                        <span className="font-mono text-xs">{distribution.providerKeyId}</span>
                      </div>
                      <div>
                        <span className="text-muted-foreground block">Provider Type</span>
                        <span className="capitalize">{distribution.metadata.providerType.replace('_', ' ')}</span>
                      </div>
                      <div>
                        <span className="text-muted-foreground block">Last Sync</span>
                        <span>{new Date(distribution.lastSyncAt).toLocaleString()}</span>
                      </div>
                    </div>
                    
                    {distribution.syncError && (
                      <div className="p-3 bg-red-50 border border-red-200 rounded-lg">
                        <div className="flex items-center space-x-2 text-red-600 text-sm">
                          <AlertTriangle className="w-4 h-4" />
                          <span className="font-medium">Sync Error:</span>
                        </div>
                        <p className="text-red-700 text-sm mt-1">{distribution.syncError}</p>
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="replications" className="space-y-6">
          {replications.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-12">
                <GitBranch className="w-12 h-12 text-muted-foreground mb-4" />
                <h3 className="text-lg font-semibold mb-2">No Cross-Region Replications</h3>
                <p className="text-muted-foreground text-center mb-4">
                  Cross-region key replications will appear here when configured for high availability.
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              {replications.map((replication) => (
                <Card key={replication.id} data-testid={`replication-${replication.id}`}>
                  <CardHeader className="pb-3">
                    <div className="flex items-center justify-between">
                      <div>
                        <CardTitle className="text-lg">
                          {replication.metadata.sourceProvider} → {replication.metadata.targetProvider}
                        </CardTitle>
                        <CardDescription>
                          {replication.metadata.sourceRegion} to {replication.metadata.targetRegion}
                        </CardDescription>
                      </div>
                      <Badge className={statusColors[replication.replicationStatus]}>
                        {statusIcons[replication.replicationStatus]}
                        <span className="ml-1 capitalize">{replication.replicationStatus}</span>
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm">
                      <div>
                        <span className="text-muted-foreground block">Source Key</span>
                        <span className="font-mono text-xs">{replication.sourceKeyId}</span>
                      </div>
                      <div>
                        <span className="text-muted-foreground block">Target Key</span>
                        <span className="font-mono text-xs">{replication.targetKeyId}</span>
                      </div>
                      <div>
                        <span className="text-muted-foreground block">Last Replication</span>
                        <span>{new Date(replication.lastReplicationAt).toLocaleString()}</span>
                      </div>
                    </div>
                    
                    {replication.replicationError && (
                      <div className="p-3 bg-red-50 border border-red-200 rounded-lg">
                        <div className="flex items-center space-x-2 text-red-600 text-sm">
                          <AlertTriangle className="w-4 h-4" />
                          <span className="font-medium">Replication Error:</span>
                        </div>
                        <p className="text-red-700 text-sm mt-1">{replication.replicationError}</p>
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="analytics" className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-lg">Distribution Status</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {Object.entries(
                    distributions.reduce((acc, dist) => {
                      acc[dist.distributionStatus] = (acc[dist.distributionStatus] || 0) + 1;
                      return acc;
                    }, {} as Record<string, number>)
                  ).map(([status, count]) => (
                    <div key={status} className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        {statusIcons[status as keyof typeof statusIcons]}
                        <span className="capitalize text-sm">{status.replace('_', ' ')}</span>
                      </div>
                      <span className="font-medium">{count}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-lg">Provider Distribution</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {Object.entries(
                    distributions.reduce((acc, dist) => {
                      acc[dist.metadata.providerType] = (acc[dist.metadata.providerType] || 0) + 1;
                      return acc;
                    }, {} as Record<string, number>)
                  ).map(([provider, count]) => (
                    <div key={provider} className="flex items-center justify-between">
                      <span className="capitalize text-sm">{provider.replace('_', ' ')}</span>
                      <span className="font-medium">{count}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-lg">Replication Health</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {Object.entries(
                    replications.reduce((acc, rep) => {
                      acc[rep.replicationStatus] = (acc[rep.replicationStatus] || 0) + 1;
                      return acc;
                    }, {} as Record<string, number>)
                  ).map(([status, count]) => (
                    <div key={status} className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        {statusIcons[status as keyof typeof statusIcons]}
                        <span className="capitalize text-sm">{status}</span>
                      </div>
                      <span className="font-medium">{count}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}