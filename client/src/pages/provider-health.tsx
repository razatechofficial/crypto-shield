import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useToast } from "@/hooks/use-toast";
import { queryClient } from "@/lib/queryClient";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { 
  Activity, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  Database, 
  Lock, 
  Shield as CloudShield,
  TrendingUp,
  TrendingDown,
  Zap,
  Globe,
  Server,
  Timer,
  AlertCircle
} from "lucide-react";

interface ProviderHealthMetrics {
  id: string;
  name: string;
  provider: "aws_kms" | "azure_key_vault" | "gcp_kms";
  status: "healthy" | "degraded" | "critical" | "unknown";
  region: string;
  uptime: number;
  responseTime: number;
  operationsPerMinute: number;
  errorRate: number;
  lastHealthCheck: string;
  keyCount: number;
  encryptionOps: number;
  decryptionOps: number;
  keyRotations: number;
  alerts: Array<{
    id: string;
    type: "warning" | "error" | "info";
    message: string;
    timestamp: string;
  }>;
  resources: {
    cpu: number;
    memory: number;
    network: number;
  };
}

interface HealthSummary {
  totalProviders: number;
  healthyProviders: number;
  degradedProviders: number;
  criticalProviders: number;
  averageResponseTime: number;
  totalOperations: number;
  averageErrorRate: number;
}

export default function ProviderHealthPage() {
  const { toast } = useToast();

  // Fetch provider health metrics
  const { data: healthMetrics = [], isLoading: healthLoading } = useQuery<ProviderHealthMetrics[]>({
    queryKey: ["/api/provider-health/metrics"],
  });

  // Fetch health summary
  const { data: summary, isLoading: summaryLoading } = useQuery<HealthSummary>({
    queryKey: ["/api/provider-health/summary"],
  });

  const getProviderIcon = (provider: string) => {
    switch (provider) {
      case "aws_kms":
        return <Database className="w-5 h-5" aria-label="AWS KMS" />;
      case "azure_key_vault":
        return <Lock className="w-5 h-5" aria-label="Azure Key Vault" />;
      case "gcp_kms":
        return <CloudShield className="w-5 h-5" aria-label="Google Cloud KMS" />;
      default:
        return <Server className="w-5 h-5" />;
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "healthy":
        return <CheckCircle className="w-4 h-4 text-green-500" />;
      case "degraded":
        return <AlertTriangle className="w-4 h-4 text-yellow-500" />;
      case "critical":
        return <AlertCircle className="w-4 h-4 text-red-500" />;
      default:
        return <Clock className="w-4 h-4 text-gray-500" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "healthy":
        return "bg-green-500";
      case "degraded":
        return "bg-yellow-500";
      case "critical":
        return "bg-red-500";
      default:
        return "bg-gray-500";
    }
  };

  if (healthLoading || summaryLoading) {
    return (
      <div className="p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold">Provider Health Dashboard</h1>
            <p className="text-muted-foreground">Monitor cloud provider performance and health metrics</p>
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <Card key={i} className="animate-pulse">
              <CardHeader className="pb-2">
                <div className="w-4 h-4 bg-muted rounded" />
              </CardHeader>
              <CardContent>
                <div className="w-16 h-8 bg-muted rounded mb-1" />
                <div className="w-20 h-4 bg-muted rounded" />
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6" data-testid="provider-health-page">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Provider Health Dashboard</h1>
          <p className="text-muted-foreground">Real-time monitoring of cloud provider performance and reliability</p>
        </div>
        <Button 
          className="gap-2" 
          data-testid="button-refresh-metrics"
          onClick={() => {
            queryClient.invalidateQueries({ queryKey: ["/api/provider-health/metrics"] });
            queryClient.invalidateQueries({ queryKey: ["/api/provider-health/summary"] });
            toast({
              title: "Metrics Refreshed",
              description: "Provider health data has been updated.",
            });
          }}
        >
          <Activity className="w-4 h-4" />
          Refresh Metrics
        </Button>
      </div>

      {/* Health Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card data-testid="card-total-providers">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Providers</CardTitle>
            <Server className="w-4 h-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-total-providers">
              {summary?.totalProviders || 0}
            </div>
            <p className="text-xs text-muted-foreground">
              Multi-cloud infrastructure
            </p>
          </CardContent>
        </Card>

        <Card data-testid="card-healthy-providers">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Healthy Providers</CardTitle>
            <CheckCircle className="w-4 h-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600" data-testid="text-healthy-providers">
              {summary?.healthyProviders || 0}
            </div>
            <p className="text-xs text-muted-foreground">
              Operating normally
            </p>
          </CardContent>
        </Card>

        <Card data-testid="card-response-time">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Avg Response Time</CardTitle>
            <Timer className="w-4 h-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-response-time">
              {summary?.averageResponseTime || 0}ms
            </div>
            <p className="text-xs text-muted-foreground">
              Cross-provider average
            </p>
          </CardContent>
        </Card>

        <Card data-testid="card-error-rate">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Error Rate</CardTitle>
            <AlertTriangle className="w-4 h-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-error-rate">
              {(summary?.averageErrorRate || 0).toFixed(2)}%
            </div>
            <p className="text-xs text-muted-foreground">
              24-hour average
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Provider Health Details */}
      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList data-testid="tabs-health-dashboard">
          <TabsTrigger value="overview" data-testid="tab-overview">Overview</TabsTrigger>
          <TabsTrigger value="performance" data-testid="tab-performance">Performance</TabsTrigger>
          <TabsTrigger value="alerts" data-testid="tab-alerts">Alerts</TabsTrigger>
          <TabsTrigger value="resources" data-testid="tab-resources">Resources</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {healthMetrics.map((provider) => (
              <Card key={provider.id} data-testid={`card-provider-${provider.id}`}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      {getProviderIcon(provider.provider)}
                      <div>
                        <CardTitle className="text-lg">{provider.name}</CardTitle>
                        <CardDescription>{provider.region}</CardDescription>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {getStatusIcon(provider.status)}
                      <Badge 
                        variant="secondary" 
                        className={`${getStatusColor(provider.status)} text-white`}
                        data-testid={`badge-status-${provider.id}`}
                      >
                        {provider.status}
                      </Badge>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <p className="text-muted-foreground">Uptime</p>
                      <p className="font-medium" data-testid={`text-uptime-${provider.id}`}>
                        {provider.uptime.toFixed(2)}%
                      </p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Response Time</p>
                      <p className="font-medium" data-testid={`text-response-${provider.id}`}>
                        {provider.responseTime}ms
                      </p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Operations/min</p>
                      <p className="font-medium" data-testid={`text-operations-${provider.id}`}>
                        {provider.operationsPerMinute.toLocaleString()}
                      </p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Error Rate</p>
                      <p className="font-medium" data-testid={`text-errors-${provider.id}`}>
                        {provider.errorRate.toFixed(2)}%
                      </p>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="flex justify-between items-center text-sm">
                      <span>Health Score</span>
                      <span className="font-medium">
                        {Math.max(0, 100 - provider.errorRate - (100 - provider.uptime)).toFixed(0)}/100
                      </span>
                    </div>
                    <Progress 
                      value={Math.max(0, 100 - provider.errorRate - (100 - provider.uptime))} 
                      className="h-2" 
                    />
                  </div>

                  {provider.alerts.length > 0 && (
                    <Alert>
                      <AlertTriangle className="w-4 h-4" />
                      <AlertDescription>
                        {provider.alerts.length} active alert{provider.alerts.length > 1 ? 's' : ''}
                      </AlertDescription>
                    </Alert>
                  )}

                  <div className="text-xs text-muted-foreground">
                    Last checked: {new Date(provider.lastHealthCheck).toLocaleString()}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="performance" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {healthMetrics.map((provider) => (
              <Card key={`perf-${provider.id}`} data-testid={`card-performance-${provider.id}`}>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    {getProviderIcon(provider.provider)}
                    {provider.name}
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Keys Managed</span>
                      <span className="font-medium" data-testid={`text-keys-${provider.id}`}>
                        {provider.keyCount.toLocaleString()}
                      </span>
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <span className="text-sm flex items-center gap-1">
                        <Lock className="w-3 h-3" />
                        Encryptions
                      </span>
                      <span className="font-medium text-green-600" data-testid={`text-encryptions-${provider.id}`}>
                        {provider.encryptionOps.toLocaleString()}
                      </span>
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <span className="text-sm flex items-center gap-1">
                        <Lock className="w-3 h-3 rotate-180" />
                        Decryptions
                      </span>
                      <span className="font-medium text-blue-600" data-testid={`text-decryptions-${provider.id}`}>
                        {provider.decryptionOps.toLocaleString()}
                      </span>
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <span className="text-sm flex items-center gap-1">
                        <Activity className="w-3 h-3" />
                        Key Rotations
                      </span>
                      <span className="font-medium" data-testid={`text-rotations-${provider.id}`}>
                        {provider.keyRotations}
                      </span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="alerts" className="space-y-4">
          <div className="space-y-4">
            {healthMetrics.flatMap(provider => 
              provider.alerts.map(alert => (
                <Alert key={alert.id} data-testid={`alert-${alert.id}`}>
                  <AlertTriangle className="w-4 h-4" />
                  <AlertDescription>
                    <div className="flex items-center justify-between">
                      <div>
                        <strong>{provider.name}:</strong> {alert.message}
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {new Date(alert.timestamp).toLocaleString()}
                      </div>
                    </div>
                  </AlertDescription>
                </Alert>
              ))
            )}
            {healthMetrics.every(provider => provider.alerts.length === 0) && (
              <Card data-testid="card-no-alerts">
                <CardContent className="pt-6">
                  <div className="text-center">
                    <CheckCircle className="w-12 h-12 text-green-500 mx-auto mb-4" />
                    <h3 className="text-lg font-semibold mb-2">All Systems Operational</h3>
                    <p className="text-muted-foreground">No active alerts across all cloud providers</p>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        </TabsContent>

        <TabsContent value="resources" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {healthMetrics.map((provider) => (
              <Card key={`resource-${provider.id}`} data-testid={`card-resources-${provider.id}`}>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    {getProviderIcon(provider.provider)}
                    {provider.name} Resources
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-3">
                    <div>
                      <div className="flex justify-between mb-2">
                        <span className="text-sm">CPU Usage</span>
                        <span className="text-sm font-medium">
                          {provider.resources.cpu}%
                        </span>
                      </div>
                      <Progress value={provider.resources.cpu} className="h-2" />
                    </div>
                    
                    <div>
                      <div className="flex justify-between mb-2">
                        <span className="text-sm">Memory Usage</span>
                        <span className="text-sm font-medium">
                          {provider.resources.memory}%
                        </span>
                      </div>
                      <Progress value={provider.resources.memory} className="h-2" />
                    </div>
                    
                    <div>
                      <div className="flex justify-between mb-2">
                        <span className="text-sm">Network I/O</span>
                        <span className="text-sm font-medium">
                          {provider.resources.network}%
                        </span>
                      </div>
                      <Progress value={provider.resources.network} className="h-2" />
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}