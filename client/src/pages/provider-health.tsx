import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useToast } from "@/hooks/use-toast";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
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
  AlertCircle,
  Settings,
  Plus,
  Bell,
  Monitor,
  Loader
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

// Health monitoring configuration schema
const healthConfigSchema = z.object({
  providerIds: z.array(z.string()).min(1, "Select at least one provider"),
  checkInterval: z.enum(["30s", "1m", "5m", "15m", "1h"]),
  alertThresholds: z.object({
    responseTimeMs: z.number().min(1).max(30000),
    errorRatePercent: z.number().min(0.1).max(100),
    uptimePercent: z.number().min(50).max(99.9),
  }),
  notifications: z.object({
    email: z.boolean().default(true),
    slack: z.boolean().default(false),
    webhook: z.boolean().default(false),
    webhookUrl: z.string().url().optional(),
  }),
  autoRemediation: z.boolean().default(false),
  escalationPolicy: z.enum(["immediate", "after_5min", "after_15min", "manual"]),
  monitoringScope: z.enum(["basic", "detailed", "comprehensive"]),
  retentionDays: z.number().min(7).max(365).default(30),
  customChecks: z.array(z.object({
    name: z.string().min(1),
    endpoint: z.string().url(),
    method: z.enum(["GET", "POST", "PUT"]),
    expectedStatus: z.number().default(200),
  })).default([]),
});

// Alert rule schema
const alertRuleSchema = z.object({
  name: z.string().min(1, "Alert name is required"),
  description: z.string().optional(),
  condition: z.enum(["response_time", "error_rate", "uptime", "custom"]),
  operator: z.enum(["greater_than", "less_than", "equals", "not_equals"]),
  threshold: z.number().min(0),
  severity: z.enum(["low", "medium", "high", "critical"]),
  enabled: z.boolean().default(true),
  providers: z.array(z.string()).min(1, "Select at least one provider"),
  notificationChannels: z.array(z.string()).default([]),
  cooldownMinutes: z.number().min(1).max(1440).default(15),
});

type HealthConfigData = z.infer<typeof healthConfigSchema>;
type AlertRuleData = z.infer<typeof alertRuleSchema>;

export default function ProviderHealthPage() {
  const [isHealthConfigOpen, setIsHealthConfigOpen] = useState(false);
  const [isAlertRuleOpen, setIsAlertRuleOpen] = useState(false);
  const { toast } = useToast();

  // Forms for configuration
  const healthForm = useForm<HealthConfigData>({
    resolver: zodResolver(healthConfigSchema),
    defaultValues: {
      checkInterval: "5m",
      alertThresholds: {
        responseTimeMs: 5000,
        errorRatePercent: 5.0,
        uptimePercent: 99.5,
      },
      notifications: {
        email: true,
        slack: false,
        webhook: false,
      },
      autoRemediation: false,
      escalationPolicy: "after_5min",
      monitoringScope: "detailed",
      retentionDays: 30,
      customChecks: [],
    },
  });

  const alertForm = useForm<AlertRuleData>({
    resolver: zodResolver(alertRuleSchema),
    defaultValues: {
      condition: "response_time",
      operator: "greater_than",
      threshold: 1000,
      severity: "medium",
      enabled: true,
      providers: [],
      notificationChannels: [],
      cooldownMinutes: 15,
    },
  });

  // Fetch provider health metrics
  const { data: healthMetrics = [], isLoading: healthLoading } = useQuery<ProviderHealthMetrics[]>({
    queryKey: ["/api/provider-health/metrics"],
  });

  // Fetch health summary
  const { data: summary, isLoading: summaryLoading } = useQuery<HealthSummary>({
    queryKey: ["/api/provider-health/summary"],
  });

  // Fetch cloud providers for configuration
  const { data: cloudProviders = [] } = useQuery<any[]>({
    queryKey: ["/api/cloud-providers"],
  });

  // Health configuration mutation
  const configureHealthMutation = useMutation({
    mutationFn: async (data: HealthConfigData) => {
      const response = await apiRequest("POST", "/api/provider-health/configure", data);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/provider-health/metrics"] });
      setIsHealthConfigOpen(false);
      healthForm.reset();
      toast({
        title: "Health Monitoring Configured",
        description: "Provider health monitoring settings have been updated successfully.",
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Configuration Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  // Alert rule mutation
  const createAlertMutation = useMutation({
    mutationFn: async (data: AlertRuleData) => {
      const response = await apiRequest("POST", "/api/provider-health/alerts", data);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/provider-health/metrics"] });
      setIsAlertRuleOpen(false);
      alertForm.reset();
      toast({
        title: "Alert Rule Created",
        description: "Health monitoring alert rule has been configured successfully.",
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Alert Creation Failed",
        description: error.message,
        variant: "destructive",
      });
    },
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
        
        <div className="flex items-center space-x-2">
          {/* Health Configuration Dialog */}
          <Dialog open={isHealthConfigOpen} onOpenChange={setIsHealthConfigOpen}>
            <DialogTrigger asChild>
              <Button variant="outline" data-testid="button-configure-health">
                <Settings className="w-4 h-4 mr-2" />
                Configure Monitoring
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
              <DialogHeader>
                <DialogTitle>Configure Health Monitoring</DialogTitle>
                <DialogDescription>
                  Set up advanced health monitoring, thresholds, and alerting for your cloud providers.
                </DialogDescription>
              </DialogHeader>
              
              <Form {...healthForm}>
                <form onSubmit={healthForm.handleSubmit((data) => configureHealthMutation.mutate(data))} className="space-y-6">
                  <div className="grid grid-cols-2 gap-6">
                    <FormField
                      control={healthForm.control}
                      name="providerIds"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Select Providers</FormLabel>
                          <FormDescription>Choose which providers to monitor</FormDescription>
                          <div className="space-y-2">
                            {cloudProviders.map((provider: any) => (
                              <div key={provider.id} className="flex items-center space-x-2">
                                <input
                                  type="checkbox"
                                  id={provider.id}
                                  checked={field.value.includes(provider.id)}
                                  onChange={(e) => {
                                    if (e.target.checked) {
                                      field.onChange([...field.value, provider.id]);
                                    } else {
                                      field.onChange(field.value.filter(id => id !== provider.id));
                                    }
                                  }}
                                  data-testid={`checkbox-provider-${provider.id}`}
                                />
                                <label htmlFor={provider.id} className="text-sm">
                                  {provider.name} ({provider.providerType})
                                </label>
                              </div>
                            ))}
                          </div>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <FormField
                      control={healthForm.control}
                      name="checkInterval"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Check Interval</FormLabel>
                          <Select onValueChange={field.onChange} defaultValue={field.value}>
                            <FormControl>
                              <SelectTrigger data-testid="select-check-interval">
                                <SelectValue />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              <SelectItem value="30s">Every 30 seconds</SelectItem>
                              <SelectItem value="1m">Every minute</SelectItem>
                              <SelectItem value="5m">Every 5 minutes</SelectItem>
                              <SelectItem value="15m">Every 15 minutes</SelectItem>
                              <SelectItem value="1h">Every hour</SelectItem>
                            </SelectContent>
                          </Select>
                          <FormDescription>How often to check provider health</FormDescription>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  </div>

                  {/* Alert Thresholds */}
                  <div className="space-y-4">
                    <h3 className="text-lg font-semibold">Alert Thresholds</h3>
                    <div className="grid grid-cols-3 gap-4">
                      <FormField
                        control={healthForm.control}
                        name="alertThresholds.responseTimeMs"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Response Time (ms)</FormLabel>
                            <FormControl>
                              <Input 
                                type="number" 
                                {...field} 
                                onChange={(e) => field.onChange(Number(e.target.value))}
                                data-testid="input-response-threshold"
                              />
                            </FormControl>
                            <FormDescription>Alert when response time exceeds</FormDescription>
                            <FormMessage />
                          </FormItem>
                        )}
                      />

                      <FormField
                        control={healthForm.control}
                        name="alertThresholds.errorRatePercent"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Error Rate (%)</FormLabel>
                            <FormControl>
                              <Input 
                                type="number" 
                                step="0.1"
                                {...field} 
                                onChange={(e) => field.onChange(Number(e.target.value))}
                                data-testid="input-error-threshold"
                              />
                            </FormControl>
                            <FormDescription>Alert when error rate exceeds</FormDescription>
                            <FormMessage />
                          </FormItem>
                        )}
                      />

                      <FormField
                        control={healthForm.control}
                        name="alertThresholds.uptimePercent"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Uptime (%)</FormLabel>
                            <FormControl>
                              <Input 
                                type="number" 
                                step="0.1"
                                {...field} 
                                onChange={(e) => field.onChange(Number(e.target.value))}
                                data-testid="input-uptime-threshold"
                              />
                            </FormControl>
                            <FormDescription>Alert when uptime falls below</FormDescription>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                    </div>
                  </div>

                  {/* Notification Settings */}
                  <div className="space-y-4">
                    <h3 className="text-lg font-semibold">Notification Settings</h3>
                    <div className="grid grid-cols-2 gap-4">
                      <FormField
                        control={healthForm.control}
                        name="notifications.email"
                        render={({ field }) => (
                          <FormItem className="flex flex-row items-center justify-between rounded-lg border p-4">
                            <div className="space-y-0.5">
                              <FormLabel className="text-base">Email Notifications</FormLabel>
                              <FormDescription>Send alerts via email</FormDescription>
                            </div>
                            <FormControl>
                              <Switch checked={field.value} onCheckedChange={field.onChange} />
                            </FormControl>
                          </FormItem>
                        )}
                      />

                      <FormField
                        control={healthForm.control}
                        name="notifications.slack"
                        render={({ field }) => (
                          <FormItem className="flex flex-row items-center justify-between rounded-lg border p-4">
                            <div className="space-y-0.5">
                              <FormLabel className="text-base">Slack Notifications</FormLabel>
                              <FormDescription>Send alerts to Slack</FormDescription>
                            </div>
                            <FormControl>
                              <Switch checked={field.value} onCheckedChange={field.onChange} />
                            </FormControl>
                          </FormItem>
                        )}
                      />

                      <FormField
                        control={healthForm.control}
                        name="notifications.webhook"
                        render={({ field }) => (
                          <FormItem className="flex flex-row items-center justify-between rounded-lg border p-4">
                            <div className="space-y-0.5">
                              <FormLabel className="text-base">Webhook Notifications</FormLabel>
                              <FormDescription>Send alerts to webhook URL</FormDescription>
                            </div>
                            <FormControl>
                              <Switch checked={field.value} onCheckedChange={field.onChange} />
                            </FormControl>
                          </FormItem>
                        )}
                      />

                      {healthForm.watch("notifications.webhook") && (
                        <FormField
                          control={healthForm.control}
                          name="notifications.webhookUrl"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Webhook URL</FormLabel>
                              <FormControl>
                                <Input {...field} placeholder="https://your-webhook-url.com" data-testid="input-webhook-url" />
                              </FormControl>
                              <FormDescription>URL to receive webhook notifications</FormDescription>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                      )}
                    </div>
                  </div>

                  {/* Advanced Settings */}
                  <div className="grid grid-cols-2 gap-4">
                    <FormField
                      control={healthForm.control}
                      name="escalationPolicy"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Escalation Policy</FormLabel>
                          <Select onValueChange={field.onChange} defaultValue={field.value}>
                            <FormControl>
                              <SelectTrigger data-testid="select-escalation">
                                <SelectValue />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              <SelectItem value="immediate">Immediate</SelectItem>
                              <SelectItem value="after_5min">After 5 minutes</SelectItem>
                              <SelectItem value="after_15min">After 15 minutes</SelectItem>
                              <SelectItem value="manual">Manual only</SelectItem>
                            </SelectContent>
                          </Select>
                          <FormDescription>When to escalate critical alerts</FormDescription>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <FormField
                      control={healthForm.control}
                      name="monitoringScope"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Monitoring Scope</FormLabel>
                          <Select onValueChange={field.onChange} defaultValue={field.value}>
                            <FormControl>
                              <SelectTrigger data-testid="select-monitoring-scope">
                                <SelectValue />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              <SelectItem value="basic">Basic (Status only)</SelectItem>
                              <SelectItem value="detailed">Detailed (+ Performance)</SelectItem>
                              <SelectItem value="comprehensive">Comprehensive (All metrics)</SelectItem>
                            </SelectContent>
                          </Select>
                          <FormDescription>Depth of monitoring</FormDescription>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  </div>

                  <div className="flex items-center justify-end space-x-2">
                    <Button 
                      type="button" 
                      variant="outline" 
                      onClick={() => setIsHealthConfigOpen(false)}
                      data-testid="button-cancel-health"
                    >
                      Cancel
                    </Button>
                    <Button 
                      type="submit" 
                      disabled={configureHealthMutation.isPending}
                      data-testid="button-save-health"
                    >
                      {configureHealthMutation.isPending && (
                        <Loader className="w-4 h-4 mr-2 animate-spin" />
                      )}
                      Save Configuration
                    </Button>
                  </div>
                </form>
              </Form>
            </DialogContent>
          </Dialog>

          {/* Alert Rule Dialog */}
          <Dialog open={isAlertRuleOpen} onOpenChange={setIsAlertRuleOpen}>
            <DialogTrigger asChild>
              <Button variant="outline" data-testid="button-create-alert">
                <Bell className="w-4 h-4 mr-2" />
                Create Alert
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-2xl">
              <DialogHeader>
                <DialogTitle>Create Alert Rule</DialogTitle>
                <DialogDescription>
                  Set up custom alert rules for specific health conditions.
                </DialogDescription>
              </DialogHeader>
              
              <Form {...alertForm}>
                <form onSubmit={alertForm.handleSubmit((data) => createAlertMutation.mutate(data))} className="space-y-6">
                  <div className="grid grid-cols-2 gap-4">
                    <FormField
                      control={alertForm.control}
                      name="name"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Alert Name</FormLabel>
                          <FormControl>
                            <Input {...field} placeholder="High response time alert" data-testid="input-alert-name" />
                          </FormControl>
                          <FormDescription>Descriptive name for this alert</FormDescription>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <FormField
                      control={alertForm.control}
                      name="severity"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Severity</FormLabel>
                          <Select onValueChange={field.onChange} defaultValue={field.value}>
                            <FormControl>
                              <SelectTrigger data-testid="select-alert-severity">
                                <SelectValue />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              <SelectItem value="low">Low</SelectItem>
                              <SelectItem value="medium">Medium</SelectItem>
                              <SelectItem value="high">High</SelectItem>
                              <SelectItem value="critical">Critical</SelectItem>
                            </SelectContent>
                          </Select>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  </div>

                  <FormField
                    control={alertForm.control}
                    name="description"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Description (Optional)</FormLabel>
                        <FormControl>
                          <Textarea {...field} placeholder="Alert description..." data-testid="textarea-alert-description" />
                        </FormControl>
                        <FormDescription>Additional details about this alert</FormDescription>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <div className="grid grid-cols-3 gap-4">
                    <FormField
                      control={alertForm.control}
                      name="condition"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Condition</FormLabel>
                          <Select onValueChange={field.onChange} defaultValue={field.value}>
                            <FormControl>
                              <SelectTrigger data-testid="select-alert-condition">
                                <SelectValue />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              <SelectItem value="response_time">Response Time</SelectItem>
                              <SelectItem value="error_rate">Error Rate</SelectItem>
                              <SelectItem value="uptime">Uptime</SelectItem>
                              <SelectItem value="custom">Custom</SelectItem>
                            </SelectContent>
                          </Select>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <FormField
                      control={alertForm.control}
                      name="operator"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Operator</FormLabel>
                          <Select onValueChange={field.onChange} defaultValue={field.value}>
                            <FormControl>
                              <SelectTrigger data-testid="select-alert-operator">
                                <SelectValue />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              <SelectItem value="greater_than">Greater than</SelectItem>
                              <SelectItem value="less_than">Less than</SelectItem>
                              <SelectItem value="equals">Equals</SelectItem>
                              <SelectItem value="not_equals">Not equals</SelectItem>
                            </SelectContent>
                          </Select>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <FormField
                      control={alertForm.control}
                      name="threshold"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Threshold</FormLabel>
                          <FormControl>
                            <Input 
                              type="number" 
                              {...field} 
                              onChange={(e) => field.onChange(Number(e.target.value))}
                              data-testid="input-alert-threshold"
                            />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  </div>

                  <FormField
                    control={alertForm.control}
                    name="providers"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Apply to Providers</FormLabel>
                        <FormDescription>Select which providers this alert should monitor</FormDescription>
                        <div className="space-y-2">
                          {cloudProviders.map((provider: any) => (
                            <div key={provider.id} className="flex items-center space-x-2">
                              <input
                                type="checkbox"
                                id={`alert-${provider.id}`}
                                checked={field.value.includes(provider.id)}
                                onChange={(e) => {
                                  if (e.target.checked) {
                                    field.onChange([...field.value, provider.id]);
                                  } else {
                                    field.onChange(field.value.filter(id => id !== provider.id));
                                  }
                                }}
                                data-testid={`checkbox-alert-provider-${provider.id}`}
                              />
                              <label htmlFor={`alert-${provider.id}`} className="text-sm">
                                {provider.name} ({provider.providerType})
                              </label>
                            </div>
                          ))}
                        </div>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={alertForm.control}
                    name="cooldownMinutes"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Cooldown Period (minutes)</FormLabel>
                        <FormControl>
                          <Input 
                            type="number" 
                            {...field} 
                            onChange={(e) => field.onChange(Number(e.target.value))}
                            data-testid="input-alert-cooldown"
                          />
                        </FormControl>
                        <FormDescription>Wait time before re-triggering the same alert</FormDescription>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <div className="flex items-center justify-end space-x-2">
                    <Button 
                      type="button" 
                      variant="outline" 
                      onClick={() => setIsAlertRuleOpen(false)}
                      data-testid="button-cancel-alert"
                    >
                      Cancel
                    </Button>
                    <Button 
                      type="submit" 
                      disabled={createAlertMutation.isPending}
                      data-testid="button-save-alert"
                    >
                      {createAlertMutation.isPending && (
                        <Loader className="w-4 h-4 mr-2 animate-spin" />
                      )}
                      Create Alert Rule
                    </Button>
                  </div>
                </form>
              </Form>
            </DialogContent>
          </Dialog>

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