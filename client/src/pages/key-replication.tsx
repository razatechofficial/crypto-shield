import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery } from "@tanstack/react-query";
import { z } from "zod";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import {
  Globe,
  ArrowRightLeft,
  MapPin,
  Clock,
  CheckCircle,
  AlertTriangle,
  Settings,
  Play,
  Pause,
  RotateCcw,
  Plus,
  Trash2,
  Eye,
  Activity,
  Zap,
  Shield,
  Database,
  Lock
} from "lucide-react";

// Replication Policy Schema
const replicationPolicySchema = z.object({
  name: z.string().min(1, "Policy name is required").max(128, "Policy name too long"),
  keyId: z.string().min(1, "Key selection is required"),
  sourceRegion: z.string().min(1, "Source region is required"),
  targetRegions: z.array(z.string()).min(1, "At least one target region is required"),
  replicationMode: z.enum(["synchronous", "asynchronous"], {
    required_error: "Replication mode is required"
  }),
  schedule: z.enum(["real-time", "hourly", "daily", "weekly"], {
    required_error: "Schedule is required"
  }),
  retryPolicy: z.object({
    maxAttempts: z.number().min(1).max(10),
    backoffMultiplier: z.number().min(1).max(5),
    maxDelay: z.number().min(60).max(3600)
  }),
  failoverEnabled: z.boolean().default(false),
  encryptInTransit: z.boolean().default(true),
  compressionEnabled: z.boolean().default(false),
  priority: z.enum(["low", "medium", "high", "critical"]).default("medium")
});

type ReplicationPolicy = z.infer<typeof replicationPolicySchema>;

interface KeyReplication {
  id: string;
  policyName: string;
  keyId: string;
  keyName: string;
  sourceRegion: string;
  targetRegions: string[];
  status: "active" | "paused" | "failed" | "syncing" | "pending";
  replicationMode: string;
  schedule: string;
  lastSync: string;
  nextSync: string;
  successRate: number;
  totalReplications: number;
  failedReplications: number;
  averageLatency: number;
  dataTransferred: number;
  failoverEnabled: boolean;
  priority: string;
  errors: Array<{
    id: string;
    region: string;
    message: string;
    timestamp: string;
    resolved: boolean;
  }>;
}

interface EncryptionKey {
  id: string;
  name: string;
  keyType: string;
  provider: string;
  region: string;
  status: string;
}

interface Region {
  id: string;
  name: string;
  provider: string;
  location: string;
  latency: number;
}

export default function KeyReplicationPage() {
  const [selectedTab, setSelectedTab] = useState("replications");
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const { toast } = useToast();

  // Fetch key replications
  const { data: replications = [], isLoading: replicationsLoading } = useQuery<KeyReplication[]>({
    queryKey: ["/api/key-replications"],
  });

  // Fetch available keys
  const { data: keys = [], isLoading: keysLoading } = useQuery<EncryptionKey[]>({
    queryKey: ["/api/keys"],
  });

  // Fetch available regions
  const { data: regions = [], isLoading: regionsLoading } = useQuery<Region[]>({
    queryKey: ["/api/regions"],
  });

  // Form setup
  const form = useForm<ReplicationPolicy>({
    resolver: zodResolver(replicationPolicySchema),
    defaultValues: {
      name: "",
      keyId: "",
      sourceRegion: "",
      targetRegions: [],
      replicationMode: "asynchronous",
      schedule: "daily",
      retryPolicy: {
        maxAttempts: 3,
        backoffMultiplier: 2,
        maxDelay: 300
      },
      failoverEnabled: false,
      encryptInTransit: true,
      compressionEnabled: false,
      priority: "medium"
    }
  });

  // Create replication policy mutation
  const createPolicyMutation = useMutation({
    mutationFn: async (data: ReplicationPolicy) => {
      return apiRequest("POST", "/api/key-replications/policies", data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/key-replications"] });
      toast({
        title: "Replication Policy Created",
        description: "Key replication has been configured successfully.",
      });
      form.reset();
      setShowCreateDialog(false);
    },
    onError: (error: any) => {
      toast({
        title: "Creation Failed",
        description: error.message || "Failed to create replication policy.",
        variant: "destructive",
      });
    },
  });

  // Control replication mutation
  const controlReplicationMutation = useMutation({
    mutationFn: async ({ id, action }: { id: string; action: "start" | "pause" | "resume" | "delete" }) => {
      return apiRequest("POST", `/api/key-replications/${id}/${action}`);
    },
    onSuccess: (_, { action }) => {
      queryClient.invalidateQueries({ queryKey: ["/api/key-replications"] });
      const actionText = action === "start" ? "started" : action === "pause" ? "paused" : action === "resume" ? "resumed" : "deleted";
      toast({
        title: "Action Successful",
        description: `Key replication has been ${actionText}.`,
      });
    },
    onError: (error: any) => {
      toast({
        title: "Action Failed",
        description: error.message || "Failed to perform the requested action.",
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: ReplicationPolicy) => {
    createPolicyMutation.mutate(data);
  };

  const handleControlReplication = (id: string, action: "start" | "pause" | "resume" | "delete") => {
    controlReplicationMutation.mutate({ id, action });
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "active":
        return <CheckCircle className="w-4 h-4 text-green-500" />;
      case "syncing":
        return <Activity className="w-4 h-4 text-blue-500 animate-pulse" />;
      case "paused":
        return <Pause className="w-4 h-4 text-yellow-500" />;
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
      case "syncing":
        return "bg-blue-500";
      case "paused":
        return "bg-yellow-500";
      case "failed":
        return "bg-red-500";
      default:
        return "bg-gray-500";
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case "critical":
        return "bg-red-500";
      case "high":
        return "bg-orange-500";
      case "medium":
        return "bg-blue-500";
      case "low":
        return "bg-gray-500";
      default:
        return "bg-gray-500";
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  return (
    <div className="p-6 space-y-6" data-testid="key-replication-page">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Key Replication</h1>
          <p className="text-muted-foreground">Manage cross-region key replication and disaster recovery</p>
        </div>
        <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
          <DialogTrigger asChild>
            <Button className="gap-2" data-testid="button-create-policy">
              <Plus className="w-4 h-4" />
              Create Policy
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl" data-testid="dialog-create-policy">
            <DialogHeader>
              <DialogTitle>Create Replication Policy</DialogTitle>
              <DialogDescription>
                Set up automated key replication across regions for disaster recovery
              </DialogDescription>
            </DialogHeader>
            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4 max-h-[60vh] overflow-y-auto">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <FormField
                    control={form.control}
                    name="name"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Policy Name</FormLabel>
                        <FormControl>
                          <Input placeholder="production-key-replication" {...field} data-testid="input-policy-name" />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="keyId"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Key</FormLabel>
                        <Select onValueChange={field.onChange} defaultValue={field.value}>
                          <FormControl>
                            <SelectTrigger data-testid="select-key">
                              <SelectValue placeholder="Select key to replicate" />
                            </SelectTrigger>
                          </FormControl>
                          <SelectContent>
                            {keys.map((key) => (
                              <SelectItem key={key.id} value={key.id}>
                                {key.name} ({key.keyType})
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <FormField
                    control={form.control}
                    name="sourceRegion"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Source Region</FormLabel>
                        <Select onValueChange={field.onChange} defaultValue={field.value}>
                          <FormControl>
                            <SelectTrigger data-testid="select-source-region">
                              <SelectValue placeholder="Select source region" />
                            </SelectTrigger>
                          </FormControl>
                          <SelectContent>
                            {regions.map((region) => (
                              <SelectItem key={region.id} value={region.id}>
                                {region.name} ({region.location})
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="replicationMode"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Replication Mode</FormLabel>
                        <Select onValueChange={field.onChange} defaultValue={field.value}>
                          <FormControl>
                            <SelectTrigger data-testid="select-replication-mode">
                              <SelectValue />
                            </SelectTrigger>
                          </FormControl>
                          <SelectContent>
                            <SelectItem value="synchronous">Synchronous</SelectItem>
                            <SelectItem value="asynchronous">Asynchronous</SelectItem>
                          </SelectContent>
                        </Select>
                        <FormDescription>
                          Synchronous ensures data consistency; Asynchronous provides better performance
                        </FormDescription>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <FormField
                    control={form.control}
                    name="schedule"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Schedule</FormLabel>
                        <Select onValueChange={field.onChange} defaultValue={field.value}>
                          <FormControl>
                            <SelectTrigger data-testid="select-schedule">
                              <SelectValue />
                            </SelectTrigger>
                          </FormControl>
                          <SelectContent>
                            <SelectItem value="real-time">Real-time</SelectItem>
                            <SelectItem value="hourly">Hourly</SelectItem>
                            <SelectItem value="daily">Daily</SelectItem>
                            <SelectItem value="weekly">Weekly</SelectItem>
                          </SelectContent>
                        </Select>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="priority"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Priority</FormLabel>
                        <Select onValueChange={field.onChange} defaultValue={field.value}>
                          <FormControl>
                            <SelectTrigger data-testid="select-priority">
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

                <div className="flex gap-2 pt-4">
                  <Button type="submit" disabled={createPolicyMutation.isPending} data-testid="button-submit-policy">
                    {createPolicyMutation.isPending ? "Creating..." : "Create Policy"}
                  </Button>
                  <Button 
                    type="button" 
                    variant="outline" 
                    onClick={() => setShowCreateDialog(false)}
                    data-testid="button-cancel-policy"
                  >
                    Cancel
                  </Button>
                </div>
              </form>
            </Form>
          </DialogContent>
        </Dialog>
      </div>

      <Tabs value={selectedTab} onValueChange={setSelectedTab} className="space-y-4">
        <TabsList data-testid="tabs-replication">
          <TabsTrigger value="replications" data-testid="tab-replications">Active Replications</TabsTrigger>
          <TabsTrigger value="analytics" data-testid="tab-analytics">Analytics</TabsTrigger>
          <TabsTrigger value="regions" data-testid="tab-regions">Regions</TabsTrigger>
        </TabsList>

        {/* Active Replications Tab */}
        <TabsContent value="replications" className="space-y-4">
          {replicationsLoading ? (
            <div className="grid grid-cols-1 gap-4">
              {[...Array(3)].map((_, i) => (
                <Card key={i} className="animate-pulse">
                  <CardHeader>
                    <div className="w-48 h-5 bg-muted rounded" />
                    <div className="w-32 h-4 bg-muted rounded" />
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
          ) : replications.length === 0 ? (
            <Card data-testid="card-no-replications">
              <CardContent className="pt-6">
                <div className="text-center">
                  <ArrowRightLeft className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                  <h3 className="text-lg font-semibold mb-2">No Key Replications</h3>
                  <p className="text-muted-foreground mb-4">
                    Set up your first key replication policy for disaster recovery
                  </p>
                  <Button onClick={() => setShowCreateDialog(true)} data-testid="button-create-first-policy">
                    <Plus className="w-4 h-4 mr-2" />
                    Create Replication Policy
                  </Button>
                </div>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              {replications.map((replication) => (
                <Card key={replication.id} data-testid={`card-replication-${replication.id}`}>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <div>
                        <CardTitle className="text-lg">{replication.policyName}</CardTitle>
                        <CardDescription className="flex items-center gap-2">
                          <MapPin className="w-3 h-3" />
                          {replication.sourceRegion} → {replication.targetRegions.join(", ")}
                        </CardDescription>
                      </div>
                      <div className="flex items-center gap-2">
                        {getStatusIcon(replication.status)}
                        <Badge 
                          variant="secondary" 
                          className={`${getStatusColor(replication.status)} text-white`}
                          data-testid={`badge-status-${replication.id}`}
                        >
                          {replication.status}
                        </Badge>
                        <Badge 
                          variant="outline" 
                          className={`${getPriorityColor(replication.priority)} text-white border-0`}
                        >
                          {replication.priority}
                        </Badge>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                      <div>
                        <p className="text-muted-foreground">Key</p>
                        <p className="font-medium" data-testid={`text-key-${replication.id}`}>{replication.keyName}</p>
                      </div>
                      <div>
                        <p className="text-muted-foreground">Mode</p>
                        <p className="font-medium">{replication.replicationMode}</p>
                      </div>
                      <div>
                        <p className="text-muted-foreground">Schedule</p>
                        <p className="font-medium">{replication.schedule}</p>
                      </div>
                      <div>
                        <p className="text-muted-foreground">Success Rate</p>
                        <p className="font-medium text-green-600" data-testid={`text-success-rate-${replication.id}`}>
                          {replication.successRate.toFixed(1)}%
                        </p>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                      <div>
                        <p className="text-muted-foreground">Total Replications</p>
                        <p className="font-medium">{replication.totalReplications.toLocaleString()}</p>
                      </div>
                      <div>
                        <p className="text-muted-foreground">Failed</p>
                        <p className="font-medium text-red-600">{replication.failedReplications}</p>
                      </div>
                      <div>
                        <p className="text-muted-foreground">Avg Latency</p>
                        <p className="font-medium">{replication.averageLatency}ms</p>
                      </div>
                      <div>
                        <p className="text-muted-foreground">Data Transferred</p>
                        <p className="font-medium">{formatBytes(replication.dataTransferred)}</p>
                      </div>
                    </div>

                    <div className="space-y-2">
                      <div className="flex justify-between items-center text-sm">
                        <span>Replication Health</span>
                        <span className="font-medium">{replication.successRate.toFixed(0)}%</span>
                      </div>
                      <Progress value={replication.successRate} className="h-2" />
                    </div>

                    {replication.errors.length > 0 && (
                      <Alert>
                        <AlertTriangle className="w-4 h-4" />
                        <AlertDescription>
                          {replication.errors.filter(e => !e.resolved).length} unresolved error{replication.errors.filter(e => !e.resolved).length !== 1 ? 's' : ''} 
                          in {replication.errors.map(e => e.region).join(", ")}
                        </AlertDescription>
                      </Alert>
                    )}

                    <div className="flex items-center justify-between">
                      <div className="text-xs text-muted-foreground">
                        Last sync: {new Date(replication.lastSync).toLocaleString()} • 
                        Next: {new Date(replication.nextSync).toLocaleString()}
                      </div>
                      <div className="flex gap-2">
                        <Button 
                          variant="outline" 
                          size="sm"
                          onClick={() => handleControlReplication(replication.id, replication.status === "paused" ? "resume" : "pause")}
                          disabled={controlReplicationMutation.isPending}
                          data-testid={`button-toggle-${replication.id}`}
                        >
                          {replication.status === "paused" ? (
                            <><Play className="w-3 h-3 mr-1" />Resume</>
                          ) : (
                            <><Pause className="w-3 h-3 mr-1" />Pause</>
                          )}
                        </Button>
                        <Button 
                          variant="outline" 
                          size="sm"
                          data-testid={`button-view-${replication.id}`}
                        >
                          <Eye className="w-3 h-3 mr-1" />
                          Details
                        </Button>
                        <Button 
                          variant="outline" 
                          size="sm"
                          onClick={() => handleControlReplication(replication.id, "delete")}
                          disabled={controlReplicationMutation.isPending}
                          data-testid={`button-delete-${replication.id}`}
                        >
                          <Trash2 className="w-3 h-3 mr-1" />
                          Delete
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* Analytics Tab */}
        <TabsContent value="analytics" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card data-testid="card-total-replications">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Total Replications</CardTitle>
                <ArrowRightLeft className="w-4 h-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold" data-testid="text-total-replications">
                  {replications.reduce((sum, r) => sum + r.totalReplications, 0).toLocaleString()}
                </div>
                <p className="text-xs text-muted-foreground">Across all policies</p>
              </CardContent>
            </Card>

            <Card data-testid="card-average-success-rate">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Average Success Rate</CardTitle>
                <CheckCircle className="w-4 h-4 text-green-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-green-600" data-testid="text-average-success-rate">
                  {replications.length > 0 
                    ? (replications.reduce((sum, r) => sum + r.successRate, 0) / replications.length).toFixed(1)
                    : 0
                  }%
                </div>
                <p className="text-xs text-muted-foreground">Replication reliability</p>
              </CardContent>
            </Card>

            <Card data-testid="card-data-transferred">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Data Transferred</CardTitle>
                <Database className="w-4 h-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold" data-testid="text-data-transferred">
                  {formatBytes(replications.reduce((sum, r) => sum + r.dataTransferred, 0))}
                </div>
                <p className="text-xs text-muted-foreground">Total across regions</p>
              </CardContent>
            </Card>
          </div>

          <Card data-testid="card-replication-health">
            <CardHeader>
              <CardTitle>Replication Health Overview</CardTitle>
              <CardDescription>Performance metrics for active replication policies</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {replications.map((replication) => (
                  <div key={`analytics-${replication.id}`} className="flex items-center justify-between p-3 border rounded-lg">
                    <div className="flex items-center gap-3">
                      <div className="flex items-center gap-2">
                        {getStatusIcon(replication.status)}
                        <span className="font-medium">{replication.policyName}</span>
                      </div>
                      <Badge variant="outline" className="text-xs">
                        {replication.targetRegions.length} region{replication.targetRegions.length !== 1 ? 's' : ''}
                      </Badge>
                    </div>
                    <div className="text-right">
                      <div className="text-sm font-medium">{replication.successRate.toFixed(1)}% success</div>
                      <div className="text-xs text-muted-foreground">{replication.averageLatency}ms avg</div>
                    </div>
                  </div>
                ))}
                
                {replications.length === 0 && (
                  <div className="text-center py-8">
                    <Activity className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                    <p className="text-muted-foreground">No replication data available</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Regions Tab */}
        <TabsContent value="regions" className="space-y-4">
          <Card data-testid="card-available-regions">
            <CardHeader>
              <CardTitle>Available Regions</CardTitle>
              <CardDescription>Cloud provider regions available for key replication</CardDescription>
            </CardHeader>
            <CardContent>
              {regionsLoading ? (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {[...Array(6)].map((_, i) => (
                    <div key={i} className="p-4 border rounded-lg animate-pulse">
                      <div className="w-24 h-5 bg-muted rounded mb-2" />
                      <div className="w-32 h-4 bg-muted rounded mb-1" />
                      <div className="w-16 h-3 bg-muted rounded" />
                    </div>
                  ))}
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {regions.map((region) => (
                    <div key={region.id} className="p-4 border rounded-lg" data-testid={`region-${region.id}`}>
                      <div className="flex items-center gap-2 mb-2">
                        <Globe className="w-4 h-4 text-muted-foreground" />
                        <span className="font-medium">{region.name}</span>
                      </div>
                      <div className="text-sm text-muted-foreground mb-1">{region.location}</div>
                      <div className="text-xs text-muted-foreground">
                        Latency: {region.latency}ms • {region.provider}
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