import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { 
  Table, 
  TableBody, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from "@/components/ui/table";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Input } from "@/components/ui/input";
import { 
  Download, 
  Trash2, 
  Package, 
  Search, 
  Calendar,
  Code,
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock
} from "lucide-react";
import type { Sdk } from '@shared/schema';

export default function SDKManagement() {
  const [searchTerm, setSearchTerm] = useState("");
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [deleteAllDialogOpen, setDeleteAllDialogOpen] = useState(false);
  const [selectedSDK, setSelectedSDK] = useState<Sdk | null>(null);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Fetch SDKs
  const { data: sdks = [], isLoading, error } = useQuery<Sdk[]>({
    queryKey: ['/api/sdks'],
    retry: (failureCount, error) => {
      if (isUnauthorizedError(error)) return false;
      return failureCount < 3;
    },
  });

  // Delete single SDK mutation
  const deleteSDKMutation = useMutation({
    mutationFn: (sdkId: string) => fetch(`/api/sdks/${sdkId}`, {
      method: 'DELETE',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
      },
    }).then(async (res) => {
      if (!res.ok) {
        const error = await res.json();
        throw new Error(error.message || 'Failed to delete SDK');
      }
      return res.json();
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/sdks'] });
      toast({
        title: "SDK Deleted",
        description: "The SDK has been successfully deleted.",
      });
      setDeleteDialogOpen(false);
      setSelectedSDK(null);
    },
    onError: (error: any) => {
      toast({
        title: "Delete Failed",
        description: error.message || "Failed to delete SDK. Please try again.",
        variant: "destructive",
      });
    },
  });

  // Delete all SDKs mutation
  const deleteAllSDKsMutation = useMutation({
    mutationFn: () => fetch('/api/sdks/delete-all', {
      method: 'DELETE',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
      },
    }).then(async (res) => {
      if (!res.ok) {
        const error = await res.json();
        throw new Error(error.message || 'Failed to delete all SDKs');
      }
      return res.json();
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/sdks'] });
      toast({
        title: "All SDKs Deleted",
        description: "All SDKs have been successfully deleted.",
      });
      setDeleteAllDialogOpen(false);
    },
    onError: (error: any) => {
      toast({
        title: "Delete All Failed",
        description: error.message || "Failed to delete all SDKs. Please try again.",
        variant: "destructive",
      });
    },
  });

  // Download SDK
  const handleDownload = async (sdk: Sdk) => {
    try {
      if (!sdk.downloadUrl) {
        toast({
          title: "Download Not Available",
          description: "This SDK does not have a download URL.",
          variant: "destructive",
        });
        return;
      }

      // Extract download ID from URL (e.g., "/api/sdks/finance-secure-v2.1.0/download" -> "finance-secure-v2.1.0")
      const urlParts = sdk.downloadUrl.split('/');
      const downloadId = urlParts[urlParts.length - 2]; // Get the part before "/download"
      const response = await fetch(`/api/sdks/${downloadId}/download`, {
        method: 'GET',
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error('Download failed');
      }

      // Create blob and download
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.style.display = 'none';
      a.href = url;
      a.download = `${sdk.name.replace(/[^a-zA-Z0-9\s]/g, '')}-v${sdk.version}.zip`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      toast({
        title: "Download Started",
        description: `${sdk.name} SDK download has started.`,
      });
    } catch (error) {
      toast({
        title: "Download Failed",
        description: "Failed to download SDK. Please try again.",
        variant: "destructive",
      });
    }
  };

  // Filter SDKs based on search term
  const filteredSDKs = (sdks as Sdk[]).filter((sdk: Sdk) =>
    sdk.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    sdk.applicationType?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    sdk.securityLevel?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Get security level badge variant
  const getSecurityBadgeVariant = (level: string) => {
    switch (level) {
      case 'confidential':
      case 'privacy_preserving':
        return 'default';
      case 'maximum':
        return 'destructive';
      case 'enhanced':
        return 'secondary';
      default:
        return 'outline';
    }
  };

  // Format date
  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  // Parse JSON safely
  const parseJSON = (jsonString: string, fallback: any[] = []) => {
    try {
      return JSON.parse(jsonString);
    } catch {
      return fallback;
    }
  };

  if (isLoading) {
    return (
      <div className="p-6">
        <div className="max-w-7xl mx-auto">
          <div className="text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto"></div>
            <p className="mt-2 text-muted-foreground">Loading SDKs...</p>
          </div>
        </div>
      </div>
    );
  }

  if (error && isUnauthorizedError(error)) {
    return (
      <div className="p-6">
        <div className="max-w-7xl mx-auto text-center">
          <p className="text-muted-foreground">Please log in to view your SDKs.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div>
              <h1 className="text-3xl font-bold text-foreground">SDK Management</h1>
              <p className="text-muted-foreground">
                Manage, download, and organize your generated encryption SDKs
              </p>
            </div>
            <div className="flex gap-2">
              <Button
                variant="outline"
                onClick={() => window.location.href = '/wizard'}
                data-testid="button-create-new-sdk"
              >
                <Package className="w-4 h-4 mr-2" />
                Create New SDK
              </Button>
              {(sdks as Sdk[]).length > 0 && (
                <Button
                  variant="destructive"
                  onClick={() => setDeleteAllDialogOpen(true)}
                  disabled={deleteAllSDKsMutation.isPending}
                  data-testid="button-delete-all-sdks"
                >
                  <Trash2 className="w-4 h-4 mr-2" />
                  Delete All
                </Button>
              )}
            </div>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-blue-100 dark:bg-blue-900/20 rounded-lg">
                  <Package className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                </div>
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Total SDKs</p>
                  <p className="text-2xl font-bold" data-testid="total-sdks-count">{(sdks as Sdk[]).length}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-green-100 dark:bg-green-900/20 rounded-lg">
                  <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400" />
                </div>
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Active SDKs</p>
                  <p className="text-2xl font-bold" data-testid="active-sdks-count">
                    {(sdks as Sdk[]).filter((sdk: Sdk) => sdk.isActive).length}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-purple-100 dark:bg-purple-900/20 rounded-lg">
                  <Shield className="w-5 h-5 text-purple-600 dark:text-purple-400" />
                </div>
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Confidential</p>
                  <p className="text-2xl font-bold" data-testid="confidential-sdks-count">
                    {(sdks as Sdk[]).filter((sdk: Sdk) => 
                      sdk.securityLevel === 'confidential' || sdk.securityLevel === 'privacy_preserving'
                    ).length}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-yellow-100 dark:bg-yellow-900/20 rounded-lg">
                  <Code className="w-5 h-5 text-yellow-600 dark:text-yellow-400" />
                </div>
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Languages</p>
                  <p className="text-2xl font-bold" data-testid="total-languages-count">
                    {new Set((sdks as Sdk[]).flatMap((sdk: Sdk) => parseJSON(sdk.languages))).size}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Search and Filters */}
        <Card className="mb-6">
          <CardContent className="p-4">
            <div className="flex items-center gap-4">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground w-4 h-4" />
                <Input
                  placeholder="Search SDKs by name, type, or security level..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                  data-testid="input-search-sdks"
                />
              </div>
              <Badge variant="outline" className="text-sm">
                {filteredSDKs.length} of {(sdks as Sdk[]).length} SDKs
              </Badge>
            </div>
          </CardContent>
        </Card>

        {/* SDKs Table */}
        {filteredSDKs.length === 0 ? (
          <Card>
            <CardContent className="p-12 text-center">
              <Package className="w-16 h-16 text-muted-foreground mx-auto mb-4" />
              <h3 className="text-lg font-semibold text-foreground mb-2">
                {searchTerm ? 'No SDKs Found' : 'No SDKs Created'}
              </h3>
              <p className="text-muted-foreground mb-6">
                {searchTerm 
                  ? 'Try adjusting your search terms to find the SDKs you\'re looking for.'
                  : 'Get started by creating your first encryption SDK with our wizard.'
                }
              </p>
              {!searchTerm && (
                <Button
                  onClick={() => window.location.href = '/wizard'}
                  data-testid="button-create-first-sdk"
                >
                  <Package className="w-4 h-4 mr-2" />
                  Create Your First SDK
                </Button>
              )}
            </CardContent>
          </Card>
        ) : (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Package className="w-5 h-5" />
                Generated SDKs
              </CardTitle>
              <CardDescription>
                Manage and download your encryption SDKs
              </CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Security Level</TableHead>
                      <TableHead>Languages</TableHead>
                      <TableHead>Version</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredSDKs.map((sdk: Sdk) => {
                      const languages = parseJSON(sdk.languages);
                      const algorithms = parseJSON(sdk.algorithms);
                      
                      return (
                        <TableRow key={sdk.id} data-testid={`sdk-row-${sdk.id}`}>
                          <TableCell>
                            <div>
                              <div className="font-medium text-foreground">{sdk.name}</div>
                              <div className="text-sm text-muted-foreground">
                                {algorithms.length} algorithm{algorithms.length !== 1 ? 's' : ''}
                              </div>
                            </div>
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline" className="capitalize">
                              {sdk.applicationType || 'General'}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Badge variant={getSecurityBadgeVariant(sdk.securityLevel || 'standard')}>
                              {(sdk.securityLevel || 'standard').replace('_', ' ')}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <div className="flex flex-wrap gap-1">
                              {languages.slice(0, 2).map((lang: string) => (
                                <Badge key={lang} variant="secondary" className="text-xs">
                                  {lang}
                                </Badge>
                              ))}
                              {languages.length > 2 && (
                                <Badge variant="outline" className="text-xs">
                                  +{languages.length - 2}
                                </Badge>
                              )}
                            </div>
                          </TableCell>
                          <TableCell>
                            <code className="text-sm">{sdk.version}</code>
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-1 text-sm text-muted-foreground">
                              <Calendar className="w-3 h-3" />
                              {formatDate(typeof sdk.createdAt === 'string' ? sdk.createdAt : sdk.createdAt ? new Date(sdk.createdAt).toISOString() : new Date().toISOString())}
                            </div>
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-1">
                              {sdk.isActive ? (
                                <CheckCircle className="w-4 h-4 text-green-500" />
                              ) : (
                                <Clock className="w-4 h-4 text-yellow-500" />
                              )}
                              <span className="text-sm">
                                {sdk.isActive ? 'Active' : 'Inactive'}
                              </span>
                            </div>
                          </TableCell>
                          <TableCell className="text-right">
                            <div className="flex items-center justify-end gap-2">
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => handleDownload(sdk)}
                                data-testid={`button-download-${sdk.id}`}
                              >
                                <Download className="w-4 h-4" />
                              </Button>
                              <Button
                                size="sm"
                                variant="destructive"
                                onClick={() => {
                                  setSelectedSDK(sdk);
                                  setDeleteDialogOpen(true);
                                }}
                                disabled={deleteSDKMutation.isPending}
                                data-testid={`button-delete-${sdk.id}`}
                              >
                                <Trash2 className="w-4 h-4" />
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Delete Single SDK Dialog */}
        <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-destructive" />
                Delete SDK
              </AlertDialogTitle>
              <AlertDialogDescription>
                Are you sure you want to delete "{selectedSDK?.name}"? This action cannot be undone.
                The SDK files and all associated data will be permanently removed.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel data-testid="button-cancel-delete">Cancel</AlertDialogCancel>
              <AlertDialogAction
                onClick={() => selectedSDK && deleteSDKMutation.mutate(selectedSDK.id)}
                className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                disabled={deleteSDKMutation.isPending}
                data-testid="button-confirm-delete"
              >
                {deleteSDKMutation.isPending ? 'Deleting...' : 'Delete SDK'}
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>

        {/* Delete All SDKs Dialog */}
        <AlertDialog open={deleteAllDialogOpen} onOpenChange={setDeleteAllDialogOpen}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-destructive" />
                Delete All SDKs
              </AlertDialogTitle>
              <AlertDialogDescription>
                Are you sure you want to delete ALL {(sdks as Sdk[]).length} SDKs? This action cannot be undone.
                All SDK files and associated data will be permanently removed from your account.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel data-testid="button-cancel-delete-all">Cancel</AlertDialogCancel>
              <AlertDialogAction
                onClick={() => deleteAllSDKsMutation.mutate()}
                className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                disabled={deleteAllSDKsMutation.isPending}
                data-testid="button-confirm-delete-all"
              >
                {deleteAllSDKsMutation.isPending ? 'Deleting All...' : 'Delete All SDKs'}
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </div>
    </div>
  );
}