import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Plus, RotateCcw, Pause, Trash2 } from "lucide-react";
import { formatDistanceToNow } from "date-fns";

export default function KeyManagement() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: keys, isLoading } = useQuery({
    queryKey: ["/api/keys"],
    retry: false,
    onError: (error: Error) => {
      if (isUnauthorizedError(error)) {
        toast({
          title: "Unauthorized",
          description: "You are logged out. Logging in again...",
          variant: "destructive",
        });
        setTimeout(() => {
          window.location.href = "/api/login";
        }, 500);
        return;
      }
    },
  });

  const rotateKeyMutation = useMutation({
    mutationFn: async (keyId: string) => {
      return await apiRequest('PUT', `/api/keys/${keyId}/rotate`, {});
    },
    onSuccess: () => {
      toast({
        title: "Success",
        description: "Key rotation initiated successfully!",
      });
      queryClient.invalidateQueries(["/api/keys"]);
    },
    onError: (error: Error) => {
      if (isUnauthorizedError(error)) {
        toast({
          title: "Unauthorized",
          description: "You are logged out. Logging in again...",
          variant: "destructive",
        });
        setTimeout(() => {
          window.location.href = "/api/login";
        }, 500);
        return;
      }
      toast({
        title: "Error",
        description: "Failed to rotate key. Please try again.",
        variant: "destructive",
      });
    },
  });

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
      <div className="mb-6">
        <Button className="bg-blue-500 hover:bg-blue-600 text-white" data-testid="button-generate-key">
          <Plus className="w-4 h-4 mr-2" />
          Generate New Key
        </Button>
      </div>

      <Card className="bg-slate-800 border-slate-700">
        <CardHeader>
          <CardTitle className="text-white">Encryption Keys</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-4">
              {[1, 2, 3].map((i) => (
                <div key={i} className="h-16 bg-slate-700 rounded animate-pulse"></div>
              ))}
            </div>
          ) : keys?.length ? (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="border-slate-700">
                    <TableHead className="text-white font-medium">Key ID</TableHead>
                    <TableHead className="text-white font-medium">Type</TableHead>
                    <TableHead className="text-white font-medium">Algorithm</TableHead>
                    <TableHead className="text-white font-medium">Created</TableHead>
                    <TableHead className="text-white font-medium">Status</TableHead>
                    <TableHead className="text-white font-medium">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {keys.map((key: any) => (
                    <TableRow key={key.id} className="border-slate-700">
                      <TableCell className="text-slate-300 font-mono text-sm" data-testid={`key-id-${key.id}`}>
                        {key.keyId}
                      </TableCell>
                      <TableCell className="text-slate-300" data-testid={`key-type-${key.id}`}>
                        {key.keyType}
                      </TableCell>
                      <TableCell className="text-slate-300" data-testid={`key-algorithm-${key.id}`}>
                        {key.algorithm?.displayName || 'N/A'}
                      </TableCell>
                      <TableCell className="text-slate-300" data-testid={`key-created-${key.id}`}>
                        {formatDistanceToNow(new Date(key.createdAt), { addSuffix: true })}
                      </TableCell>
                      <TableCell>
                        <Badge className={`${getStatusColor(key.status)} text-white`} data-testid={`key-status-${key.id}`}>
                          {key.status.toUpperCase()}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex space-x-2">
                          <Button
                            size="sm"
                            variant="ghost"
                            className="text-blue-500 hover:text-blue-400 hover:bg-slate-700"
                            onClick={() => rotateKeyMutation.mutate(key.keyId)}
                            disabled={rotateKeyMutation.isPending || key.status === 'rotating'}
                            data-testid={`button-rotate-${key.id}`}
                          >
                            <RotateCcw className="w-4 h-4" />
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            className="text-yellow-500 hover:text-yellow-400 hover:bg-slate-700"
                            data-testid={`button-pause-${key.id}`}
                          >
                            <Pause className="w-4 h-4" />
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            className="text-red-500 hover:text-red-400 hover:bg-slate-700"
                            data-testid={`button-delete-${key.id}`}
                          >
                            <Trash2 className="w-4 h-4" />
                          </Button>
                        </div>
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
