import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Plus, Edit, Ban, Users, UserPlus, ShieldCheck, Eye } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";

const inviteUserSchema = z.object({
  email: z.string().email("Please enter a valid email address"),
  firstName: z.string().min(1, "First name is required"),
  lastName: z.string().optional(),
  role: z.enum(["admin", "developer", "viewer"], {
    required_error: "Please select a role",
  }),
});

type InviteUserFormData = z.infer<typeof inviteUserSchema>;

export default function UserManagement() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [isInviteDialogOpen, setIsInviteDialogOpen] = useState(false);

  const { data: users = [], isLoading, error } = useQuery({
    queryKey: ["/api/users"],
    retry: false,
  });

  const { data: userStats } = useQuery({
    queryKey: ["/api/users/stats"],
    retry: false,
  });

  const form = useForm<InviteUserFormData>({
    resolver: zodResolver(inviteUserSchema),
    defaultValues: {
      email: "",
      firstName: "",
      lastName: "",
      role: "viewer",
    },
  });

  const inviteUserMutation = useMutation({
    mutationFn: async (data: InviteUserFormData) => {
      return await apiRequest('POST', `/api/users/invite`, data);
    },
    onSuccess: () => {
      toast({
        title: "Success",
        description: "User invited successfully!",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/users"] });
      queryClient.invalidateQueries({ queryKey: ["/api/users/stats"] });
      setIsInviteDialogOpen(false);
      form.reset();
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to invite user. Please try again.",
        variant: "destructive",
      });
    },
  });

  const updateRoleMutation = useMutation({
    mutationFn: async ({ userId, role }: { userId: string; role: string }) => {
      return await apiRequest('PUT', `/api/users/${userId}/role`, { role });
    },
    onSuccess: () => {
      toast({
        title: "Success",
        description: "User role updated successfully!",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/users"] });
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
        description: "Failed to update user role. Please try again.",
        variant: "destructive",
      });
    },
  });

  const getRoleColor = (role: string) => {
    switch (role) {
      case 'admin':
        return 'bg-red-500';
      case 'developer':
        return 'bg-blue-500';
      case 'viewer':
        return 'bg-gray-500';
      default:
        return 'bg-gray-500';
    }
  };

  const handleRoleChange = (userId: string, newRole: string) => {
    updateRoleMutation.mutate({ userId, role: newRole });
  };

  const onInviteUser = (data: InviteUserFormData) => {
    inviteUserMutation.mutate(data);
  };

  if (error) {
    return (
      <div className="min-h-screen bg-white p-6">
        <div className="text-center py-12">
          <ShieldCheck className="w-16 h-16 mx-auto text-red-500 mb-4" />
          <h3 className="text-lg font-semibold text-gray-900 mb-2">Access Denied</h3>
          <p className="text-gray-600">You don't have permission to access user management.</p>
          <p className="text-sm text-gray-500 mt-2">Please contact an administrator for access.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-white p-6">
      <div className="mb-6 flex justify-between items-center">
        <div>
          <h3 className="text-2xl font-bold text-gray-900">User Management</h3>
          <p className="text-gray-600 mt-1">Manage team members and their permissions</p>
        </div>
        <Dialog open={isInviteDialogOpen} onOpenChange={setIsInviteDialogOpen}>
          <DialogTrigger asChild>
            <Button className="bg-blue-600 hover:bg-blue-700 text-white" data-testid="button-invite-user">
              <Plus className="w-4 h-4 mr-2" />
              Invite User
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>Invite New User</DialogTitle>
            </DialogHeader>
            <Form {...form}>
              <form onSubmit={form.handleSubmit(onInviteUser)} className="space-y-4">
                <FormField
                  control={form.control}
                  name="email"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Email Address</FormLabel>
                      <FormControl>
                        <Input placeholder="user@example.com" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <div className="grid grid-cols-2 gap-4">
                  <FormField
                    control={form.control}
                    name="firstName"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>First Name</FormLabel>
                        <FormControl>
                          <Input placeholder="John" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="lastName"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Last Name</FormLabel>
                        <FormControl>
                          <Input placeholder="Doe" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>
                <FormField
                  control={form.control}
                  name="role"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Role</FormLabel>
                      <Select onValueChange={field.onChange} defaultValue={field.value}>
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue placeholder="Select a role" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="viewer">
                            <div className="flex items-center">
                              <Eye className="w-4 h-4 mr-2" />
                              Viewer - Read-only access
                            </div>
                          </SelectItem>
                          <SelectItem value="developer">
                            <div className="flex items-center">
                              <Users className="w-4 h-4 mr-2" />
                              Developer - Create and manage SDKs
                            </div>
                          </SelectItem>
                          <SelectItem value="admin">
                            <div className="flex items-center">
                              <ShieldCheck className="w-4 h-4 mr-2" />
                              Admin - Full access
                            </div>
                          </SelectItem>
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <div className="flex justify-end space-x-2 pt-4">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setIsInviteDialogOpen(false)}
                  >
                    Cancel
                  </Button>
                  <Button
                    type="submit"
                    disabled={inviteUserMutation.isPending}
                    className="bg-blue-600 hover:bg-blue-700"
                  >
                    {inviteUserMutation.isPending ? "Inviting..." : "Send Invite"}
                  </Button>
                </div>
              </form>
            </Form>
          </DialogContent>
        </Dialog>
      </div>

      {/* User Statistics Cards */}
      {userStats && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-6">
          <Card className="bg-white border border-gray-200">
            <CardContent className="p-6">
              <div className="flex items-center">
                <Users className="w-8 h-8 text-blue-600" />
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Total Users</p>
                  <p className="text-2xl font-bold text-gray-900">{userStats.totalUsers}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card className="bg-white border border-gray-200">
            <CardContent className="p-6">
              <div className="flex items-center">
                <UserPlus className="w-8 h-8 text-green-600" />
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Active Users</p>
                  <p className="text-2xl font-bold text-gray-900">{userStats.activeUsers}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card className="bg-white border border-gray-200">
            <CardContent className="p-6">
              <div className="flex items-center">
                <ShieldCheck className="w-8 h-8 text-purple-600" />
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Admins</p>
                  <p className="text-2xl font-bold text-gray-900">{userStats.adminUsers}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card className="bg-white border border-gray-200">
            <CardContent className="p-6">
              <div className="flex items-center">
                <Users className="w-8 h-8 text-orange-600" />
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Recent Joins</p>
                  <p className="text-2xl font-bold text-gray-900">{userStats.recentlyJoined}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      <Card className="bg-white border border-gray-200 shadow-sm">
        <CardHeader>
          <CardTitle className="text-gray-900 flex items-center">
            <Users className="w-5 h-5 mr-2" />
            Team Members ({users.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-4">
              {[1, 2, 3].map((i) => (
                <div key={i} className="h-16 bg-gray-100 rounded animate-pulse"></div>
              ))}
            </div>
          ) : users?.length ? (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="border-gray-200">
                    <TableHead className="text-gray-900 font-medium">User</TableHead>
                    <TableHead className="text-gray-900 font-medium">Role</TableHead>
                    <TableHead className="text-gray-900 font-medium">Last Active</TableHead>
                    <TableHead className="text-gray-900 font-medium">Status</TableHead>
                    <TableHead className="text-gray-900 font-medium">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {users.map((user: any) => (
                    <TableRow key={user.id} className="border-gray-200 hover:bg-gray-50">
                      <TableCell>
                        <div className="flex items-center space-x-3">
                          <Avatar className="w-8 h-8">
                            <AvatarImage src={user.profileImageUrl} />
                            <AvatarFallback className="bg-blue-500 text-white">
                              {user.firstName?.[0] || user.email?.[0]?.toUpperCase() || 'U'}
                            </AvatarFallback>
                          </Avatar>
                          <div>
                            <p className="text-gray-900 font-medium" data-testid={`user-name-${user.id}`}>
                              {user.firstName ? `${user.firstName} ${user.lastName || ''}` : 'Unknown User'}
                            </p>
                            <p className="text-gray-500 text-sm" data-testid={`user-email-${user.id}`}>
                              {user.email}
                            </p>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Select
                          value={user.role}
                          onValueChange={(value) => handleRoleChange(user.id, value)}
                          disabled={updateRoleMutation.isPending}
                        >
                          <SelectTrigger className="w-32 bg-white border-gray-300 text-gray-900">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="admin">Admin</SelectItem>
                            <SelectItem value="developer">Developer</SelectItem>
                            <SelectItem value="viewer">Viewer</SelectItem>
                          </SelectContent>
                        </Select>
                      </TableCell>
                      <TableCell className="text-gray-600" data-testid={`user-last-active-${user.id}`}>
                        {formatDistanceToNow(new Date(user.updatedAt), { addSuffix: true })}
                      </TableCell>
                      <TableCell>
                        <Badge 
                          className={`${
                            user.status === 'suspended' ? 'bg-red-500' : 
                            user.status === 'inactive' ? 'bg-gray-500' : 
                            'bg-green-500'
                          } text-white`} 
                          data-testid={`user-status-${user.id}`}
                        >
                          {user.status || 'ACTIVE'}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex space-x-2">
                          <Button
                            size="sm"
                            variant="ghost"
                            className="text-blue-600 hover:text-blue-700 hover:bg-blue-50"
                            data-testid={`button-edit-${user.id}`}
                          >
                            <Edit className="w-4 h-4" />
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            className="text-red-600 hover:text-red-700 hover:bg-red-50"
                            data-testid={`button-ban-${user.id}`}
                          >
                            <Ban className="w-4 h-4" />
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
              <p className="text-gray-600">No users found</p>
              <p className="text-gray-500 text-sm mt-2">Invite team members to get started</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
