import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { CheckCircle, Plus, MoreVertical, Edit, Trash2, Eye, EyeOff } from "lucide-react";

export default function Subscription() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [editingPackage, setEditingPackage] = useState<any>(null);
  const [newPackage, setNewPackage] = useState({
    name: "",
    description: "",
    version: "1.0.0",
    isVisible: true
  });

  const { data: tenant, isLoading } = useQuery<any>({
    queryKey: ["/api/tenant"],
    retry: false,
  });

  const { data: packages = [], isLoading: packagesLoading } = useQuery<any[]>({
    queryKey: ["/api/packages"],
    retry: false,
  });

  const { data: sdks = [] } = useQuery<any[]>({
    queryKey: ["/api/sdks"],
    retry: false,
  });

  const { data: subscriptionData } = useQuery<{
    subscription: any;
    plan: any;
  }>({
    queryKey: ["/api/enterprise/subscription"],
    retry: false,
  });

  const createPackageMutation = useMutation({
    mutationFn: (packageData: any) => apiRequest('POST', '/api/packages', packageData),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/packages"] });
      setIsCreateOpen(false);
      setNewPackage({ name: "", description: "", version: "1.0.0", isVisible: true });
      toast({
        title: "Package created",
        description: "Package has been created successfully.",
      });
    },
    onError: (error) => {
      toast({
        title: "Failed to create package",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const updatePackageMutation = useMutation({
    mutationFn: ({ id, ...data }: any) => apiRequest('PUT', `/api/packages/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/packages"] });
      setEditingPackage(null);
      toast({
        title: "Package updated",
        description: "Package has been updated successfully.",
      });
    },
    onError: (error) => {
      toast({
        title: "Failed to update package",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const deletePackageMutation = useMutation({
    mutationFn: (id: string) => apiRequest('DELETE', `/api/packages/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/packages"] });
      toast({
        title: "Package deleted",
        description: "Package has been deleted successfully.",
      });
    },
    onError: (error) => {
      toast({
        title: "Failed to delete package",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const toggleVisibilityMutation = useMutation({
    mutationFn: ({ id, isVisible }: any) => apiRequest('PUT', `/api/packages/${id}`, { isVisible }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/packages"] });
      toast({
        title: "Visibility updated",
        description: "Package visibility has been updated.",
      });
    },
    onError: (error) => {
      toast({
        title: "Failed to update visibility",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const getSubscriptionDetails = (tier: string) => {
    switch (tier) {
      case 'starter':
        return {
          name: 'Starter',
          price: '$49',
          features: ['Up to 5 SDKs', 'Basic monitoring', 'Email support', 'Standard encryption']
        };
      case 'professional':
        return {
          name: 'Professional',
          price: '$149',
          features: ['Up to 50 SDKs', 'Advanced monitoring', 'Priority support', 'Quantum-safe encryption']
        };
      case 'enterprise':
        return {
          name: 'Enterprise',
          price: '$299',
          features: ['Unlimited SDKs', 'Real-time monitoring', '24/7 support', 'Custom compliance']
        };
      default:
        return {
          name: 'Unknown',
          price: '$0',
          features: []
        };
    }
  };

  if (isLoading) {
    return (
      <div className="p-6">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {[1, 2, 3].map((i) => (
            <div key={i} className="bg-slate-800 rounded-xl p-6 border border-slate-700 animate-pulse">
              <div className="h-32 bg-slate-700 rounded"></div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  const subscription = getSubscriptionDetails(tenant?.subscriptionTier || 'starter');

  return (
    <div className="p-6 bg-white min-h-screen">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Current Plan */}
        <Card className="bg-white border-gray-200">
          <CardHeader>
            <CardTitle className="text-gray-900">Current Plan</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-center">
              <h4 className="text-2xl font-bold text-blue-600 mb-2" data-testid="text-subscription-name">
                {subscription.name}
              </h4>
              <p className="text-3xl font-bold text-gray-900 mb-1" data-testid="text-subscription-price">
                {subscription.price}
                <span className="text-gray-600 text-lg">/month</span>
              </p>
              <p className="text-gray-600 text-sm mb-4">Billed annually</p>
              <div className="space-y-2 text-sm text-gray-700">
                {subscription.features.map((feature, index) => (
                  <p key={index} className="flex items-center">
                    <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                    {feature}
                  </p>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Usage Stats */}
        <Card className="bg-white border-gray-200">
          <CardHeader>
            <CardTitle className="text-gray-900">Plan Limits & Usage</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-gray-600">Generated SDKs</span>
                  <span className="text-gray-900 font-medium" data-testid="text-sdk-usage">
                    {sdks.length} / {
                      subscriptionData?.plan?.limits?.maxSdks 
                        ? subscriptionData.plan.limits.maxSdks 
                        : 'Unlimited'
                    }
                  </span>
                </div>
                <Progress 
                  value={
                    subscriptionData?.plan?.limits?.maxSdks 
                      ? (sdks.length / subscriptionData.plan.limits.maxSdks) * 100 
                      : 0
                  } 
                  className="h-2" 
                />
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-gray-600">Encryption Keys</span>
                  <span className="text-gray-900 font-medium" data-testid="text-key-usage">
                    0 / {
                      subscriptionData?.plan?.limits?.maxKeys 
                        ? subscriptionData.plan.limits.maxKeys 
                        : 'Unlimited'
                    }
                  </span>
                </div>
                <Progress value={0} className="h-2" />
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-gray-600">Team Members</span>
                  <span className="text-gray-900 font-medium" data-testid="text-user-usage">
                    3 / {
                      subscriptionData?.plan?.limits?.maxUsers 
                        ? subscriptionData.plan.limits.maxUsers 
                        : 'Unlimited'
                    }
                  </span>
                </div>
                <Progress 
                  value={
                    subscriptionData?.plan?.limits?.maxUsers 
                      ? (3 / subscriptionData.plan.limits.maxUsers) * 100 
                      : 0
                  } 
                  className="h-2" 
                />
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Billing */}
        <Card className="bg-white border-gray-200">
          <CardHeader>
            <CardTitle className="text-gray-900">Billing Information</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex justify-between">
                <span className="text-gray-600">Next billing</span>
                <span className="text-gray-900" data-testid="text-next-billing">Feb 15, 2024</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600">Payment method</span>
                <span className="text-gray-900" data-testid="text-payment-method">•••• 4242</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600">Amount</span>
                <span className="text-gray-900" data-testid="text-amount">{subscription.price}.00</span>
              </div>
              <Button 
                className="w-full mt-4 bg-blue-600 hover:bg-blue-700 text-white"
                data-testid="button-update-payment"
              >
                Update Payment Method
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Plan Comparison */}
      <div className="mt-8">
        <h3 className="text-2xl font-bold text-gray-900 mb-6 text-center">Choose Your Plan</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Starter Plan */}
          <Card className="bg-white border-gray-200">
            <CardHeader>
              <div className="text-center">
                <h4 className="text-xl font-bold text-gray-900">Starter</h4>
                <p className="text-3xl font-bold text-gray-900 mt-2">$49<span className="text-gray-600 text-lg">/month</span></p>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-3 mb-6">
                <p className="flex items-center text-gray-700">
                  <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                  Up to 5 SDKs
                </p>
                <p className="flex items-center text-gray-700">
                  <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                  Basic monitoring
                </p>
                <p className="flex items-center text-gray-700">
                  <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                  Email support
                </p>
                <p className="flex items-center text-gray-700">
                  <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                  Standard encryption
                </p>
              </div>
              <Button 
                className="w-full bg-gray-600 hover:bg-gray-700 text-white"
                variant={tenant?.subscriptionTier === 'starter' ? 'default' : 'outline'}
                data-testid="button-starter-plan"
              >
                {tenant?.subscriptionTier === 'starter' ? 'Current Plan' : 'Choose Starter'}
              </Button>
            </CardContent>
          </Card>

          {/* Professional Plan */}
          <Card className="bg-white border-blue-500 border-2">
            <CardHeader>
              <div className="text-center">
                <Badge className="bg-blue-500 text-white mb-2">Most Popular</Badge>
                <h4 className="text-xl font-bold text-gray-900">Professional</h4>
                <p className="text-3xl font-bold text-gray-900 mt-2">$149<span className="text-gray-600 text-lg">/month</span></p>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-3 mb-6">
                <p className="flex items-center text-gray-700">
                  <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                  Up to 50 SDKs
                </p>
                <p className="flex items-center text-gray-700">
                  <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                  Advanced monitoring
                </p>
                <p className="flex items-center text-gray-700">
                  <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                  Priority support
                </p>
                <p className="flex items-center text-gray-700">
                  <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                  Quantum-safe encryption
                </p>
              </div>
              <Button 
                className="w-full bg-blue-600 hover:bg-blue-700 text-white"
                variant={tenant?.subscriptionTier === 'professional' ? 'default' : 'outline'}
                data-testid="button-professional-plan"
              >
                {tenant?.subscriptionTier === 'professional' ? 'Current Plan' : 'Choose Professional'}
              </Button>
            </CardContent>
          </Card>

          {/* Enterprise Plan */}
          <Card className="bg-white border-gray-200">
            <CardHeader>
              <div className="text-center">
                <h4 className="text-xl font-bold text-gray-900">Enterprise</h4>
                <p className="text-3xl font-bold text-gray-900 mt-2">$299<span className="text-gray-600 text-lg">/month</span></p>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-3 mb-6">
                <p className="flex items-center text-gray-700">
                  <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                  Unlimited SDKs
                </p>
                <p className="flex items-center text-gray-700">
                  <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                  Real-time monitoring
                </p>
                <p className="flex items-center text-gray-700">
                  <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                  24/7 support
                </p>
                <p className="flex items-center text-gray-700">
                  <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                  Custom compliance
                </p>
              </div>
              <Button 
                className="w-full bg-gray-600 hover:bg-gray-700 text-white"
                variant={tenant?.subscriptionTier === 'enterprise' ? 'default' : 'outline'}
                data-testid="button-enterprise-plan"
              >
                {tenant?.subscriptionTier === 'enterprise' ? 'Current Plan' : 'Choose Enterprise'}
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Packages Management Section */}
      <div className="mt-12">
        <div className="flex justify-between items-center mb-6">
          <h3 className="text-2xl font-bold text-gray-900">Packages Management</h3>
          <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
            <DialogTrigger asChild>
              <Button className="bg-blue-600 hover:bg-blue-700 text-white" data-testid="button-create-package">
                <Plus className="w-4 h-4 mr-2" />
                Create Package
              </Button>
            </DialogTrigger>
            <DialogContent className="bg-white">
              <DialogHeader>
                <DialogTitle className="text-gray-900">Create New Package</DialogTitle>
                <DialogDescription className="text-gray-600">
                  Add a new package to your subscription.
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-4 py-4">
                <div className="grid grid-cols-4 items-center gap-4">
                  <Label htmlFor="name" className="text-right text-gray-900">
                    Name
                  </Label>
                  <Input
                    id="name"
                    value={newPackage.name}
                    onChange={(e) => setNewPackage({ ...newPackage, name: e.target.value })}
                    className="col-span-3"
                    data-testid="input-package-name"
                  />
                </div>
                <div className="grid grid-cols-4 items-center gap-4">
                  <Label htmlFor="version" className="text-right text-gray-900">
                    Version
                  </Label>
                  <Input
                    id="version"
                    value={newPackage.version}
                    onChange={(e) => setNewPackage({ ...newPackage, version: e.target.value })}
                    className="col-span-3"
                    data-testid="input-package-version"
                  />
                </div>
                <div className="grid grid-cols-4 items-start gap-4">
                  <Label htmlFor="description" className="text-right text-gray-900">
                    Description
                  </Label>
                  <Textarea
                    id="description"
                    value={newPackage.description}
                    onChange={(e) => setNewPackage({ ...newPackage, description: e.target.value })}
                    className="col-span-3"
                    data-testid="textarea-package-description"
                  />
                </div>
                <div className="grid grid-cols-4 items-center gap-4">
                  <Label htmlFor="visible" className="text-right text-gray-900">
                    Visible in Menu
                  </Label>
                  <Switch
                    id="visible"
                    checked={newPackage.isVisible}
                    onCheckedChange={(checked) => setNewPackage({ ...newPackage, isVisible: checked })}
                    data-testid="switch-package-visibility"
                  />
                </div>
              </div>
              <DialogFooter>
                <Button 
                  type="submit" 
                  onClick={() => createPackageMutation.mutate(newPackage)}
                  disabled={createPackageMutation.isPending}
                  className="bg-blue-600 hover:bg-blue-700 text-white"
                  data-testid="button-save-package"
                >
                  {createPackageMutation.isPending ? "Creating..." : "Create Package"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>

        {/* Packages List */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {packagesLoading ? (
            <div className="col-span-full flex items-center justify-center py-8">
              <div className="text-gray-600">Loading packages...</div>
            </div>
          ) : packages.length === 0 ? (
            <div className="col-span-full flex items-center justify-center py-8">
              <div className="text-gray-600">No packages found. Create your first package!</div>
            </div>
          ) : (
            packages.map((pkg) => (
              <Card key={pkg.id} className="bg-white border-gray-200" data-testid={`card-package-${pkg.id}`}>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium text-gray-900" data-testid={`text-package-name-${pkg.id}`}>
                    {pkg.name}
                  </CardTitle>
                  <div className="flex items-center space-x-2">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => toggleVisibilityMutation.mutate({ id: pkg.id, isVisible: !pkg.isVisible })}
                      className="h-8 w-8 p-0"
                      data-testid={`button-toggle-visibility-${pkg.id}`}
                    >
                      {pkg.isVisible ? (
                        <Eye className="h-4 w-4 text-green-600" />
                      ) : (
                        <EyeOff className="h-4 w-4 text-gray-400" />
                      )}
                    </Button>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" className="h-8 w-8 p-0" data-testid={`button-menu-${pkg.id}`}>
                          <MoreVertical className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end" className="bg-white border-gray-200">
                        <DropdownMenuItem
                          onClick={() => setEditingPackage(pkg)}
                          className="text-gray-900 hover:bg-gray-100"
                          data-testid={`button-edit-${pkg.id}`}
                        >
                          <Edit className="mr-2 h-4 w-4" />
                          Edit
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() => deletePackageMutation.mutate(pkg.id)}
                          className="text-red-600 hover:bg-red-50"
                          data-testid={`button-delete-${pkg.id}`}
                        >
                          <Trash2 className="mr-2 h-4 w-4" />
                          Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="text-xs text-gray-600 mb-2" data-testid={`text-package-version-${pkg.id}`}>
                    Version: {pkg.version}
                  </div>
                  <p className="text-sm text-gray-700" data-testid={`text-package-description-${pkg.id}`}>
                    {pkg.description || "No description available"}
                  </p>
                  <div className="mt-2">
                    <Badge 
                      variant={pkg.isVisible ? "default" : "secondary"}
                      className={pkg.isVisible ? "bg-green-100 text-green-800" : "bg-gray-100 text-gray-800"}
                      data-testid={`badge-package-visibility-${pkg.id}`}
                    >
                      {pkg.isVisible ? "Visible" : "Hidden"}
                    </Badge>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </div>

        {/* Edit Package Dialog */}
        {editingPackage && (
          <Dialog open={true} onOpenChange={() => setEditingPackage(null)}>
            <DialogContent className="bg-white">
              <DialogHeader>
                <DialogTitle className="text-gray-900">Edit Package</DialogTitle>
                <DialogDescription className="text-gray-600">
                  Update package information.
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-4 py-4">
                <div className="grid grid-cols-4 items-center gap-4">
                  <Label htmlFor="edit-name" className="text-right text-gray-900">
                    Name
                  </Label>
                  <Input
                    id="edit-name"
                    value={editingPackage.name}
                    onChange={(e) => setEditingPackage({ ...editingPackage, name: e.target.value })}
                    className="col-span-3"
                    data-testid="input-edit-package-name"
                  />
                </div>
                <div className="grid grid-cols-4 items-center gap-4">
                  <Label htmlFor="edit-version" className="text-right text-gray-900">
                    Version
                  </Label>
                  <Input
                    id="edit-version"
                    value={editingPackage.version}
                    onChange={(e) => setEditingPackage({ ...editingPackage, version: e.target.value })}
                    className="col-span-3"
                    data-testid="input-edit-package-version"
                  />
                </div>
                <div className="grid grid-cols-4 items-start gap-4">
                  <Label htmlFor="edit-description" className="text-right text-gray-900">
                    Description
                  </Label>
                  <Textarea
                    id="edit-description"
                    value={editingPackage.description || ""}
                    onChange={(e) => setEditingPackage({ ...editingPackage, description: e.target.value })}
                    className="col-span-3"
                    data-testid="textarea-edit-package-description"
                  />
                </div>
                <div className="grid grid-cols-4 items-center gap-4">
                  <Label htmlFor="edit-visible" className="text-right text-gray-900">
                    Visible in Menu
                  </Label>
                  <Switch
                    id="edit-visible"
                    checked={editingPackage.isVisible}
                    onCheckedChange={(checked) => setEditingPackage({ ...editingPackage, isVisible: checked })}
                    data-testid="switch-edit-package-visibility"
                  />
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setEditingPackage(null)}>
                  Cancel
                </Button>
                <Button 
                  type="submit" 
                  onClick={() => updatePackageMutation.mutate(editingPackage)}
                  disabled={updatePackageMutation.isPending}
                  className="bg-blue-600 hover:bg-blue-700 text-white"
                  data-testid="button-update-package"
                >
                  {updatePackageMutation.isPending ? "Updating..." : "Update Package"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        )}
      </div>
    </div>
  );
}
