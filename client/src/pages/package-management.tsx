import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Plus, Edit, Package, Trash2, DollarSign, Users } from "lucide-react";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";

const planFormSchema = z.object({
  code: z.string().min(1, "Plan code is required"),
  name: z.string().min(1, "Plan name is required"),
  description: z.string().optional(),
  priceCents: z.coerce.number().min(0, "Price must be positive"),
  currency: z.string().default("USD"),
  interval: z.enum(["month", "year", "week"], {
    required_error: "Billing interval is required",
  }),
  maxSdks: z.coerce.number().min(0, "Max SDKs must be positive").optional(),
  maxKeys: z.coerce.number().min(0, "Max keys must be positive").optional(),
  maxUsers: z.coerce.number().min(0, "Max users must be positive").optional(),
  isActive: z.boolean().default(true),
  sortOrder: z.coerce.number().min(0).default(0),
});

type PlanFormData = z.infer<typeof planFormSchema>;

export default function PackageManagement() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [isEditDialogOpen, setIsEditDialogOpen] = useState(false);
  const [selectedPlan, setSelectedPlan] = useState<any>(null);

  const { data: plans = [], isLoading } = useQuery<any[]>({
    queryKey: ["/api/admin/plans"],
    retry: false,
  });

  const createForm = useForm<PlanFormData>({
    resolver: zodResolver(planFormSchema),
    defaultValues: {
      code: "",
      name: "",
      description: "",
      priceCents: 0,
      currency: "USD",
      interval: "month",
      maxSdks: 10,
      maxKeys: 50,
      maxUsers: 5,
      isActive: true,
      sortOrder: 0,
    },
  });

  const editForm = useForm<PlanFormData>({
    resolver: zodResolver(planFormSchema),
    defaultValues: {
      code: "",
      name: "",
      description: "",
      priceCents: 0,
      currency: "USD",
      interval: "month",
      maxSdks: 10,
      maxKeys: 50,
      maxUsers: 5,
      isActive: true,
      sortOrder: 0,
    },
  });

  const createPlanMutation = useMutation({
    mutationFn: async (data: PlanFormData) => {
      const planData = {
        code: data.code,
        name: data.name,
        description: data.description || "",
        priceCents: data.priceCents,
        currency: data.currency,
        interval: data.interval,
        limits: {
          maxSdks: data.maxSdks || null,
          maxKeys: data.maxKeys || null,
          maxUsers: data.maxUsers || null,
        },
        features: {},
        isActive: data.isActive,
        sortOrder: data.sortOrder,
      };
      return await apiRequest('POST', `/api/admin/plans`, planData);
    },
    onSuccess: () => {
      toast({
        title: "Success",
        description: "Subscription plan created successfully!",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/plans"] });
      setIsCreateDialogOpen(false);
      createForm.reset();
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to create plan. Please try again.",
        variant: "destructive",
      });
    },
  });

  const updatePlanMutation = useMutation({
    mutationFn: async ({ planId, data }: { planId: string; data: PlanFormData }) => {
      const planData = {
        code: data.code,
        name: data.name,
        description: data.description || "",
        priceCents: data.priceCents,
        currency: data.currency,
        interval: data.interval,
        limits: {
          maxSdks: data.maxSdks || null,
          maxKeys: data.maxKeys || null,
          maxUsers: data.maxUsers || null,
        },
        features: {},
        isActive: data.isActive,
        sortOrder: data.sortOrder,
      };
      return await apiRequest('PUT', `/api/admin/plans/${planId}`, planData);
    },
    onSuccess: () => {
      toast({
        title: "Success",
        description: "Subscription plan updated successfully!",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/plans"] });
      setIsEditDialogOpen(false);
      editForm.reset();
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to update plan. Please try again.",
        variant: "destructive",
      });
    },
  });

  const deactivatePlanMutation = useMutation({
    mutationFn: async (planId: string) => {
      return await apiRequest('DELETE', `/api/admin/plans/${planId}`);
    },
    onSuccess: () => {
      toast({
        title: "Success",
        description: "Subscription plan deactivated successfully!",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/plans"] });
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to deactivate plan. Please try again.",
        variant: "destructive",
      });
    },
  });

  const onCreateSubmit = (data: PlanFormData) => {
    createPlanMutation.mutate(data);
  };

  const onEditSubmit = (data: PlanFormData) => {
    if (selectedPlan) {
      updatePlanMutation.mutate({ planId: selectedPlan.id, data });
    }
  };

  const handleEditPlan = (plan: any) => {
    setSelectedPlan(plan);
    editForm.reset({
      code: plan.code,
      name: plan.name,
      description: plan.description || "",
      priceCents: plan.priceCents,
      currency: plan.currency,
      interval: plan.interval,
      maxSdks: plan.limits?.maxSdks || undefined,
      maxKeys: plan.limits?.maxKeys || undefined,
      maxUsers: plan.limits?.maxUsers || undefined,
      isActive: plan.isActive,
      sortOrder: plan.sortOrder,
    });
    setIsEditDialogOpen(true);
  };

  const handleDeactivatePlan = (planId: string) => {
    if (confirm("Are you sure you want to deactivate this plan? Existing subscriptions will continue, but new customers won't be able to select it.")) {
      deactivatePlanMutation.mutate(planId);
    }
  };

  const formatPrice = (cents: number, currency: string) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: currency || 'USD',
    }).format(cents / 100);
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto"></div>
          <p className="mt-4 text-muted-foreground">Loading subscription plans...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold" data-testid="heading-package-management">Package Management</h1>
          <p className="text-muted-foreground mt-2">
            Manage subscription plans and pricing for your platform
          </p>
        </div>
        <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
          <DialogTrigger asChild>
            <Button data-testid="button-create-plan">
              <Plus className="mr-2 h-4 w-4" />
              Create Plan
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Create New Subscription Plan</DialogTitle>
            </DialogHeader>
            <Form {...createForm}>
              <form onSubmit={createForm.handleSubmit(onCreateSubmit)} className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <FormField
                    control={createForm.control}
                    name="code"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Plan Code</FormLabel>
                        <FormControl>
                          <Input placeholder="starter" {...field} data-testid="input-plan-code" />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={createForm.control}
                    name="name"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Plan Name</FormLabel>
                        <FormControl>
                          <Input placeholder="Starter Plan" {...field} data-testid="input-plan-name" />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>

                <FormField
                  control={createForm.control}
                  name="description"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Description</FormLabel>
                      <FormControl>
                        <Textarea 
                          placeholder="Perfect for small teams..." 
                          {...field} 
                          data-testid="input-plan-description"
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <div className="grid grid-cols-3 gap-4">
                  <FormField
                    control={createForm.control}
                    name="priceCents"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Price (cents)</FormLabel>
                        <FormControl>
                          <Input 
                            type="number" 
                            placeholder="4900" 
                            {...field}
                            onChange={(e) => field.onChange(parseInt(e.target.value) || 0)}
                            data-testid="input-plan-price"
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={createForm.control}
                    name="currency"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Currency</FormLabel>
                        <FormControl>
                          <Input placeholder="USD" {...field} data-testid="input-plan-currency" />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={createForm.control}
                    name="interval"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Billing Interval</FormLabel>
                        <Select onValueChange={field.onChange} defaultValue={field.value}>
                          <FormControl>
                            <SelectTrigger data-testid="select-plan-interval">
                              <SelectValue placeholder="Select interval" />
                            </SelectTrigger>
                          </FormControl>
                          <SelectContent>
                            <SelectItem value="month">Monthly</SelectItem>
                            <SelectItem value="year">Yearly</SelectItem>
                            <SelectItem value="week">Weekly</SelectItem>
                          </SelectContent>
                        </Select>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>

                <div className="space-y-2">
                  <h3 className="font-medium">Plan Limits</h3>
                  <div className="grid grid-cols-3 gap-4">
                    <FormField
                      control={createForm.control}
                      name="maxSdks"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Max SDKs</FormLabel>
                          <FormControl>
                            <Input 
                              type="number" 
                              placeholder="10" 
                              {...field}
                              onChange={(e) => field.onChange(parseInt(e.target.value) || undefined)}
                              data-testid="input-plan-max-sdks"
                            />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                    <FormField
                      control={createForm.control}
                      name="maxKeys"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Max Keys</FormLabel>
                          <FormControl>
                            <Input 
                              type="number" 
                              placeholder="50" 
                              {...field}
                              onChange={(e) => field.onChange(parseInt(e.target.value) || undefined)}
                              data-testid="input-plan-max-keys"
                            />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                    <FormField
                      control={createForm.control}
                      name="maxUsers"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Max Users</FormLabel>
                          <FormControl>
                            <Input 
                              type="number" 
                              placeholder="5" 
                              {...field}
                              onChange={(e) => field.onChange(parseInt(e.target.value) || undefined)}
                              data-testid="input-plan-max-users"
                            />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <FormField
                    control={createForm.control}
                    name="sortOrder"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Sort Order</FormLabel>
                        <FormControl>
                          <Input 
                            type="number" 
                            placeholder="0" 
                            {...field}
                            onChange={(e) => field.onChange(parseInt(e.target.value) || 0)}
                            data-testid="input-plan-sort-order"
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={createForm.control}
                    name="isActive"
                    render={({ field }) => (
                      <FormItem className="flex items-center justify-between rounded-lg border p-4">
                        <div className="space-y-0.5">
                          <FormLabel>Active Plan</FormLabel>
                          <div className="text-sm text-muted-foreground">
                            Available for new subscriptions
                          </div>
                        </div>
                        <FormControl>
                          <Switch
                            checked={field.value}
                            onCheckedChange={field.onChange}
                            data-testid="switch-plan-active"
                          />
                        </FormControl>
                      </FormItem>
                    )}
                  />
                </div>

                <div className="flex justify-end gap-2">
                  <Button 
                    type="button" 
                    variant="outline" 
                    onClick={() => setIsCreateDialogOpen(false)}
                    data-testid="button-cancel-create"
                  >
                    Cancel
                  </Button>
                  <Button 
                    type="submit" 
                    disabled={createPlanMutation.isPending}
                    data-testid="button-submit-create"
                  >
                    {createPlanMutation.isPending ? "Creating..." : "Create Plan"}
                  </Button>
                </div>
              </form>
            </Form>
          </DialogContent>
        </Dialog>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Package className="h-5 w-5" />
            Subscription Plans
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Plan</TableHead>
                <TableHead>Price</TableHead>
                <TableHead>Interval</TableHead>
                <TableHead>Limits</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Sort</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {plans.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                    No subscription plans found. Create your first plan to get started.
                  </TableCell>
                </TableRow>
              ) : (
                plans.map((plan) => (
                  <TableRow key={plan.id} data-testid={`row-plan-${plan.id}`}>
                    <TableCell>
                      <div>
                        <div className="font-medium" data-testid={`text-plan-name-${plan.id}`}>
                          {plan.name}
                        </div>
                        <div className="text-sm text-muted-foreground" data-testid={`text-plan-code-${plan.id}`}>
                          {plan.code}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell data-testid={`text-plan-price-${plan.id}`}>
                      <div className="flex items-center gap-1">
                        <DollarSign className="h-4 w-4" />
                        {formatPrice(plan.priceCents, plan.currency)}
                      </div>
                    </TableCell>
                    <TableCell data-testid={`text-plan-interval-${plan.id}`}>
                      {plan.interval}
                    </TableCell>
                    <TableCell>
                      <div className="space-y-1 text-sm">
                        {plan.limits?.maxSdks && (
                          <div data-testid={`text-plan-limit-sdks-${plan.id}`}>
                            SDKs: {plan.limits.maxSdks}
                          </div>
                        )}
                        {plan.limits?.maxKeys && (
                          <div data-testid={`text-plan-limit-keys-${plan.id}`}>
                            Keys: {plan.limits.maxKeys}
                          </div>
                        )}
                        {plan.limits?.maxUsers && (
                          <div data-testid={`text-plan-limit-users-${plan.id}`}>
                            Users: {plan.limits.maxUsers}
                          </div>
                        )}
                        {(!plan.limits?.maxSdks && !plan.limits?.maxKeys && !plan.limits?.maxUsers) && (
                          <span className="text-muted-foreground">No limits</span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell data-testid={`badge-plan-status-${plan.id}`}>
                      <Badge variant={plan.isActive ? "default" : "secondary"}>
                        {plan.isActive ? "Active" : "Inactive"}
                      </Badge>
                    </TableCell>
                    <TableCell data-testid={`text-plan-sort-${plan.id}`}>
                      {plan.sortOrder}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleEditPlan(plan)}
                          data-testid={`button-edit-plan-${plan.id}`}
                        >
                          <Edit className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="destructive"
                          size="sm"
                          onClick={() => handleDeactivatePlan(plan.id)}
                          disabled={!plan.isActive}
                          data-testid={`button-deactivate-plan-${plan.id}`}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Dialog open={isEditDialogOpen} onOpenChange={setIsEditDialogOpen}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Edit Subscription Plan</DialogTitle>
          </DialogHeader>
          <Form {...editForm}>
            <form onSubmit={editForm.handleSubmit(onEditSubmit)} className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <FormField
                  control={editForm.control}
                  name="code"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Plan Code</FormLabel>
                      <FormControl>
                        <Input placeholder="starter" {...field} data-testid="input-edit-plan-code" />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={editForm.control}
                  name="name"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Plan Name</FormLabel>
                      <FormControl>
                        <Input placeholder="Starter Plan" {...field} data-testid="input-edit-plan-name" />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              <FormField
                control={editForm.control}
                name="description"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Description</FormLabel>
                    <FormControl>
                      <Textarea 
                        placeholder="Perfect for small teams..." 
                        {...field} 
                        data-testid="input-edit-plan-description"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <div className="grid grid-cols-3 gap-4">
                <FormField
                  control={editForm.control}
                  name="priceCents"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Price (cents)</FormLabel>
                      <FormControl>
                        <Input 
                          type="number" 
                          placeholder="4900" 
                          {...field}
                          onChange={(e) => field.onChange(parseInt(e.target.value) || 0)}
                          data-testid="input-edit-plan-price"
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={editForm.control}
                  name="currency"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Currency</FormLabel>
                      <FormControl>
                        <Input placeholder="USD" {...field} data-testid="input-edit-plan-currency" />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={editForm.control}
                  name="interval"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Billing Interval</FormLabel>
                      <Select onValueChange={field.onChange} value={field.value}>
                        <FormControl>
                          <SelectTrigger data-testid="select-edit-plan-interval">
                            <SelectValue placeholder="Select interval" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="month">Monthly</SelectItem>
                          <SelectItem value="year">Yearly</SelectItem>
                          <SelectItem value="week">Weekly</SelectItem>
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              <div className="space-y-2">
                <h3 className="font-medium">Plan Limits</h3>
                <div className="grid grid-cols-3 gap-4">
                  <FormField
                    control={editForm.control}
                    name="maxSdks"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Max SDKs</FormLabel>
                        <FormControl>
                          <Input 
                            type="number" 
                            placeholder="10" 
                            {...field}
                            onChange={(e) => field.onChange(parseInt(e.target.value) || undefined)}
                            data-testid="input-edit-plan-max-sdks"
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={editForm.control}
                    name="maxKeys"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Max Keys</FormLabel>
                        <FormControl>
                          <Input 
                            type="number" 
                            placeholder="50" 
                            {...field}
                            onChange={(e) => field.onChange(parseInt(e.target.value) || undefined)}
                            data-testid="input-edit-plan-max-keys"
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={editForm.control}
                    name="maxUsers"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Max Users</FormLabel>
                        <FormControl>
                          <Input 
                            type="number" 
                            placeholder="5" 
                            {...field}
                            onChange={(e) => field.onChange(parseInt(e.target.value) || undefined)}
                            data-testid="input-edit-plan-max-users"
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <FormField
                  control={editForm.control}
                  name="sortOrder"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Sort Order</FormLabel>
                      <FormControl>
                        <Input 
                          type="number" 
                          placeholder="0" 
                          {...field}
                          onChange={(e) => field.onChange(parseInt(e.target.value) || 0)}
                          data-testid="input-edit-plan-sort-order"
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={editForm.control}
                  name="isActive"
                  render={({ field }) => (
                    <FormItem className="flex items-center justify-between rounded-lg border p-4">
                      <div className="space-y-0.5">
                        <FormLabel>Active Plan</FormLabel>
                        <div className="text-sm text-muted-foreground">
                          Available for new subscriptions
                        </div>
                      </div>
                      <FormControl>
                        <Switch
                          checked={field.value}
                          onCheckedChange={field.onChange}
                          data-testid="switch-edit-plan-active"
                        />
                      </FormControl>
                    </FormItem>
                  )}
                />
              </div>

              <div className="flex justify-end gap-2">
                <Button 
                  type="button" 
                  variant="outline" 
                  onClick={() => setIsEditDialogOpen(false)}
                  data-testid="button-cancel-edit"
                >
                  Cancel
                </Button>
                <Button 
                  type="submit" 
                  disabled={updatePlanMutation.isPending}
                  data-testid="button-submit-edit"
                >
                  {updatePlanMutation.isPending ? "Updating..." : "Update Plan"}
                </Button>
              </div>
            </form>
          </Form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
