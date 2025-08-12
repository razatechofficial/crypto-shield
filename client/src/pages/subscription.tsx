import { useQuery } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { CheckCircle } from "lucide-react";

export default function Subscription() {
  const { toast } = useToast();

  const { data: tenant, isLoading } = useQuery({
    queryKey: ["/api/tenant"],
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
    <div className="p-6">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Current Plan */}
        <Card className="bg-slate-800 border-slate-700">
          <CardHeader>
            <CardTitle className="text-white">Current Plan</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-center">
              <h4 className="text-2xl font-bold text-blue-500 mb-2" data-testid="text-subscription-name">
                {subscription.name}
              </h4>
              <p className="text-3xl font-bold text-white mb-1" data-testid="text-subscription-price">
                {subscription.price}
                <span className="text-slate-400 text-lg">/month</span>
              </p>
              <p className="text-slate-400 text-sm mb-4">Billed annually</p>
              <div className="space-y-2 text-sm text-slate-300">
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
        <Card className="bg-slate-800 border-slate-700">
          <CardHeader>
            <CardTitle className="text-white">Usage This Month</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-slate-400">API Calls</span>
                  <span className="text-white" data-testid="text-api-calls">2.4M / Unlimited</span>
                </div>
                <Progress value={65} className="h-2" />
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-slate-400">Storage</span>
                  <span className="text-white" data-testid="text-storage">847GB / 1TB</span>
                </div>
                <Progress value={84} className="h-2" />
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-slate-400">Active Users</span>
                  <span className="text-white" data-testid="text-active-users">127 / Unlimited</span>
                </div>
                <Progress value={32} className="h-2" />
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Billing */}
        <Card className="bg-slate-800 border-slate-700">
          <CardHeader>
            <CardTitle className="text-white">Billing Information</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex justify-between">
                <span className="text-slate-400">Next billing</span>
                <span className="text-white" data-testid="text-next-billing">Feb 15, 2024</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Payment method</span>
                <span className="text-white" data-testid="text-payment-method">•••• 4242</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Amount</span>
                <span className="text-white" data-testid="text-amount">{subscription.price}.00</span>
              </div>
              <Button 
                className="w-full mt-4 bg-blue-500 hover:bg-blue-600 text-white"
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
        <h3 className="text-2xl font-bold text-white mb-6 text-center">Choose Your Plan</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Starter Plan */}
          <Card className="bg-slate-800 border-slate-700">
            <CardHeader>
              <div className="text-center">
                <h4 className="text-xl font-bold text-white">Starter</h4>
                <p className="text-3xl font-bold text-white mt-2">$49<span className="text-slate-400 text-lg">/month</span></p>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-3 mb-6">
                <p className="flex items-center text-slate-300">
                  <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                  Up to 5 SDKs
                </p>
                <p className="flex items-center text-slate-300">
                  <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                  Basic monitoring
                </p>
                <p className="flex items-center text-slate-300">
                  <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                  Email support
                </p>
                <p className="flex items-center text-slate-300">
                  <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                  Standard encryption
                </p>
              </div>
              <Button 
                className="w-full bg-slate-600 hover:bg-slate-500 text-white"
                variant={tenant?.subscriptionTier === 'starter' ? 'default' : 'outline'}
                data-testid="button-starter-plan"
              >
                {tenant?.subscriptionTier === 'starter' ? 'Current Plan' : 'Choose Starter'}
              </Button>
            </CardContent>
          </Card>

          {/* Professional Plan */}
          <Card className="bg-slate-800 border-blue-500 border-2">
            <CardHeader>
              <div className="text-center">
                <Badge className="bg-blue-500 text-white mb-2">Most Popular</Badge>
                <h4 className="text-xl font-bold text-white">Professional</h4>
                <p className="text-3xl font-bold text-white mt-2">$149<span className="text-slate-400 text-lg">/month</span></p>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-3 mb-6">
                <p className="flex items-center text-slate-300">
                  <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                  Up to 50 SDKs
                </p>
                <p className="flex items-center text-slate-300">
                  <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                  Advanced monitoring
                </p>
                <p className="flex items-center text-slate-300">
                  <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                  Priority support
                </p>
                <p className="flex items-center text-slate-300">
                  <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                  Quantum-safe encryption
                </p>
              </div>
              <Button 
                className="w-full bg-blue-500 hover:bg-blue-600 text-white"
                variant={tenant?.subscriptionTier === 'professional' ? 'default' : 'outline'}
                data-testid="button-professional-plan"
              >
                {tenant?.subscriptionTier === 'professional' ? 'Current Plan' : 'Choose Professional'}
              </Button>
            </CardContent>
          </Card>

          {/* Enterprise Plan */}
          <Card className="bg-slate-800 border-slate-700">
            <CardHeader>
              <div className="text-center">
                <h4 className="text-xl font-bold text-white">Enterprise</h4>
                <p className="text-3xl font-bold text-white mt-2">$299<span className="text-slate-400 text-lg">/month</span></p>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-3 mb-6">
                <p className="flex items-center text-slate-300">
                  <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                  Unlimited SDKs
                </p>
                <p className="flex items-center text-slate-300">
                  <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                  Real-time monitoring
                </p>
                <p className="flex items-center text-slate-300">
                  <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                  24/7 support
                </p>
                <p className="flex items-center text-slate-300">
                  <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                  Custom compliance
                </p>
              </div>
              <Button 
                className="w-full bg-slate-600 hover:bg-slate-500 text-white"
                variant={tenant?.subscriptionTier === 'enterprise' ? 'default' : 'outline'}
                data-testid="button-enterprise-plan"
              >
                {tenant?.subscriptionTier === 'enterprise' ? 'Current Plan' : 'Choose Enterprise'}
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
