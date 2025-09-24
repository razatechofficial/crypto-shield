import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { useAuth } from "@/hooks/useAuth";
import Landing from "@/pages/landing";
import Login from "@/pages/Login";
import Register from "@/pages/Register";
import ForgotPassword from "@/pages/ForgotPassword";
import ResetPassword from "@/pages/ResetPassword";
import Layout from "@/components/Layout";
import Dashboard from "@/pages/dashboard";
import SdkWizard from "@/pages/sdk-wizard";
import SdkManagement from "@/pages/sdk-management";
import Monitoring from "@/pages/monitoring";
import KeyManagement from "@/pages/key-management";
import CloudProviders from "@/pages/cloud-providers";
import KeyDistribution from "@/pages/key-distribution";
import ProviderHealth from "@/pages/provider-health";
import BYOKImport from "@/pages/byok-import";
import KeyReplication from "@/pages/key-replication";
import UserManagement from "@/pages/user-management";
import Subscription from "@/pages/subscription";
import Settings from "@/pages/settings";
import QuantumSecurity from "@/pages/quantum-security";
import AdvancedAnalytics from "@/pages/advanced-analytics";
import NotFound from "@/pages/not-found";

function Router() {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center">
        <div className="text-white">Loading...</div>
      </div>
    );
  }

  return (
    <Switch>
      {!isAuthenticated ? (
        <>
          <Route path="/login" component={Login} />
          <Route path="/register" component={Register} />
          <Route path="/forgot-password" component={ForgotPassword} />
          <Route path="/reset-password" component={ResetPassword} />
          <Route path="/" component={Landing} />
        </>
      ) : (
        <Layout>
          <Route path="/" component={Dashboard} />
          <Route path="/wizard" component={SdkWizard} />
          <Route path="/sdks" component={SdkManagement} />
          <Route path="/monitoring" component={Monitoring} />
          <Route path="/keys" component={KeyManagement} />
          <Route path="/providers" component={CloudProviders} />
          <Route path="/distributions" component={KeyDistribution} />
          <Route path="/provider-health" component={ProviderHealth} />
          <Route path="/byok" component={BYOKImport} />
          <Route path="/replication" component={KeyReplication} />
          <Route path="/users" component={UserManagement} />
          <Route path="/subscription" component={Subscription} />
          <Route path="/quantum" component={QuantumSecurity} />
          <Route path="/analytics" component={AdvancedAnalytics} />
          <Route path="/settings" component={Settings} />
        </Layout>
      )}
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Router />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
