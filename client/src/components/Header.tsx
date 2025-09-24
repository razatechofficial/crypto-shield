import { useLocation } from "wouter";
import { User, LogOut } from "lucide-react";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger, DropdownMenuSeparator } from "@/components/ui/dropdown-menu";
import { useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";
import NotificationDropdown from "./NotificationDropdown";

const pageInfo = {
  "/": { title: "Dashboard", subtitle: "Monitor your encryption infrastructure" },
  "/wizard": { title: "SDK Wizard", subtitle: "Create custom encryption SDKs" },
  "/monitoring": { title: "Security Monitoring", subtitle: "Real-time threat detection and response" },
  "/keys": { title: "Key Management", subtitle: "Manage encryption keys and certificates" },
  "/providers": { title: "Cloud Providers", subtitle: "Manage AWS KMS, Azure Key Vault, and GCP KMS configurations" },
  "/distributions": { title: "Key Distribution", subtitle: "Monitor multi-cloud key synchronization and replication" },
  "/users": { title: "User Management", subtitle: "Manage users and permissions" },
  "/subscription": { title: "Subscription", subtitle: "Manage your billing and usage" },
  "/settings": { title: "Settings", subtitle: "Configure system preferences" },
};

export default function Header() {
  const [location, setLocation] = useLocation();
  const info = pageInfo[location as keyof typeof pageInfo] || pageInfo["/"];
  const { toast } = useToast();
  const { user } = useAuth();

  const logoutMutation = useMutation({
    mutationFn: () => apiRequest('POST', '/api/logout', {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/auth/user"] });
      toast({
        title: "Logged out successfully",
        description: "You have been logged out of your account.",
      });
      setLocation("/login");
    },
    onError: (error: any) => {
      toast({
        title: "Logout failed",
        description: error.message || "Failed to logout. Please try again.",
        variant: "destructive",
      });
    },
  });

  return (
    <header className="bg-background border-b border-border px-6 py-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-foreground" data-testid="text-page-title">
            {info.title}
          </h2>
          <p className="text-muted-foreground" data-testid="text-page-subtitle">
            {info.subtitle}
          </p>
        </div>
        <div className="flex items-center space-x-4">
          {/* Security Status */}
          <div className="flex items-center space-x-2 px-3 py-1 bg-green-500 bg-opacity-10 border border-green-500/20 rounded-full">
            <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
            <span className="text-green-600 text-sm font-medium">Secure</span>
          </div>
          
          {/* Notifications */}
          <NotificationDropdown />

          {/* User Menu */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm" className="flex items-center space-x-2" data-testid="button-user-menu">
                <User className="w-4 h-4" />
                <span className="text-sm">{user?.email}</span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-48">
              <DropdownMenuItem disabled className="text-muted-foreground">
                <User className="w-4 h-4 mr-2" />
                {user?.email}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem 
                onClick={() => logoutMutation.mutate()}
                disabled={logoutMutation.isPending}
                className="text-red-600 focus:text-red-600"
                data-testid="button-logout"
              >
                <LogOut className="w-4 h-4 mr-2" />
                {logoutMutation.isPending ? "Logging out..." : "Logout"}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>
  );
}
