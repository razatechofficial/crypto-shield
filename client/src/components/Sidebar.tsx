import { Link, useLocation } from "wouter";
import { useAuth } from "@/hooks/useAuth";
import { 
  BarChart3, 
  Wand2, 
  Eye, 
  Key, 
  Users, 
  CreditCard, 
  Settings, 
  Shield,
  LogOut,
  Package,
  Zap,
  TrendingUp
} from "lucide-react";
import { cn } from "@/lib/utils";

const navigation = [
  { name: "Dashboard", href: "/", icon: BarChart3 },
  { name: "SDK Wizard", href: "/wizard", icon: Wand2 },
  { name: "SDK Management", href: "/sdks", icon: Package },
  { name: "Monitoring", href: "/monitoring", icon: Eye },
  { name: "Key Management", href: "/keys", icon: Key },
  { name: "Quantum Security", href: "/quantum", icon: Zap },
  { name: "Advanced Analytics", href: "/analytics", icon: TrendingUp },
  { name: "User Management", href: "/users", icon: Users },
  { name: "Subscription", href: "/subscription", icon: CreditCard },
  { name: "Settings", href: "/settings", icon: Settings },
];

export default function Sidebar() {
  const [location] = useLocation();
  const { user } = useAuth();

  return (
    <div className="w-64 bg-background border-r border-border flex flex-col">
      {/* Logo */}
      <div className="p-6 border-b border-border">
        <div className="flex flex-col items-center text-center space-y-2">
          <img 
            src="/averox-logo.png" 
            alt="Averox Logo" 
            className="w-16 h-16 object-contain"
          />
          <p className="text-sm font-medium text-muted-foreground">Enterprise Encryption</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-4 py-6 space-y-2">
        {navigation.map((item) => {
          const Icon = item.icon;
          const isActive = location === item.href;
          
          return (
            <Link key={item.name} href={item.href}>
              <div
                className={cn(
                  "flex items-center space-x-3 px-3 py-2 rounded-lg transition-colors cursor-pointer",
                  isActive
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:bg-secondary hover:text-foreground"
                )}
                data-testid={`nav-${item.name.toLowerCase().replace(/\s+/g, '-')}`}
              >
                <Icon className="w-5 h-5" />
                <span>{item.name}</span>
              </div>
            </Link>
          );
        })}
      </nav>

      {/* User Profile */}
      <div className="p-4 border-t border-border">
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 bg-primary rounded-full flex items-center justify-center">
            <span className="text-primary-foreground text-sm font-medium">
              {user?.firstName?.[0] || user?.email?.[0]?.toUpperCase() || 'U'}
            </span>
          </div>
          <div className="flex-1">
            <p className="text-sm font-medium text-foreground" data-testid="text-user-name">
              {user?.firstName ? `${user.firstName} ${user?.lastName || ''}` : user?.email}
            </p>
            <p className="text-xs text-muted-foreground" data-testid="text-user-role">
              {user?.role || 'User'}
            </p>
          </div>
          <button 
            className="text-muted-foreground hover:text-foreground"
            onClick={() => window.location.href = '/api/logout'}
            data-testid="button-logout"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
