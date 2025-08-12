import { useLocation } from "wouter";
import { Bell } from "lucide-react";
import { Badge } from "@/components/ui/badge";

const pageInfo = {
  "/": { title: "Dashboard", subtitle: "Monitor your encryption infrastructure" },
  "/wizard": { title: "SDK Wizard", subtitle: "Create custom encryption SDKs" },
  "/monitoring": { title: "Security Monitoring", subtitle: "Real-time threat detection and response" },
  "/keys": { title: "Key Management", subtitle: "Manage encryption keys and certificates" },
  "/users": { title: "User Management", subtitle: "Manage users and permissions" },
  "/subscription": { title: "Subscription", subtitle: "Manage your billing and usage" },
  "/settings": { title: "Settings", subtitle: "Configure system preferences" },
};

export default function Header() {
  const [location] = useLocation();
  const info = pageInfo[location as keyof typeof pageInfo] || pageInfo["/"];

  return (
    <header className="bg-slate-800 border-b border-slate-700 px-6 py-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white" data-testid="text-page-title">
            {info.title}
          </h2>
          <p className="text-slate-400" data-testid="text-page-subtitle">
            {info.subtitle}
          </p>
        </div>
        <div className="flex items-center space-x-4">
          {/* Security Status */}
          <div className="flex items-center space-x-2 px-3 py-1 bg-green-500 bg-opacity-20 rounded-full">
            <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
            <span className="text-green-500 text-sm font-medium">Secure</span>
          </div>
          
          {/* Notifications */}
          <button className="relative p-2 text-slate-400 hover:text-white" data-testid="button-notifications">
            <Bell className="w-5 h-5" />
            <Badge className="absolute -top-1 -right-1 w-5 h-5 p-0 flex items-center justify-center bg-red-500 text-white text-xs">
              3
            </Badge>
          </button>
        </div>
      </div>
    </header>
  );
}
