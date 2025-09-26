import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { Save, Shield, Key, Bell, Palette, BookOpen, Download, ExternalLink } from "lucide-react";

export default function Settings() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  
  // Local state for settings
  const [autoKeyRotation, setAutoKeyRotation] = useState(true);
  const [threatDetection, setThreatDetection] = useState(true);
  const [emailNotifications, setEmailNotifications] = useState(true);
  const [browserNotifications, setBrowserNotifications] = useState(false);
  const [defaultAlgorithm, setDefaultAlgorithm] = useState('aes-256-gcm');
  const [keyRotationInterval, setKeyRotationInterval] = useState('30');
  const [sessionTimeout, setSessionTimeout] = useState('8');
  const [maxFailedAttempts, setMaxFailedAttempts] = useState('5');

  const { data: algorithms = [] } = useQuery({
    queryKey: ["/api/algorithms"],
    retry: false,
  });

  const { data: apiKeyData, isLoading: apiKeyLoading } = useQuery({
    queryKey: ["/api/tenant/api-key"],
    retry: false,
  });

  const regenerateApiKeyMutation = useMutation({
    mutationFn: async () => {
      return await apiRequest('POST', '/api/tenant/api-key/regenerate', {});
    },
    onSuccess: (data: any) => {
      toast({
        title: "Success",
        description: "API key regenerated successfully! Please update your applications with the new key.",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/tenant/api-key"] });
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
        description: "Failed to regenerate API key. Please try again.",
        variant: "destructive",
      });
    },
  });

  const handleRegenerateApiKey = () => {
    regenerateApiKeyMutation.mutate();
  };

  const saveSettingsMutation = useMutation({
    mutationFn: async (settings: any) => {
      return await apiRequest('PUT', '/api/settings', settings);
    },
    onSuccess: () => {
      toast({
        title: "Success",
        description: "Settings saved successfully!",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/settings"] });
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
        description: "Failed to save settings. Please try again.",
        variant: "destructive",
      });
    },
  });

  const handleSaveSettings = () => {
    const settings = {
      security: {
        autoKeyRotation,
        threatDetection,
        defaultAlgorithm,
        keyRotationInterval: parseInt(keyRotationInterval),
        sessionTimeout: parseInt(sessionTimeout),
        maxFailedAttempts: parseInt(maxFailedAttempts),
      },
      notifications: {
        email: emailNotifications,
        browser: browserNotifications,
      },
    };

    saveSettingsMutation.mutate(settings);
  };

  return (
    <div className="p-6">
      <div className="max-w-4xl">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-2xl font-bold text-white">Settings</h3>
          <Button 
            onClick={handleSaveSettings}
            disabled={saveSettingsMutation.isPending}
            className="bg-blue-500 hover:bg-blue-600 text-white"
            data-testid="button-save-settings"
          >
            <Save className="w-4 h-4 mr-2" />
            {saveSettingsMutation.isPending ? 'Saving...' : 'Save Changes'}
          </Button>
        </div>
        
        <div className="space-y-6">
          {/* Security Settings */}
          <Card className="bg-slate-800 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white flex items-center">
                <Shield className="w-5 h-5 mr-2" />
                Security Settings
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <Label className="text-white font-medium">Auto Key Rotation</Label>
                  <p className="text-slate-400 text-sm">Automatically rotate encryption keys at specified intervals</p>
                </div>
                <Switch
                  checked={autoKeyRotation}
                  onCheckedChange={setAutoKeyRotation}
                  data-testid="switch-auto-key-rotation"
                />
              </div>

              <Separator className="bg-slate-700" />

              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <Label className="text-white font-medium">Threat Detection</Label>
                  <p className="text-slate-400 text-sm">Real-time monitoring for security threats and anomalies</p>
                </div>
                <Switch
                  checked={threatDetection}
                  onCheckedChange={setThreatDetection}
                  data-testid="switch-threat-detection"
                />
              </div>

              <Separator className="bg-slate-700" />

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-2">
                  <Label className="text-white font-medium">Default Encryption Algorithm</Label>
                  <Select value={defaultAlgorithm} onValueChange={setDefaultAlgorithm}>
                    <SelectTrigger className="bg-slate-700 border-slate-600 text-white" data-testid="select-default-algorithm">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {(algorithms as any[])?.map((algorithm: any) => (
                        <SelectItem key={algorithm.id} value={algorithm.name.toLowerCase()}>
                          {algorithm.displayName}
                        </SelectItem>
                      )) || [
                        <SelectItem key="aes-256-gcm" value="aes-256-gcm">AES-256-GCM</SelectItem>,
                        <SelectItem key="chacha20-poly1305" value="chacha20-poly1305">ChaCha20-Poly1305</SelectItem>,
                        <SelectItem key="kyber-1024" value="kyber-1024">Kyber-1024</SelectItem>
                      ]}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label className="text-white font-medium">Key Rotation Interval (days)</Label>
                  <Select value={keyRotationInterval} onValueChange={setKeyRotationInterval}>
                    <SelectTrigger className="bg-slate-700 border-slate-600 text-white" data-testid="select-rotation-interval">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="7">7 days</SelectItem>
                      <SelectItem value="30">30 days</SelectItem>
                      <SelectItem value="90">90 days</SelectItem>
                      <SelectItem value="manual">Manual</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-2">
                  <Label className="text-white font-medium">Session Timeout (hours)</Label>
                  <Input
                    type="number"
                    value={sessionTimeout}
                    onChange={(e) => setSessionTimeout(e.target.value)}
                    min="1"
                    max="24"
                    className="bg-slate-700 border-slate-600 text-white"
                    data-testid="input-session-timeout"
                  />
                </div>

                <div className="space-y-2">
                  <Label className="text-white font-medium">Max Failed Login Attempts</Label>
                  <Input
                    type="number"
                    value={maxFailedAttempts}
                    onChange={(e) => setMaxFailedAttempts(e.target.value)}
                    min="3"
                    max="10"
                    className="bg-slate-700 border-slate-600 text-white"
                    data-testid="input-max-failed-attempts"
                  />
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Notification Settings */}
          <Card className="bg-slate-800 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white flex items-center">
                <Bell className="w-5 h-5 mr-2" />
                Notification Settings
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <Label className="text-white font-medium">Email Notifications</Label>
                  <p className="text-slate-400 text-sm">Receive security alerts and system updates via email</p>
                </div>
                <Switch
                  checked={emailNotifications}
                  onCheckedChange={setEmailNotifications}
                  data-testid="switch-email-notifications"
                />
              </div>

              <Separator className="bg-slate-700" />

              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <Label className="text-white font-medium">Browser Notifications</Label>
                  <p className="text-slate-400 text-sm">Show real-time alerts in your browser</p>
                </div>
                <Switch
                  checked={browserNotifications}
                  onCheckedChange={setBrowserNotifications}
                  data-testid="switch-browser-notifications"
                />
              </div>
            </CardContent>
          </Card>

          {/* API & Integration Settings */}
          <Card className="bg-slate-800 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white flex items-center">
                <Key className="w-5 h-5 mr-2" />
                API & Integration
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-2">
                <Label className="text-white font-medium">API Key</Label>
                <div className="flex space-x-2">
                  <Input
                    type="password"
                    value={apiKeyLoading ? "Loading..." : ((apiKeyData as any)?.fullApiKey || "No API key found")}
                    readOnly
                    className="bg-slate-700 border-slate-600 text-white font-mono"
                    data-testid="input-api-key"
                  />
                  <Button 
                    variant="outline" 
                    className="border-slate-600 text-slate-300 hover:bg-slate-700"
                    onClick={handleRegenerateApiKey}
                    disabled={regenerateApiKeyMutation.isPending}
                    data-testid="button-regenerate-api-key"
                  >
                    {regenerateApiKeyMutation.isPending ? 'Regenerating...' : 'Regenerate'}
                  </Button>
                </div>
                <p className="text-slate-400 text-sm">Use this API key to authenticate requests to the Averox API</p>
              </div>

              <Separator className="bg-slate-700" />

              <div className="space-y-2">
                <Label className="text-white font-medium">Webhook URL</Label>
                <Input
                  type="url"
                  placeholder="https://your-app.com/webhooks/averox"
                  className="bg-slate-700 border-slate-600 text-white"
                  data-testid="input-webhook-url"
                />
                <p className="text-slate-400 text-sm">Receive real-time security events at this endpoint</p>
              </div>

              <div className="space-y-2">
                <Label className="text-white font-medium">Allowed Origins</Label>
                <Input
                  type="text"
                  placeholder="https://yourdomain.com, https://app.yourdomain.com"
                  className="bg-slate-700 border-slate-600 text-white"
                  data-testid="input-allowed-origins"
                />
                <p className="text-slate-400 text-sm">Comma-separated list of allowed CORS origins</p>
              </div>
            </CardContent>
          </Card>

          {/* Documentation & Training */}
          <Card className="bg-slate-800 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white flex items-center">
                <BookOpen className="w-5 h-5 mr-2" />
                Documentation & Training
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <Label className="text-white font-medium">SDK Installation Guides</Label>
                <p className="text-slate-400 text-sm">Comprehensive installation and deployment guides for all supported languages</p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <Button 
                    variant="outline" 
                    className="border-slate-600 text-slate-300 hover:bg-slate-700 justify-start"
                    data-testid="button-js-installation-guide"
                    onClick={() => window.open('/api/docs/javascript-installation-guide', '_blank')}
                  >
                    <Download className="w-4 h-4 mr-2" />
                    JavaScript/TypeScript Guide
                  </Button>
                  <Button 
                    variant="outline" 
                    className="border-slate-600 text-slate-300 hover:bg-slate-700 justify-start"
                    data-testid="button-python-installation-guide"
                    onClick={() => window.open('/api/docs/python-installation-guide', '_blank')}
                  >
                    <Download className="w-4 h-4 mr-2" />
                    Python Installation Guide
                  </Button>
                  <Button 
                    variant="outline" 
                    className="border-slate-600 text-slate-300 hover:bg-slate-700 justify-start"
                    data-testid="button-java-installation-guide"
                    onClick={() => window.open('/api/docs/java-installation-guide', '_blank')}
                  >
                    <Download className="w-4 h-4 mr-2" />
                    Java Installation Guide
                  </Button>
                  <Button 
                    variant="outline" 
                    className="border-slate-600 text-slate-300 hover:bg-slate-700 justify-start"
                    data-testid="button-c-installation-guide"
                    onClick={() => window.open('/api/docs/c-cpp-installation-guide', '_blank')}
                  >
                    <Download className="w-4 h-4 mr-2" />
                    C/C++ Installation Guide
                  </Button>
                </div>
              </div>

              <Separator className="bg-slate-700" />

              <div className="space-y-4">
                <Label className="text-white font-medium">Troubleshooting & Support</Label>
                <p className="text-slate-400 text-sm">Error resolution guides and debugging resources</p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <Button 
                    variant="outline" 
                    className="border-slate-600 text-slate-300 hover:bg-slate-700 justify-start"
                    data-testid="button-universal-troubleshooting"
                    onClick={() => window.open('/api/docs/universal-troubleshooting-guide', '_blank')}
                  >
                    <ExternalLink className="w-4 h-4 mr-2" />
                    Universal Troubleshooting
                  </Button>
                  <Button 
                    variant="outline" 
                    className="border-slate-600 text-slate-300 hover:bg-slate-700 justify-start"
                    data-testid="button-encryption-failure-guide"
                    onClick={() => window.open('/api/docs/encryption-failure-debugging', '_blank')}
                  >
                    <ExternalLink className="w-4 h-4 mr-2" />
                    Encryption Failure Guide
                  </Button>
                </div>
              </div>

              <Separator className="bg-slate-700" />

              <div className="space-y-4">
                <Label className="text-white font-medium">Platform-Specific Resources</Label>
                <p className="text-slate-400 text-sm">Installation guides for placeholder implementations</p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <Button 
                    variant="outline" 
                    className="border-slate-600 text-slate-300 hover:bg-slate-700 justify-start"
                    data-testid="button-csharp-installation-guide"
                    onClick={() => window.open('/api/docs/csharp-installation-guide', '_blank')}
                  >
                    <Download className="w-4 h-4 mr-2" />
                    C# Installation Guide
                  </Button>
                  <Button 
                    variant="outline" 
                    className="border-slate-600 text-slate-300 hover:bg-slate-700 justify-start"
                    data-testid="button-swift-installation-guide"
                    onClick={() => window.open('/api/docs/swift-installation-guide', '_blank')}
                  >
                    <Download className="w-4 h-4 mr-2" />
                    Swift Installation Guide
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Compliance & Auditing */}
          <Card className="bg-slate-800 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white flex items-center">
                <Palette className="w-5 h-5 mr-2" />
                Compliance & Auditing
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <Label className="text-white font-medium">Audit Logging</Label>
                  <p className="text-slate-400 text-sm">Log all security events and API access for compliance</p>
                </div>
                <Switch
                  checked={true}
                  disabled
                  data-testid="switch-audit-logging"
                />
              </div>

              <Separator className="bg-slate-700" />

              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <Label className="text-white font-medium">Data Retention</Label>
                  <p className="text-slate-400 text-sm">Automatically delete audit logs after specified period</p>
                </div>
                <Select defaultValue="365">
                  <SelectTrigger className="w-32 bg-slate-700 border-slate-600 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="90">90 days</SelectItem>
                    <SelectItem value="180">180 days</SelectItem>
                    <SelectItem value="365">1 year</SelectItem>
                    <SelectItem value="never">Never</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <Separator className="bg-slate-700" />

              <div className="space-y-4">
                <Label className="text-white font-medium">Compliance Reports</Label>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <Button 
                    variant="outline" 
                    className="border-slate-600 text-slate-300 hover:bg-slate-700"
                    data-testid="button-download-soc2-report"
                  >
                    Download SOC 2 Report
                  </Button>
                  <Button 
                    variant="outline" 
                    className="border-slate-600 text-slate-300 hover:bg-slate-700"
                    data-testid="button-download-iso27001-report"
                  >
                    Download ISO 27001 Report
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
