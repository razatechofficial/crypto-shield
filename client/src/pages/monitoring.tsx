import { useQuery } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import SecurityChart from "@/components/SecurityChart";
import { AlertTriangle, CheckCircle, Shield, Activity } from "lucide-react";
import { formatDistanceToNow } from "date-fns";

export default function Monitoring() {
  const { toast } = useToast();

  const { data: events = [], isLoading: eventsLoading } = useQuery({
    queryKey: ["/api/monitoring/events"],
    retry: false,
  });

  // Mock monitoring data - in real app this would come from API
  const monitoringData = {
    labels: Array.from({length: 24}, (_, i) => `${i}:00`),
    datasets: [
      {
        label: 'Encryption Requests',
        data: Array.from({length: 24}, () => Math.floor(Math.random() * 1000) + 500),
        borderColor: '#3B82F6',
        backgroundColor: 'rgba(59, 130, 246, 0.1)',
        tension: 0.4
      },
      {
        label: 'Threat Detections',
        data: Array.from({length: 24}, () => Math.floor(Math.random() * 50)),
        borderColor: '#EF4444',
        backgroundColor: 'rgba(239, 68, 68, 0.1)',
        tension: 0.4
      }
    ]
  };

  const getEventIcon = (eventType: string) => {
    switch (eventType) {
      case 'threat_detected':
        return <AlertTriangle className="w-4 h-4" />;
      case 'key_rotated':
        return <Shield className="w-4 h-4" />;
      default:
        return <Activity className="w-4 h-4" />;
    }
  };

  const getEventColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-500';
      case 'high':
        return 'bg-orange-500';
      case 'medium':
        return 'bg-yellow-500';
      case 'low':
        return 'bg-blue-500';
      default:
        return 'bg-gray-500';
    }
  };

  return (
    <div className="p-6">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        {/* Real-time Threats */}
        <Card className="bg-card border-border">
          <CardHeader>
            <CardTitle className="text-foreground">Real-time Threats</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex items-center justify-between p-3 bg-red-500 bg-opacity-10 border border-red-500 border-opacity-20 rounded-lg">
                <div>
                  <p className="text-foreground font-medium">Brute Force Attack</p>
                  <p className="text-muted-foreground text-sm">IP: 203.0.113.45</p>
                </div>
                <Badge className="bg-red-500 text-white">BLOCKED</Badge>
              </div>
              <div className="flex items-center justify-between p-3 bg-yellow-500 bg-opacity-10 border border-yellow-500 border-opacity-20 rounded-lg">
                <div>
                  <p className="text-foreground font-medium">Key Compromise Attempt</p>
                  <p className="text-muted-foreground text-sm">Tenant: startup-inc</p>
                </div>
                <Badge className="bg-yellow-500 text-white">MITIGATED</Badge>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* System Health */}
        <Card className="bg-card border-border">
          <CardHeader>
            <CardTitle className="text-foreground">System Health</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-muted-foreground">Encryption Performance</span>
                  <span className="text-green-500">98.7%</span>
                </div>
                <Progress value={98.7} className="h-2" />
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-muted-foreground">Key Infrastructure</span>
                  <span className="text-green-500">99.9%</span>
                </div>
                <Progress value={99.9} className="h-2" />
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-muted-foreground">Auto-healing</span>
                  <span className="text-blue-500">100%</span>
                </div>
                <Progress value={100} className="h-2" />
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Compliance Status */}
        <Card className="bg-card border-border">
          <CardHeader>
            <CardTitle className="text-foreground">Compliance Status</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-foreground">FIPS 140-2 Level 3</span>
                <CheckCircle className="w-5 h-5 text-green-500" />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-foreground">Common Criteria EAL4+</span>
                <CheckCircle className="w-5 h-5 text-green-500" />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-foreground">ISO 27001</span>
                <CheckCircle className="w-5 h-5 text-green-500" />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-300">SOC 2 Type II</span>
                <CheckCircle className="w-5 h-5 text-green-500" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Detailed Monitoring Chart */}
      <div className="mb-8">
        <SecurityChart
          type="line"
          title="Security Monitoring Dashboard"
          data={monitoringData}
          options={{ 
            responsive: true,
            maintainAspectRatio: false,
            scales: {
              y: {
                beginAtZero: true,
                ticks: { color: '#94A3B8' },
                grid: { color: '#334155' }
              },
              x: {
                ticks: { color: '#94A3B8' },
                grid: { color: '#334155' }
              }
            }
          }}
        />
      </div>

      {/* Security Events */}
      <Card className="bg-slate-800 border-slate-700">
        <CardHeader>
          <CardTitle className="text-white">Security Events</CardTitle>
        </CardHeader>
        <CardContent>
          {eventsLoading ? (
            <div className="space-y-4">
              {[1, 2, 3].map((i) => (
                <div key={i} className="flex items-center space-x-4 p-3 bg-slate-700 rounded-lg animate-pulse">
                  <div className="w-8 h-8 bg-slate-600 rounded-lg"></div>
                  <div className="flex-1">
                    <div className="h-4 bg-slate-600 rounded w-3/4 mb-2"></div>
                    <div className="h-3 bg-slate-600 rounded w-1/2"></div>
                  </div>
                  <div className="h-3 bg-slate-600 rounded w-20"></div>
                </div>
              ))}
            </div>
          ) : events?.length ? (
            <div className="space-y-4">
              {events.map((event: any) => (
                <div key={event.id} className="flex items-center space-x-4 p-3 bg-slate-700 rounded-lg">
                  <div className={`w-8 h-8 ${getEventColor(event.severity)} bg-opacity-20 rounded-lg flex items-center justify-center`}>
                    {getEventIcon(event.eventType)}
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center space-x-2">
                      <p className="text-white font-medium" data-testid={`event-type-${event.id}`}>
                        {event.eventType.replace('_', ' ').toUpperCase()}
                      </p>
                      <Badge className={`${getEventColor(event.severity)} text-white text-xs`}>
                        {event.severity.toUpperCase()}
                      </Badge>
                    </div>
                    <p className="text-slate-400 text-sm" data-testid={`event-description-${event.id}`}>
                      {event.description}
                    </p>
                  </div>
                  <span className="text-slate-400 text-sm" data-testid={`event-time-${event.id}`}>
                    {formatDistanceToNow(new Date(event.createdAt), { addSuffix: true })}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8">
              <p className="text-slate-400">No security events</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
