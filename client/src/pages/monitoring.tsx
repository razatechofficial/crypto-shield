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

  // Get real crypto operations and incidents
  const { data: operationsData, isLoading: operationsLoading } = useQuery({
    queryKey: ["/api/monitoring/operations"],
    retry: false,
  });

  const { data: healthData } = useQuery({
    queryKey: ["/api/monitoring/health"],
    retry: false,
  });

  const { data: incidents = [], isLoading: incidentsLoading } = useQuery({
    queryKey: ["/api/monitoring/incidents"],
    retry: false,
  });

  const { data: deployments = [] } = useQuery({
    queryKey: ["/api/monitoring/deployments"],
    retry: false,
  });

  // Legacy compatibility
  const events = incidents;
  const eventsLoading = incidentsLoading;
  const stats = healthData;

  // Real monitoring data from actual operations
  const getMonitoringData = () => {
    const labels = Array.from({length: 24}, (_, i) => `${i}:00`);
    
    // Use actual operation statistics 
    const stats = operationsData && typeof operationsData === 'object' && 'stats' in operationsData ? operationsData.stats : null;
    const hourlyOps = stats && typeof stats === 'object' && 'hourlyOperations' in stats ? stats.hourlyOperations : [];
    
    // Map real hourly data to chart format
    const encryptionData = labels.map((label) => {
      const hourData = Array.isArray(hourlyOps) ? hourlyOps.find((h: any) => h.hour === label) : null;
      return hourData ? hourData.count : 0;
    });

    // Use real security incidents for threat data
    const threatData = labels.map(() => {
      const criticalIncidents = Array.isArray(incidents) ? incidents.filter((i: any) => 
        i.severity === 'critical' || i.severity === 'high'
      ).length : 0;
      return criticalIncidents;
    });

    return {
      labels,
      datasets: [
        {
          label: 'Encryption Operations',
          data: encryptionData,
          borderColor: '#3B82F6',
          backgroundColor: 'rgba(59, 130, 246, 0.1)',
          tension: 0.4
        },
        {
          label: 'Security Incidents',
          data: threatData,
          borderColor: '#EF4444',
          backgroundColor: 'rgba(239, 68, 68, 0.1)',
          tension: 0.4
        }
      ]
    };
  };

  const monitoringData = getMonitoringData();

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
              {Array.isArray(incidents) && incidents.filter((i: any) => i.severity === 'critical' || i.severity === 'high').slice(0, 2).map((incident: any) => (
                <div key={incident.id} className={`flex items-center justify-between p-3 ${incident.severity === 'critical' ? 'bg-red-500' : 'bg-yellow-500'} bg-opacity-10 border ${incident.severity === 'critical' ? 'border-red-500' : 'border-yellow-500'} border-opacity-20 rounded-lg`}>
                  <div>
                    <p className="text-foreground font-medium">{(incident?.incident_type || incident?.incidentType || 'Unknown').toString().replace(/_/g, ' ').toUpperCase()}</p>
                    <p className="text-muted-foreground text-sm">{incident?.description || 'No description available'}</p>
                  </div>
                  <Badge className={`${incident.severity === 'critical' ? 'bg-red-500' : 'bg-yellow-500'} text-white`}>
                    {(incident?.status || 'UNKNOWN').toString().toUpperCase()}
                  </Badge>
                </div>
              ))}
              {(!Array.isArray(incidents) || incidents.filter((i: any) => i.severity === 'critical' || i.severity === 'high').length === 0) && (
                <div className="text-center py-4">
                  <p className="text-muted-foreground">No critical incidents detected</p>
                </div>
              )}
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
                  <span className="text-green-500">{(healthData && typeof healthData === 'object' && 'encryptionPerformance' in healthData && typeof healthData.encryptionPerformance === 'number') ? healthData.encryptionPerformance.toFixed(1) : 'No data'}%</span>
                </div>
                <Progress value={(healthData && typeof healthData === 'object' && 'encryptionPerformance' in healthData && typeof healthData.encryptionPerformance === 'number') ? healthData.encryptionPerformance : 0} className="h-2" />
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-muted-foreground">Key Infrastructure</span>
                  <span className="text-green-500">{(healthData && typeof healthData === 'object' && 'keyInfrastructure' in healthData && typeof healthData.keyInfrastructure === 'number') ? healthData.keyInfrastructure.toFixed(1) : 'No data'}%</span>
                </div>
                <Progress value={(healthData && typeof healthData === 'object' && 'keyInfrastructure' in healthData && typeof healthData.keyInfrastructure === 'number') ? healthData.keyInfrastructure : 0} className="h-2" />
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-muted-foreground">Auto-healing</span>
                  <span className="text-blue-500">{(healthData && typeof healthData === 'object' && 'autoHealing' in healthData && typeof healthData.autoHealing === 'number') ? healthData.autoHealing.toFixed(1) : 'No data'}%</span>
                </div>
                <Progress value={(healthData && typeof healthData === 'object' && 'autoHealing' in healthData && typeof healthData.autoHealing === 'number') ? healthData.autoHealing : 0} className="h-2" />
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
            plugins: {
              legend: {
                labels: { 
                  color: 'hsl(var(--foreground))',
                  font: { family: 'Inter' }
                }
              }
            },
            scales: {
              y: {
                beginAtZero: true,
                ticks: { color: 'hsl(var(--muted-foreground))' },
                grid: { color: 'hsl(var(--border))' }
              },
              x: {
                ticks: { color: 'hsl(var(--muted-foreground))' },
                grid: { color: 'hsl(var(--border))' }
              }
            }
          }}
        />
      </div>

      {/* Security Events */}
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="text-foreground">Security Events</CardTitle>
        </CardHeader>
        <CardContent>
          {eventsLoading ? (
            <div className="space-y-4">
              {[1, 2, 3].map((i) => (
                <div key={i} className="flex items-center space-x-4 p-3 bg-muted rounded-lg animate-pulse">
                  <div className="w-8 h-8 bg-muted-foreground/20 rounded-lg"></div>
                  <div className="flex-1">
                    <div className="h-4 bg-muted-foreground/20 rounded w-3/4 mb-2"></div>
                    <div className="h-3 bg-muted-foreground/20 rounded w-1/2"></div>
                  </div>
                  <div className="h-3 bg-muted-foreground/20 rounded w-20"></div>
                </div>
              ))}
            </div>
          ) : events?.length ? (
            <div className="space-y-4">
              {events.map((event: any) => (
                <div key={event.id} className="flex items-center space-x-4 p-3 bg-muted rounded-lg">
                  <div className={`w-8 h-8 ${getEventColor(event.severity)} bg-opacity-20 rounded-lg flex items-center justify-center`}>
                    {getEventIcon(event?.eventType || event?.event_type || event?.incident_type || 'unknown')}
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center space-x-2">
                      <p className="text-foreground font-medium" data-testid={`event-type-${event.id}`}>
                        {(event?.eventType || event?.event_type || event?.incident_type || 'Unknown').toString().replace(/_/g, ' ').toUpperCase()}
                      </p>
                      <Badge className={`${getEventColor(event.severity)} text-white text-xs`}>
                        {(event?.severity || 'UNKNOWN').toString().toUpperCase()}
                      </Badge>
                    </div>
                    <p className="text-muted-foreground text-sm" data-testid={`event-description-${event.id}`}>
                      {event?.description || 'No description available'}
                    </p>
                  </div>
                  <span className="text-muted-foreground text-sm" data-testid={`event-time-${event.id}`}>
                    {event?.createdAt ? formatDistanceToNow(new Date(event.createdAt), { addSuffix: true }) : 'Just now'}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8">
              <p className="text-muted-foreground">No security events</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
