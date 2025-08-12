import { useQuery } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import StatsCard from "@/components/StatsCard";
import SecurityChart from "@/components/SecurityChart";
import { Code, Lock, RotateCcw, Shield, CheckCircle, AlertTriangle, XCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { formatDistanceToNow } from "date-fns";

export default function Dashboard() {
  const { toast } = useToast();

  const { data: stats = {}, isLoading: statsLoading } = useQuery({
    queryKey: ["/api/dashboard/stats"],
    retry: false,
  });

  const { data: activities = [], isLoading: activitiesLoading } = useQuery({
    queryKey: ["/api/dashboard/activities"],
    retry: false,
  });

  if (statsLoading) {
    return (
      <div className="p-6">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="bg-card rounded-xl p-6 border border-border animate-pulse">
              <div className="h-16 bg-muted rounded"></div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  // Mock chart data - in a real app, this would come from the API
  const performanceData = {
    labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
    datasets: [{
      label: 'Encryption Speed (ops/sec)',
      data: [12000, 19000, 15000, 25000, 22000, 30000],
      borderColor: '#3B82F6',
      backgroundColor: 'rgba(59, 130, 246, 0.1)',
      tension: 0.4
    }]
  };

  const securityData = {
    labels: ['Blocked', 'Allowed', 'Monitored'],
    datasets: [{
      data: [stats?.threatBlocks || 92, 2847, 156],
      backgroundColor: ['#EF4444', '#10B981', '#F59E0B'],
      borderWidth: 0
    }]
  };

  const getActivityIcon = (eventType: string) => {
    switch (eventType) {
      case 'sdk_generated':
        return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'key_rotated':
        return <RotateCcw className="w-4 h-4 text-yellow-500" />;
      case 'threat_detected':
        return <XCircle className="w-4 h-4 text-red-500" />;
      default:
        return <AlertTriangle className="w-4 h-4 text-blue-500" />;
    }
  };

  return (
    <div className="p-6">
      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <StatsCard
          title="Active SDKs"
          value={stats?.activeSDKs || 0}
          change="+12% this month"
          changeType="positive"
          icon={Code}
          iconColor="bg-blue-500"
        />
        <StatsCard
          title="Encrypted Requests"
          value={`${((stats?.encryptedRequests || 0) / 1000000).toFixed(1)}M`}
          change="+24% this week"
          changeType="positive"
          icon={Lock}
          iconColor="bg-green-500"
        />
        <StatsCard
          title="Key Rotations"
          value={stats?.keyRotations || 0}
          change="Auto-healing active"
          changeType="neutral"
          icon={RotateCcw}
          iconColor="bg-yellow-500"
        />
        <StatsCard
          title="Threat Blocks"
          value={stats?.threatBlocks || 0}
          change="Last 24h"
          changeType="neutral"
          icon={Shield}
          iconColor="bg-red-500"
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <SecurityChart
          type="line"
          title="Encryption Performance"
          data={performanceData}
        />
        <SecurityChart
          type="doughnut"
          title="Security Events"
          data={securityData}
        />
      </div>

      {/* Recent Activities */}
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="text-foreground">Recent Activities</CardTitle>
        </CardHeader>
        <CardContent>
          {activitiesLoading ? (
            <div className="space-y-4">
              {[1, 2, 3].map((i) => (
                <div key={i} className="flex items-center space-x-4 p-3 bg-secondary rounded-lg animate-pulse">
                  <div className="w-8 h-8 bg-muted rounded-lg"></div>
                  <div className="flex-1">
                    <div className="h-4 bg-muted rounded w-3/4 mb-2"></div>
                    <div className="h-3 bg-muted rounded w-1/2"></div>
                  </div>
                  <div className="h-3 bg-muted rounded w-20"></div>
                </div>
              ))}
            </div>
          ) : activities?.length ? (
            <div className="space-y-4">
              {activities.map((activity: any) => (
                <div key={activity.id} className="flex items-center space-x-4 p-3 bg-secondary rounded-lg">
                  <div className="w-8 h-8 bg-muted rounded-lg flex items-center justify-center">
                    {getActivityIcon(activity.eventType)}
                  </div>
                  <div className="flex-1">
                    <p className="text-foreground font-medium" data-testid={`activity-title-${activity.id}`}>
                      {activity.eventType === 'sdk_generated' && 'SDK Generated Successfully'}
                      {activity.eventType === 'key_rotated' && 'Key Rotation Completed'}
                      {activity.eventType === 'threat_detected' && 'Security Alert Detected'}
                    </p>
                    <p className="text-muted-foreground text-sm" data-testid={`activity-description-${activity.id}`}>
                      {activity.description}
                    </p>
                  </div>
                  <span className="text-muted-foreground text-sm" data-testid={`activity-time-${activity.id}`}>
                    {formatDistanceToNow(new Date(activity.createdAt), { addSuffix: true })}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8">
              <p className="text-muted-foreground">No recent activities</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
