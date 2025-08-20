import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell, AreaChart, Area } from 'recharts';
import { TrendingUp, Shield, Activity, AlertTriangle, Download, Calendar, Eye, Zap } from "lucide-react";
import { useState } from "react";

export default function AdvancedAnalytics() {
  const [timeRange, setTimeRange] = useState("7d");
  const [selectedMetric, setSelectedMetric] = useState("operations");

  // Sample analytics data - in production this would come from your telemetry system
  const performanceData = [
    { time: '00:00', operations: 1240, latency: 12, errors: 2, throughput: 98.3 },
    { time: '04:00', operations: 890, latency: 8, errors: 1, throughput: 99.1 },
    { time: '08:00', operations: 2150, latency: 15, errors: 5, throughput: 97.2 },
    { time: '12:00', operations: 3200, latency: 18, errors: 8, throughput: 96.8 },
    { time: '16:00', operations: 2800, latency: 14, errors: 3, throughput: 98.5 },
    { time: '20:00', operations: 1950, latency: 11, errors: 2, throughput: 99.2 },
  ];

  const algorithmUsage = [
    { algorithm: 'AES-256-GCM', operations: 15420, percentage: 62.3, color: '#3B82F6' },
    { algorithm: 'ChaCha20-Poly1305', operations: 6890, percentage: 27.8, color: '#10B981' },
    { algorithm: 'CRYSTALS-Kyber', operations: 1245, percentage: 5.0, color: '#8B5CF6' },
    { algorithm: 'CRYSTALS-Dilithium', operations: 890, percentage: 3.6, color: '#F59E0B' },
    { algorithm: 'Others', operations: 325, percentage: 1.3, color: '#6B7280' },
  ];

  const securityEvents = [
    { type: 'Invalid Key Size', count: 23, severity: 'medium', timestamp: '2 hours ago' },
    { type: 'Authentication Failure', count: 12, severity: 'high', timestamp: '45 minutes ago' },
    { type: 'Rate Limit Exceeded', count: 156, severity: 'low', timestamp: '15 minutes ago' },
    { type: 'Suspicious Pattern', count: 3, severity: 'high', timestamp: '5 minutes ago' },
  ];

  const geographicData = [
    { region: 'North America', operations: 45.2, latency: 12, uptime: 99.9 },
    { region: 'Europe', operations: 32.1, latency: 18, uptime: 99.7 },
    { region: 'Asia Pacific', operations: 18.5, latency: 24, uptime: 99.8 },
    { region: 'South America', operations: 4.2, latency: 35, uptime: 99.5 },
  ];

  const compliance = [
    { standard: 'NIST SP 800-38D', status: 'Compliant', tests: '24/24', lastCheck: '2 hours ago' },
    { standard: 'FIPS 140-2 Level 3', status: 'Compliant', tests: '18/18', lastCheck: '6 hours ago' },
    { standard: 'Common Criteria EAL4+', status: 'In Progress', tests: '12/15', lastCheck: '1 day ago' },
    { standard: 'ISO 27001', status: 'Compliant', tests: '45/45', lastCheck: '3 days ago' },
  ];

  return (
    <div className="space-y-6 p-6 bg-white min-h-screen">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Advanced Analytics</h1>
          <p className="text-gray-600">Comprehensive cryptographic operations analytics and intelligence</p>
        </div>
        <div className="flex items-center space-x-4">
          <Select value={timeRange} onValueChange={setTimeRange}>
            <SelectTrigger className="w-32 bg-white border-gray-300">
              <SelectValue placeholder="Time Range" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="1h">Last Hour</SelectItem>
              <SelectItem value="24h">Last 24h</SelectItem>
              <SelectItem value="7d">Last 7 days</SelectItem>
              <SelectItem value="30d">Last 30 days</SelectItem>
            </SelectContent>
          </Select>
          <Button className="bg-blue-600 hover:bg-blue-700">
            <Download className="w-4 h-4 mr-2" />
            Export Report
          </Button>
        </div>
      </div>

      {/* Key Metrics Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-white border-gray-300 shadow-sm">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Total Operations</p>
                <p className="text-2xl font-bold text-gray-900">24.7K</p>
                <p className="text-sm text-green-600 flex items-center">
                  <TrendingUp className="w-3 h-3 mr-1" />
                  +12.5% from last period
                </p>
              </div>
              <Activity className="w-8 h-8 text-blue-600" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-white border-gray-300 shadow-sm">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Avg Latency</p>
                <p className="text-2xl font-bold text-gray-900">14.2ms</p>
                <p className="text-sm text-green-600 flex items-center">
                  <TrendingUp className="w-3 h-3 mr-1 rotate-180" />
                  -3.2% improvement
                </p>
              </div>
              <Zap className="w-8 h-8 text-yellow-600" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-white border-gray-300 shadow-sm">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Success Rate</p>
                <p className="text-2xl font-bold text-gray-900">99.2%</p>
                <p className="text-sm text-green-600 flex items-center">
                  <Shield className="w-3 h-3 mr-1" />
                  Enterprise SLA met
                </p>
              </div>
              <Shield className="w-8 h-8 text-green-600" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-white border-gray-300 shadow-sm">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Security Events</p>
                <p className="text-2xl font-bold text-gray-900">194</p>
                <p className="text-sm text-orange-600 flex items-center">
                  <AlertTriangle className="w-3 h-3 mr-1" />
                  3 high priority
                </p>
              </div>
              <AlertTriangle className="w-8 h-8 text-orange-600" />
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="performance" className="w-full">
        <TabsList className="grid w-full grid-cols-5 bg-gray-100 text-gray-700">
          <TabsTrigger value="performance" className="data-[state=active]:bg-blue-600 data-[state=active]:text-white">Performance</TabsTrigger>
          <TabsTrigger value="algorithms" className="data-[state=active]:bg-blue-600 data-[state=active]:text-white">Algorithms</TabsTrigger>
          <TabsTrigger value="security" className="data-[state=active]:bg-blue-600 data-[state=active]:text-white">Security</TabsTrigger>
          <TabsTrigger value="geographic" className="data-[state=active]:bg-blue-600 data-[state=active]:text-white">Geographic</TabsTrigger>
          <TabsTrigger value="compliance" className="data-[state=active]:bg-blue-600 data-[state=active]:text-white">Compliance</TabsTrigger>
        </TabsList>

        <TabsContent value="performance" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card className="bg-white border-gray-300 shadow-sm">
              <CardHeader>
                <CardTitle className="text-gray-900">Operations Over Time</CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <AreaChart data={performanceData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
                    <XAxis dataKey="time" stroke="#6B7280" />
                    <YAxis stroke="#6B7280" />
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: '#FFFFFF', 
                        border: '1px solid #E5E7EB',
                        borderRadius: '8px',
                        color: '#1F2937'
                      }} 
                    />
                    <Area type="monotone" dataKey="operations" stroke="#3B82F6" fill="#3B82F6" fillOpacity={0.3} />
                  </AreaChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            <Card className="bg-white border-gray-300 shadow-sm">
              <CardHeader>
                <CardTitle className="text-gray-900">Latency Distribution</CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={performanceData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
                    <XAxis dataKey="time" stroke="#6B7280" />
                    <YAxis stroke="#6B7280" />
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: '#FFFFFF', 
                        border: '1px solid #E5E7EB',
                        borderRadius: '8px',
                        color: '#1F2937'
                      }} 
                    />
                    <Line type="monotone" dataKey="latency" stroke="#10B981" strokeWidth={2} />
                  </LineChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>

          <Card className="bg-white border-gray-300 shadow-sm">
            <CardHeader>
              <CardTitle className="text-gray-900">Throughput vs Error Rate</CardTitle>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={400}>
                <BarChart data={performanceData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
                  <XAxis dataKey="time" stroke="#6B7280" />
                  <YAxis stroke="#6B7280" />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: '#FFFFFF', 
                      border: '1px solid #E5E7EB',
                      borderRadius: '8px',
                      color: '#1F2937'
                    }} 
                  />
                  <Bar dataKey="throughput" fill="#3B82F6" />
                  <Bar dataKey="errors" fill="#EF4444" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="algorithms" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card className="bg-white border-gray-300 shadow-sm">
              <CardHeader>
                <CardTitle className="text-gray-900">Algorithm Usage Distribution</CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={algorithmUsage}
                      cx="50%"
                      cy="50%"
                      outerRadius={100}
                      fill="#8884d8"
                      dataKey="operations"
                      label={({ algorithm, percentage }) => `${algorithm}: ${percentage}%`}
                    >
                      {algorithmUsage.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: '#FFFFFF', 
                        border: '1px solid #E5E7EB',
                        borderRadius: '8px',
                        color: '#1F2937'
                      }} 
                    />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            <Card className="bg-white border-gray-300 shadow-sm">
              <CardHeader>
                <CardTitle className="text-gray-900">Algorithm Performance</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {algorithmUsage.map((algo, index) => (
                    <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg border border-gray-200">
                      <div className="flex items-center space-x-3">
                        <div className="w-3 h-3 rounded-full" style={{ backgroundColor: algo.color }}></div>
                        <div>
                          <div className="text-gray-900 font-medium">{algo.algorithm}</div>
                          <div className="text-sm text-gray-600">{algo.operations.toLocaleString()} operations</div>
                        </div>
                      </div>
                      <div className="text-right">
                        <div className="text-gray-900 font-medium">{algo.percentage}%</div>
                        <Badge className="bg-green-600 text-white text-xs">Optimal</Badge>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="security" className="space-y-4">
          <Card className="bg-white border-gray-300 shadow-sm">
            <CardHeader>
              <CardTitle className="text-gray-900">Security Event Dashboard</CardTitle>
              <p className="text-gray-600">Real-time monitoring of cryptographic security events</p>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {securityEvents.map((event, index) => (
                  <div key={index} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg border border-gray-200">
                    <div className="flex items-center space-x-4">
                      <AlertTriangle className={`w-5 h-5 ${
                        event.severity === 'high' ? 'text-red-600' :
                        event.severity === 'medium' ? 'text-orange-600' : 'text-yellow-600'
                      }`} />
                      <div>
                        <div className="text-gray-900 font-medium">{event.type}</div>
                        <div className="text-sm text-gray-600">{event.timestamp}</div>
                      </div>
                    </div>
                    <div className="flex items-center space-x-4">
                      <div className="text-right">
                        <div className="text-gray-900 font-bold">{event.count}</div>
                        <div className="text-xs text-gray-600">incidents</div>
                      </div>
                      <Badge className={
                        event.severity === 'high' ? 'bg-red-600' :
                        event.severity === 'medium' ? 'bg-orange-600' : 'bg-yellow-600'
                      }>
                        {event.severity.toUpperCase()}
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="geographic" className="space-y-4">
          <Card className="bg-white border-gray-300 shadow-sm">
            <CardHeader>
              <CardTitle className="text-gray-900">Geographic Performance</CardTitle>
              <p className="text-gray-600">Regional operation statistics and performance metrics</p>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {geographicData.map((region, index) => (
                  <div key={index} className="p-4 bg-gray-50 rounded-lg border border-gray-200">
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="font-semibold text-gray-900">{region.region}</h3>
                      <Badge className="bg-green-600">Active</Badge>
                    </div>
                    <div className="grid grid-cols-3 gap-4">
                      <div>
                        <div className="text-2xl font-bold text-gray-900">{region.operations}%</div>
                        <div className="text-sm text-gray-600">Traffic Share</div>
                      </div>
                      <div>
                        <div className="text-2xl font-bold text-gray-900">{region.latency}ms</div>
                        <div className="text-sm text-gray-600">Avg Latency</div>
                      </div>
                      <div>
                        <div className="text-2xl font-bold text-green-600">{region.uptime}%</div>
                        <div className="text-sm text-gray-600">Uptime</div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="compliance" className="space-y-4">
          <Card className="bg-white border-gray-300 shadow-sm">
            <CardHeader>
              <CardTitle className="text-gray-900">Compliance Status</CardTitle>
              <p className="text-gray-600">Regulatory and standards compliance monitoring</p>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {compliance.map((item, index) => (
                  <div key={index} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg border border-gray-200">
                    <div className="flex-1">
                      <div className="flex items-center space-x-3">
                        <h3 className="font-semibold text-gray-900">{item.standard}</h3>
                        <Badge className={
                          item.status === 'Compliant' ? 'bg-green-600' :
                          item.status === 'In Progress' ? 'bg-orange-600' : 'bg-red-600'
                        }>
                          {item.status}
                        </Badge>
                      </div>
                      <div className="text-sm text-gray-600 mt-1">Last checked: {item.lastCheck}</div>
                    </div>
                    <div className="text-right">
                      <div className="text-gray-900 font-medium">{item.tests}</div>
                      <div className="text-xs text-gray-600">tests passed</div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}