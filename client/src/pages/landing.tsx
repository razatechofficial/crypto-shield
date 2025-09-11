import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Shield, Lock, Key, Eye, Users, CreditCard, Settings, Zap } from "lucide-react";

export default function Landing() {
  return (
    <div className="min-h-screen bg-slate-900 text-slate-50">
      {/* Hero Section */}
      <div className="relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-slate-800 to-slate-900"></div>
        <div className="relative px-6 py-24 mx-auto max-w-7xl">
          <div className="text-center">
            <div className="flex items-center justify-center space-x-3 mb-8">
              <img 
                src="/averox-logo.png" 
                alt="Averox Logo" 
                className="w-12 h-12 object-contain"
              />
              <div>
                <h1 className="text-4xl font-bold text-white">Averox</h1>
                <p className="text-slate-400">Enterprise Encryption Platform</p>
              </div>
            </div>
            
            <h2 className="text-5xl font-bold text-white mb-6">
              Confidential Computing Platform
            </h2>
            <p className="text-xl text-slate-300 mb-8 max-w-3xl mx-auto">
              Create production-ready SDKs with Intel SGX TEE, Microsoft SEAL homomorphic encryption, 
              and SPDZ multi-party computation. Enterprise-grade confidential computing for government, 
              banking, and healthcare applications.
            </p>
            
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Button 
                size="lg" 
                className="bg-blue-500 hover:bg-blue-600 text-white px-8 py-3"
                onClick={() => window.location.href = '/api/login'}
                data-testid="button-login"
              >
                Get Started
              </Button>
              <Button 
                size="lg" 
                variant="outline" 
                className="border-slate-600 text-slate-300 hover:bg-slate-800 px-8 py-3"
                data-testid="button-learn-more"
              >
                Learn More
              </Button>
            </div>
          </div>
        </div>
      </div>

      {/* Features Section */}
      <div className="py-24 px-6 max-w-7xl mx-auto">
        <div className="text-center mb-16">
          <h3 className="text-3xl font-bold text-white mb-4">
            Comprehensive Encryption Solutions
          </h3>
          <p className="text-slate-400 text-lg max-w-2xl mx-auto">
            Everything you need to implement enterprise-grade encryption across all your applications
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <Card 
            className="bg-slate-800 border-slate-700 cursor-pointer hover:bg-slate-700 transition-colors"
            onClick={() => window.location.href = '/api/login'}
            data-testid="card-sdk-wizard"
          >
            <CardHeader>
              <Zap className="w-8 h-8 text-blue-500 mb-2" />
              <CardTitle className="text-white">SDK Wizard</CardTitle>
              <CardDescription className="text-slate-400">
                Generate custom SDKs in any language with just a few clicks
              </CardDescription>
            </CardHeader>
          </Card>

          <Card className="bg-slate-800 border-slate-700">
            <CardHeader>
              <Eye className="w-8 h-8 text-green-500 mb-2" />
              <CardTitle className="text-white">Real-time Monitoring</CardTitle>
              <CardDescription className="text-slate-400">
                Comprehensive security monitoring with threat detection
              </CardDescription>
            </CardHeader>
          </Card>

          <Card className="bg-slate-800 border-slate-700">
            <CardHeader>
              <Key className="w-8 h-8 text-yellow-500 mb-2" />
              <CardTitle className="text-white">Auto Key Rotation</CardTitle>
              <CardDescription className="text-slate-400">
                Automatic key rotation and self-healing capabilities
              </CardDescription>
            </CardHeader>
          </Card>

          <Card className="bg-slate-800 border-slate-700">
            <CardHeader>
              <Lock className="w-8 h-8 text-purple-500 mb-2" />
              <CardTitle className="text-white">Quantum Safe</CardTitle>
              <CardDescription className="text-slate-400">
                Post-quantum encryption algorithms for future-proof security
              </CardDescription>
            </CardHeader>
          </Card>
        </div>
      </div>

      {/* Benefits Section */}
      <div className="py-24 px-6 bg-slate-800">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h3 className="text-3xl font-bold text-white mb-4">
              Why Choose Averox?
            </h3>
            <p className="text-slate-400 text-lg">
              Built for enterprises that demand the highest security standards
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="text-center">
              <div className="w-16 h-16 bg-blue-500 bg-opacity-20 rounded-full flex items-center justify-center mx-auto mb-4">
                <Shield className="w-8 h-8 text-blue-500" />
              </div>
              <h4 className="text-xl font-semibold text-white mb-2">Enterprise Security</h4>
              <p className="text-slate-400">
                FIPS 140-2 Level 3, Common Criteria EAL4+, ISO 27001, and SOC 2 Type II compliant
              </p>
            </div>

            <div className="text-center">
              <div className="w-16 h-16 bg-green-500 bg-opacity-20 rounded-full flex items-center justify-center mx-auto mb-4">
                <Zap className="w-8 h-8 text-green-500" />
              </div>
              <h4 className="text-xl font-semibold text-white mb-2">Zero Configuration</h4>
              <p className="text-slate-400">
                Plug-and-play SDKs with zero coding required. Integration in minutes, not days
              </p>
            </div>

            <div className="text-center">
              <div className="w-16 h-16 bg-purple-500 bg-opacity-20 rounded-full flex items-center justify-center mx-auto mb-4">
                <Eye className="w-8 h-8 text-purple-500" />
              </div>
              <h4 className="text-xl font-semibold text-white mb-2">Peace of Mind</h4>
              <p className="text-slate-400">
                24/7 monitoring, auto-healing, and instant threat response. Sleep peacefully.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* CTA Section */}
      <div className="py-24 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <h3 className="text-3xl font-bold text-white mb-4">
            Ready to Secure Your Applications?
          </h3>
          <p className="text-slate-400 text-lg mb-8">
            Join thousands of enterprises protecting their data with Averox Crypto System
          </p>
          <Button 
            size="lg" 
            className="bg-blue-500 hover:bg-blue-600 text-white px-8 py-3"
            onClick={() => window.location.href = '/api/login'}
            data-testid="button-get-started"
          >
            Start Your Free Trial
          </Button>
        </div>
      </div>
    </div>
  );
}
