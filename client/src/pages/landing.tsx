import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, Lock, Key, Eye, Users, CreditCard, Settings, Zap, CheckCircle, Building, Cloud, Globe, ArrowRight, Star, TrendingUp, Clock, Award, Smartphone, Server, Database } from "lucide-react";
import { Link } from "wouter";

export default function Landing() {
  return (
    <div className="min-h-screen bg-white">
      {/* Navigation */}
      <nav className="bg-white border-b border-gray-200 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <img 
                src="/averox-logo.png" 
                alt="Averox Logo" 
                className="w-12 h-12 object-contain"
              />
              <div>
                <h1 className="text-2xl font-bold text-gray-900">CryptoShield KMS</h1>
                <p className="text-sm text-blue-600">by Averox</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <Link href="/login">
                <Button 
                  variant="ghost" 
                  className="text-gray-600 hover:text-gray-900"
                  data-testid="button-login"
                >
                  Sign In
                </Button>
              </Link>
              <Link href="/register">
                <Button 
                  className="bg-blue-600 hover:bg-blue-700 text-white"
                  data-testid="button-get-started"
                >
                  Start Free Trial
                </Button>
              </Link>
            </div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="bg-gradient-to-br from-blue-50 to-indigo-100 pt-20 pb-32">
        <div className="max-w-7xl mx-auto px-6">
          <div className="text-center">
            <Badge variant="secondary" className="mb-4 bg-blue-100 text-blue-800 border-blue-200">
              <Award className="w-4 h-4 mr-1" />
              FIPS 140-3 & NIST Certified Enterprise Solution
            </Badge>
            
            <h1 className="text-5xl md:text-6xl font-bold text-gray-900 mb-6 leading-tight">
              Stop Worrying About<br />
              <span className="text-blue-600">Data Breaches</span>
            </h1>
            
            <p className="text-xl text-gray-600 mb-8 max-w-3xl mx-auto leading-relaxed">
              <strong>83% of enterprises</strong> will face a data breach this year costing $4.45M on average. 
              CryptoShield KMS protects your sensitive data with government-grade encryption 
              that integrates in minutes, not months.
            </p>
            
            <div className="flex flex-col sm:flex-row gap-4 justify-center mb-12">
              <Link href="/register">
                <Button 
                  size="lg" 
                  className="bg-blue-600 hover:bg-blue-700 text-white px-8 py-4 text-lg"
                  data-testid="button-start-trial"
                >
                  Start 30-Day Free Trial
                  <ArrowRight className="ml-2 w-5 h-5" />
                </Button>
              </Link>
              <Button 
                size="lg" 
                variant="outline" 
                className="border-gray-300 text-gray-700 hover:bg-gray-50 px-8 py-4 text-lg"
                data-testid="button-watch-demo"
              >
                Watch 2-Min Demo
              </Button>
            </div>

            {/* Trust Indicators */}
            <div className="flex items-center justify-center space-x-8 text-sm text-gray-500">
              <div className="flex items-center">
                <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                No credit card required
              </div>
              <div className="flex items-center">
                <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                5-minute setup
              </div>
              <div className="flex items-center">
                <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                24/7 expert support
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Problem/Solution Section */}
      <section className="py-24 bg-white">
        <div className="max-w-7xl mx-auto px-6">
          <div className="grid lg:grid-cols-2 gap-16 items-center">
            <div>
              <h2 className="text-3xl font-bold text-gray-900 mb-6">
                Your Current Security Stack is Failing You
              </h2>
              <div className="space-y-4 text-gray-600">
                <div className="flex items-start">
                  <div className="w-2 h-2 bg-red-500 rounded-full mt-2 mr-3 flex-shrink-0"></div>
                  <p><strong>Months of development time</strong> implementing encryption properly</p>
                </div>
                <div className="flex items-start">
                  <div className="w-2 h-2 bg-red-500 rounded-full mt-2 mr-3 flex-shrink-0"></div>
                  <p><strong>Complex key management</strong> that breaks when you need it most</p>
                </div>
                <div className="flex items-start">
                  <div className="w-2 h-2 bg-red-500 rounded-full mt-2 mr-3 flex-shrink-0"></div>
                  <p><strong>Compliance nightmares</strong> with FIPS, SOC 2, and industry audits</p>
                </div>
                <div className="flex items-start">
                  <div className="w-2 h-2 bg-red-500 rounded-full mt-2 mr-3 flex-shrink-0"></div>
                  <p><strong>Security vulnerabilities</strong> you don't know about until it's too late</p>
                </div>
              </div>
            </div>
            
            <div>
              <h2 className="text-3xl font-bold text-gray-900 mb-6">
                CryptoShield KMS Changes Everything
              </h2>
              <div className="space-y-4 text-gray-600">
                <div className="flex items-start">
                  <CheckCircle className="w-5 h-5 text-green-500 mt-1 mr-3 flex-shrink-0" />
                  <p><strong>5-minute integration</strong> with auto-generated SDKs in 13 languages</p>
                </div>
                <div className="flex items-start">
                  <CheckCircle className="w-5 h-5 text-green-500 mt-1 mr-3 flex-shrink-0" />
                  <p><strong>Self-healing infrastructure</strong> with automatic key rotation</p>
                </div>
                <div className="flex items-start">
                  <CheckCircle className="w-5 h-5 text-green-500 mt-1 mr-3 flex-shrink-0" />
                  <p><strong>Pre-certified compliance</strong> for all major frameworks</p>
                </div>
                <div className="flex items-start">
                  <CheckCircle className="w-5 h-5 text-green-500 mt-1 mr-3 flex-shrink-0" />
                  <p><strong>Real-time threat detection</strong> with instant automated response</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-24 bg-gray-50">
        <div className="max-w-7xl mx-auto px-6">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold text-gray-900 mb-4">
              Everything You Need to Protect Your Data
            </h2>
            <p className="text-xl text-gray-600 max-w-3xl mx-auto">
              From development to production, we've got every aspect of enterprise encryption covered
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            <Card className="bg-white border-gray-200 hover:shadow-lg transition-shadow">
              <CardHeader>
                <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center mb-4">
                  <Zap className="w-6 h-6 text-blue-600" />
                </div>
                <CardTitle className="text-gray-900">SDK Generator</CardTitle>
                <CardDescription className="text-gray-600">
                  Custom SDKs in Python, Java, Node.js, Go, Rust, and 8 more languages. Production-ready in minutes.
                </CardDescription>
              </CardHeader>
            </Card>

            <Card className="bg-white border-gray-200 hover:shadow-lg transition-shadow">
              <CardHeader>
                <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center mb-4">
                  <Eye className="w-6 h-6 text-green-600" />
                </div>
                <CardTitle className="text-gray-900">Real-Time Monitoring</CardTitle>
                <CardDescription className="text-gray-600">
                  24/7 security monitoring with ML-powered threat detection and automated incident response.
                </CardDescription>
              </CardHeader>
            </Card>

            <Card className="bg-white border-gray-200 hover:shadow-lg transition-shadow">
              <CardHeader>
                <div className="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center mb-4">
                  <Key className="w-6 h-6 text-purple-600" />
                </div>
                <CardTitle className="text-gray-900">Auto Key Rotation</CardTitle>
                <CardDescription className="text-gray-600">
                  Intelligent key lifecycle management with automatic rotation, versioning, and rollback capabilities.
                </CardDescription>
              </CardHeader>
            </Card>

            <Card className="bg-white border-gray-200 hover:shadow-lg transition-shadow">
              <CardHeader>
                <div className="w-12 h-12 bg-indigo-100 rounded-lg flex items-center justify-center mb-4">
                  <Shield className="w-6 h-6 text-indigo-600" />
                </div>
                <CardTitle className="text-gray-900">Quantum-Safe Encryption</CardTitle>
                <CardDescription className="text-gray-600">
                  Post-quantum algorithms ready for the cryptographic transition. Future-proof your security now.
                </CardDescription>
              </CardHeader>
            </Card>

            <Card className="bg-white border-gray-200 hover:shadow-lg transition-shadow">
              <CardHeader>
                <div className="w-12 h-12 bg-orange-100 rounded-lg flex items-center justify-center mb-4">
                  <Cloud className="w-6 h-6 text-orange-600" />
                </div>
                <CardTitle className="text-gray-900">Multi-Cloud HSM</CardTitle>
                <CardDescription className="text-gray-600">
                  Seamless integration with AWS KMS, Azure Key Vault, Google Cloud HSM, and on-premise solutions.
                </CardDescription>
              </CardHeader>
            </Card>

            <Card className="bg-white border-gray-200 hover:shadow-lg transition-shadow">
              <CardHeader>
                <div className="w-12 h-12 bg-red-100 rounded-lg flex items-center justify-center mb-4">
                  <Award className="w-6 h-6 text-red-600" />
                </div>
                <CardTitle className="text-gray-900">Compliance Ready</CardTitle>
                <CardDescription className="text-gray-600">
                  Pre-certified for FIPS 140-3, SOC 2, ISO 27001, HIPAA, PCI DSS, and government standards.
                </CardDescription>
              </CardHeader>
            </Card>
          </div>
        </div>
      </section>

      {/* Pricing Section */}
      <section className="py-24 bg-white">
        <div className="max-w-7xl mx-auto px-6">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold text-gray-900 mb-4">
              Simple, Transparent Pricing
            </h2>
            <p className="text-xl text-gray-600">
              Choose the plan that scales with your business. No hidden fees, no surprises.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Starter Plan */}
            <Card className="bg-white border-gray-200 relative">
              <CardHeader className="text-center pb-8">
                <CardTitle className="text-2xl font-bold text-gray-900 mb-2">Starter</CardTitle>
                <CardDescription className="text-gray-600 mb-4">
                  Perfect for small teams and proof-of-concepts
                </CardDescription>
                <div className="text-4xl font-bold text-gray-900">$99</div>
                <div className="text-gray-600">per month</div>
              </CardHeader>
              <CardContent>
                <ul className="space-y-3 mb-8">
                  <li className="flex items-center">
                    <CheckCircle className="w-5 h-5 text-green-500 mr-3" />
                    <span className="text-gray-600">Up to 3 applications</span>
                  </li>
                  <li className="flex items-center">
                    <CheckCircle className="w-5 h-5 text-green-500 mr-3" />
                    <span className="text-gray-600">10,000 operations/month</span>
                  </li>
                  <li className="flex items-center">
                    <CheckCircle className="w-5 h-5 text-green-500 mr-3" />
                    <span className="text-gray-600">All SDK languages</span>
                  </li>
                  <li className="flex items-center">
                    <CheckCircle className="w-5 h-5 text-green-500 mr-3" />
                    <span className="text-gray-600">Email support</span>
                  </li>
                  <li className="flex items-center">
                    <CheckCircle className="w-5 h-5 text-green-500 mr-3" />
                    <span className="text-gray-600">Basic monitoring</span>
                  </li>
                </ul>
                <Link href="/register">
                  <Button className="w-full bg-gray-900 hover:bg-gray-800 text-white">
                    Start Free Trial
                  </Button>
                </Link>
              </CardContent>
            </Card>

            {/* Professional Plan */}
            <Card className="bg-white border-blue-500 border-2 relative shadow-lg">
              <div className="absolute -top-4 left-1/2 transform -translate-x-1/2">
                <Badge className="bg-blue-600 text-white px-4 py-1">Most Popular</Badge>
              </div>
              <CardHeader className="text-center pb-8">
                <CardTitle className="text-2xl font-bold text-gray-900 mb-2">Professional</CardTitle>
                <CardDescription className="text-gray-600 mb-4">
                  Ideal for growing businesses with serious security needs
                </CardDescription>
                <div className="text-4xl font-bold text-gray-900">$299</div>
                <div className="text-gray-600">per month</div>
              </CardHeader>
              <CardContent>
                <ul className="space-y-3 mb-8">
                  <li className="flex items-center">
                    <CheckCircle className="w-5 h-5 text-green-500 mr-3" />
                    <span className="text-gray-600">Up to 15 applications</span>
                  </li>
                  <li className="flex items-center">
                    <CheckCircle className="w-5 h-5 text-green-500 mr-3" />
                    <span className="text-gray-600">100,000 operations/month</span>
                  </li>
                  <li className="flex items-center">
                    <CheckCircle className="w-5 h-5 text-green-500 mr-3" />
                    <span className="text-gray-600">Advanced monitoring & alerts</span>
                  </li>
                  <li className="flex items-center">
                    <CheckCircle className="w-5 h-5 text-green-500 mr-3" />
                    <span className="text-gray-600">Priority phone support</span>
                  </li>
                  <li className="flex items-center">
                    <CheckCircle className="w-5 h-5 text-green-500 mr-3" />
                    <span className="text-gray-600">Multi-cloud key distribution</span>
                  </li>
                  <li className="flex items-center">
                    <CheckCircle className="w-5 h-5 text-green-500 mr-3" />
                    <span className="text-gray-600">Compliance reporting</span>
                  </li>
                </ul>
                <Link href="/register">
                  <Button className="w-full bg-blue-600 hover:bg-blue-700 text-white">
                    Start Free Trial
                  </Button>
                </Link>
              </CardContent>
            </Card>

            {/* Enterprise Plan */}
            <Card className="bg-white border-gray-200 relative">
              <CardHeader className="text-center pb-8">
                <CardTitle className="text-2xl font-bold text-gray-900 mb-2">Enterprise</CardTitle>
                <CardDescription className="text-gray-600 mb-4">
                  For large organizations with mission-critical requirements
                </CardDescription>
                <div className="text-4xl font-bold text-gray-900">Custom</div>
                <div className="text-gray-600">pricing</div>
              </CardHeader>
              <CardContent>
                <ul className="space-y-3 mb-8">
                  <li className="flex items-center">
                    <CheckCircle className="w-5 h-5 text-green-500 mr-3" />
                    <span className="text-gray-600">Unlimited applications</span>
                  </li>
                  <li className="flex items-center">
                    <CheckCircle className="w-5 h-5 text-green-500 mr-3" />
                    <span className="text-gray-600">Unlimited operations</span>
                  </li>
                  <li className="flex items-center">
                    <CheckCircle className="w-5 h-5 text-green-500 mr-3" />
                    <span className="text-gray-600">Dedicated success manager</span>
                  </li>
                  <li className="flex items-center">
                    <CheckCircle className="w-5 h-5 text-green-500 mr-3" />
                    <span className="text-gray-600">White-glove onboarding</span>
                  </li>
                  <li className="flex items-center">
                    <CheckCircle className="w-5 h-5 text-green-500 mr-3" />
                    <span className="text-gray-600">Custom integrations</span>
                  </li>
                  <li className="flex items-center">
                    <CheckCircle className="w-5 h-5 text-green-500 mr-3" />
                    <span className="text-gray-600">SLA guarantees</span>
                  </li>
                </ul>
                <Button variant="outline" className="w-full border-gray-300 text-gray-700 hover:bg-gray-50">
                  Contact Sales
                </Button>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* Social Proof Section */}
      <section className="py-24 bg-gray-50">
        <div className="max-w-7xl mx-auto px-6">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-bold text-gray-900 mb-4">
              Trusted by Industry Leaders
            </h2>
            <p className="text-gray-600">
              Over 500+ enterprises trust CryptoShield KMS to protect their most sensitive data
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <Card className="bg-white border-gray-200">
              <CardContent className="p-8">
                <div className="flex items-center mb-4">
                  <div className="flex text-yellow-400">
                    {[...Array(5)].map((_, i) => (
                      <Star key={i} className="w-5 h-5 fill-current" />
                    ))}
                  </div>
                </div>
                <p className="text-gray-600 mb-4">
                  "CryptoShield KMS saved us 6 months of development time. Our compliance audit went from nightmare to breeze."
                </p>
                <div className="flex items-center">
                  <div className="w-10 h-10 bg-blue-100 rounded-full flex items-center justify-center mr-3">
                    <Building className="w-5 h-5 text-blue-600" />
                  </div>
                  <div>
                    <div className="font-semibold text-gray-900">Sarah Chen</div>
                    <div className="text-sm text-gray-600">CTO, FinTech Corp</div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-white border-gray-200">
              <CardContent className="p-8">
                <div className="flex items-center mb-4">
                  <div className="flex text-yellow-400">
                    {[...Array(5)].map((_, i) => (
                      <Star key={i} className="w-5 h-5 fill-current" />
                    ))}
                  </div>
                </div>
                <p className="text-gray-600 mb-4">
                  "The auto-healing capabilities are incredible. We haven't had a single security incident since deployment."
                </p>
                <div className="flex items-center">
                  <div className="w-10 h-10 bg-green-100 rounded-full flex items-center justify-center mr-3">
                    <Shield className="w-5 h-5 text-green-600" />
                  </div>
                  <div>
                    <div className="font-semibold text-gray-900">Michael Rodriguez</div>
                    <div className="text-sm text-gray-600">CISO, Healthcare Plus</div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-white border-gray-200">
              <CardContent className="p-8">
                <div className="flex items-center mb-4">
                  <div className="flex text-yellow-400">
                    {[...Array(5)].map((_, i) => (
                      <Star key={i} className="w-5 h-5 fill-current" />
                    ))}
                  </div>
                </div>
                <p className="text-gray-600 mb-4">
                  "Finally, encryption that just works. Our developers love the SDKs and our auditors love the compliance reports."
                </p>
                <div className="flex items-center">
                  <div className="w-10 h-10 bg-purple-100 rounded-full flex items-center justify-center mr-3">
                    <Users className="w-5 h-5 text-purple-600" />
                  </div>
                  <div>
                    <div className="font-semibold text-gray-900">Jennifer Park</div>
                    <div className="text-sm text-gray-600">VP Engineering, GovTech</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* Final CTA Section */}
      <section className="py-24 bg-blue-600">
        <div className="max-w-4xl mx-auto px-6 text-center">
          <h2 className="text-4xl font-bold text-white mb-6">
            Stop the Next Data Breach Before It Happens
          </h2>
          <p className="text-xl text-blue-100 mb-8">
            Join 500+ enterprises who trust CryptoShield KMS to protect their most valuable data. 
            Start your free trial today – no credit card required.
          </p>
          
          <div className="flex flex-col sm:flex-row gap-4 justify-center mb-8">
            <Link href="/register">
              <Button 
                size="lg" 
                className="bg-white text-blue-600 hover:bg-gray-100 px-8 py-4 text-lg font-semibold"
                data-testid="button-final-cta"
              >
                Start Your Free 30-Day Trial
                <ArrowRight className="ml-2 w-5 h-5" />
              </Button>
            </Link>
          </div>

          <div className="flex items-center justify-center space-x-8 text-sm text-blue-200">
            <div className="flex items-center">
              <Clock className="w-4 h-4 mr-2" />
              5-minute setup
            </div>
            <div className="flex items-center">
              <Shield className="w-4 h-4 mr-2" />
              Enterprise-grade security
            </div>
            <div className="flex items-center">
              <Users className="w-4 h-4 mr-2" />
              24/7 expert support
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-gray-900 text-white py-16">
        <div className="max-w-7xl mx-auto px-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
            <div>
              <div className="flex items-center space-x-3 mb-4">
                <img 
                  src="/averox-logo.png" 
                  alt="Averox Logo" 
                  className="w-8 h-8 object-contain"
                />
                <div>
                  <div className="font-bold">CryptoShield KMS</div>
                  <div className="text-sm text-gray-400">by Averox</div>
                </div>
              </div>
              <p className="text-gray-400 text-sm">
                Enterprise-grade encryption platform trusted by Fortune 500 companies worldwide.
              </p>
            </div>
            
            <div>
              <h4 className="font-semibold mb-4">Product</h4>
              <ul className="space-y-2 text-sm text-gray-400">
                <li><a href="#" className="hover:text-white">Features</a></li>
                <li><a href="#" className="hover:text-white">Pricing</a></li>
                <li><a href="#" className="hover:text-white">Security</a></li>
                <li><a href="#" className="hover:text-white">Integrations</a></li>
              </ul>
            </div>
            
            <div>
              <h4 className="font-semibold mb-4">Resources</h4>
              <ul className="space-y-2 text-sm text-gray-400">
                <li><a href="#" className="hover:text-white">Documentation</a></li>
                <li><a href="#" className="hover:text-white">API Reference</a></li>
                <li><a href="#" className="hover:text-white">Support</a></li>
                <li><a href="#" className="hover:text-white">Status</a></li>
              </ul>
            </div>
            
            <div>
              <h4 className="font-semibold mb-4">Company</h4>
              <ul className="space-y-2 text-sm text-gray-400">
                <li><a href="#" className="hover:text-white">About</a></li>
                <li><a href="#" className="hover:text-white">Contact</a></li>
                <li><a href="#" className="hover:text-white">Privacy</a></li>
                <li><a href="#" className="hover:text-white">Terms</a></li>
              </ul>
            </div>
          </div>
          
          <div className="border-t border-gray-800 mt-12 pt-8 text-center text-sm text-gray-400">
            © 2024 Averox. All rights reserved.
          </div>
        </div>
      </footer>
    </div>
  );
}