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
                className="w-48 h-48 object-contain"
              />
              <div>
                <h1 className="text-xs font-bold text-gray-900">CryptoShield KMS</h1>
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
              <Link href="/trial-signup">
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
              <Link href="/trial-signup">
                <Button 
                  size="lg" 
                  className="bg-blue-600 hover:bg-blue-700 text-white px-8 py-4 text-lg"
                  data-testid="button-start-trial"
                >
                  Start 14-Day Free Trial
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

      {/* Comprehensive Features Section */}
      <section className="py-24 bg-gray-50">
        <div className="max-w-7xl mx-auto px-6">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold text-gray-900 mb-4">
              Complete Enterprise Encryption Platform
            </h2>
            <p className="text-xl text-gray-600 max-w-3xl mx-auto">
              Every feature you need to secure, monitor, and manage your encryption infrastructure at enterprise scale
            </p>
          </div>

          <div className="space-y-16">
            {/* Development & Integration */}
            <div>
              <h3 className="text-2xl font-bold text-gray-900 mb-8 text-center">Development & Integration</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                <Card className="bg-white border-gray-200 hover:shadow-lg transition-shadow">
                  <CardHeader>
                    <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center mb-4">
                      <Zap className="w-6 h-6 text-blue-600" />
                    </div>
                    <CardTitle className="text-gray-900">SDK Generator</CardTitle>
                    <CardDescription className="text-gray-600">
                      Custom SDKs in 13 languages: Python, Java, Node.js, Go, Rust, C#, Swift, Kotlin, PHP, Ruby, C++, Dart, and JavaScript. Production-ready code with documentation, examples, and test suites generated in under 5 minutes.
                    </CardDescription>
                  </CardHeader>
                </Card>

                <Card className="bg-white border-gray-200 hover:shadow-lg transition-shadow">
                  <CardHeader>
                    <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center mb-4">
                      <Settings className="w-6 h-6 text-green-600" />
                    </div>
                    <CardTitle className="text-gray-900">Zero-Config Integration</CardTitle>
                    <CardDescription className="text-gray-600">
                      Drop-in libraries with intelligent defaults. No complex configuration files, no cryptographic knowledge required. Our SDKs automatically handle encryption parameters, key derivation, and secure defaults.
                    </CardDescription>
                  </CardHeader>
                </Card>

                <Card className="bg-white border-gray-200 hover:shadow-lg transition-shadow">
                  <CardHeader>
                    <div className="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center mb-4">
                      <Database className="w-6 h-6 text-purple-600" />
                    </div>
                    <CardTitle className="text-gray-900">Universal Compatibility</CardTitle>
                    <CardDescription className="text-gray-600">
                      Works with any database, framework, or cloud platform. MySQL, PostgreSQL, MongoDB, Redis, DynamoDB, Kubernetes, Docker, AWS, Azure, GCP - if you use it, we support it.
                    </CardDescription>
                  </CardHeader>
                </Card>
              </div>
            </div>

            {/* Security & Encryption */}
            <div>
              <h3 className="text-2xl font-bold text-gray-900 mb-8 text-center">Enterprise Security</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                <Card className="bg-white border-gray-200 hover:shadow-lg transition-shadow">
                  <CardHeader>
                    <div className="w-12 h-12 bg-indigo-100 rounded-lg flex items-center justify-center mb-4">
                      <Shield className="w-6 h-6 text-indigo-600" />
                    </div>
                    <CardTitle className="text-gray-900">Military-Grade Encryption</CardTitle>
                    <CardDescription className="text-gray-600">
                      AES-256-GCM, ChaCha20-Poly1305, RSA-4096, ECDSA P-384, Ed25519. FIPS 140-3 validated cryptographic modules. NSA Suite B algorithms for classified data protection.
                    </CardDescription>
                  </CardHeader>
                </Card>

                <Card className="bg-white border-gray-200 hover:shadow-lg transition-shadow">
                  <CardHeader>
                    <div className="w-12 h-12 bg-red-100 rounded-lg flex items-center justify-center mb-4">
                      <Lock className="w-6 h-6 text-red-600" />
                    </div>
                    <CardTitle className="text-gray-900">Quantum-Safe Algorithms</CardTitle>
                    <CardDescription className="text-gray-600">
                      NIST Post-Quantum Cryptography winners: CRYSTALS-Kyber, CRYSTALS-Dilithium, FALCON, SPHINCS+. Hybrid implementations for smooth transition. Future-proof your data against quantum computers.
                    </CardDescription>
                  </CardHeader>
                </Card>

                <Card className="bg-white border-gray-200 hover:shadow-lg transition-shadow">
                  <CardHeader>
                    <div className="w-12 h-12 bg-yellow-100 rounded-lg flex items-center justify-center mb-4">
                      <Award className="w-6 h-6 text-yellow-600" />
                    </div>
                    <CardTitle className="text-gray-900">Confidential Computing</CardTitle>
                    <CardDescription className="text-gray-600">
                      Intel SGX Trusted Execution Environments, Microsoft SEAL homomorphic encryption, SPDZ multi-party computation. Process encrypted data without decryption.
                    </CardDescription>
                  </CardHeader>
                </Card>
              </div>
            </div>

            {/* Key Management */}
            <div>
              <h3 className="text-2xl font-bold text-gray-900 mb-8 text-center">Intelligent Key Management</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                <Card className="bg-white border-gray-200 hover:shadow-lg transition-shadow">
                  <CardHeader>
                    <div className="w-12 h-12 bg-orange-100 rounded-lg flex items-center justify-center mb-4">
                      <Key className="w-6 h-6 text-orange-600" />
                    </div>
                    <CardTitle className="text-gray-900">Auto Key Rotation</CardTitle>
                    <CardDescription className="text-gray-600">
                      Time-based, usage-based, or policy-driven rotation. Zero-downtime key updates with automatic versioning. Configurable rotation schedules: hourly, daily, weekly, or custom intervals based on your compliance requirements.
                    </CardDescription>
                  </CardHeader>
                </Card>

                <Card className="bg-white border-gray-200 hover:shadow-lg transition-shadow">
                  <CardHeader>
                    <div className="w-12 h-12 bg-teal-100 rounded-lg flex items-center justify-center mb-4">
                      <Cloud className="w-6 h-6 text-teal-600" />
                    </div>
                    <CardTitle className="text-gray-900">Multi-Cloud HSM</CardTitle>
                    <CardDescription className="text-gray-600">
                      AWS CloudHSM, Azure Dedicated HSM, Google Cloud HSM, HashiCorp Vault, on-premise HSMs from SafeNet, Thales, nCipher. Seamless failover between providers for true vendor independence.
                    </CardDescription>
                  </CardHeader>
                </Card>

                <Card className="bg-white border-gray-200 hover:shadow-lg transition-shadow">
                  <CardHeader>
                    <div className="w-12 h-12 bg-pink-100 rounded-lg flex items-center justify-center mb-4">
                      <Globe className="w-6 h-6 text-pink-600" />
                    </div>
                    <CardTitle className="text-gray-900">Global Key Distribution</CardTitle>
                    <CardDescription className="text-gray-600">
                      Automatic key synchronization across regions and clouds. Edge caching for sub-10ms key retrieval. Geographic compliance with data residency requirements in 40+ countries.
                    </CardDescription>
                  </CardHeader>
                </Card>
              </div>
            </div>

            {/* Monitoring & Operations */}
            <div>
              <h3 className="text-2xl font-bold text-gray-900 mb-8 text-center">Monitoring & Operations</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                <Card className="bg-white border-gray-200 hover:shadow-lg transition-shadow">
                  <CardHeader>
                    <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center mb-4">
                      <Eye className="w-6 h-6 text-blue-600" />
                    </div>
                    <CardTitle className="text-gray-900">Real-Time Monitoring</CardTitle>
                    <CardDescription className="text-gray-600">
                      24/7 security monitoring with machine learning threat detection. Behavioral analysis, anomaly detection, and automatic incident response. Integration with Splunk, DataDog, New Relic, and custom SIEM solutions.
                    </CardDescription>
                  </CardHeader>
                </Card>

                <Card className="bg-white border-gray-200 hover:shadow-lg transition-shadow">
                  <CardHeader>
                    <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center mb-4">
                      <TrendingUp className="w-6 h-6 text-green-600" />
                    </div>
                    <CardTitle className="text-gray-900">Performance Analytics</CardTitle>
                    <CardDescription className="text-gray-600">
                      Detailed performance metrics: encryption/decryption latency, throughput analysis, key usage patterns. Capacity planning recommendations and optimization suggestions for maximum efficiency.
                    </CardDescription>
                  </CardHeader>
                </Card>

                <Card className="bg-white border-gray-200 hover:shadow-lg transition-shadow">
                  <CardHeader>
                    <div className="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center mb-4">
                      <Server className="w-6 h-6 text-purple-600" />
                    </div>
                    <CardTitle className="text-gray-900">Self-Healing Infrastructure</CardTitle>
                    <CardDescription className="text-gray-600">
                      Automatic failover, load balancing, and disaster recovery. Self-diagnosing systems that detect and resolve issues before they impact your applications. 99.99% uptime SLA.
                    </CardDescription>
                  </CardHeader>
                </Card>
              </div>
            </div>

            {/* Compliance & Governance */}
            <div>
              <h3 className="text-2xl font-bold text-gray-900 mb-8 text-center">Compliance & Governance</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                <Card className="bg-white border-gray-200 hover:shadow-lg transition-shadow">
                  <CardHeader>
                    <div className="w-12 h-12 bg-red-100 rounded-lg flex items-center justify-center mb-4">
                      <Award className="w-6 h-6 text-red-600" />
                    </div>
                    <CardTitle className="text-gray-900">Pre-Certified Compliance</CardTitle>
                    <CardDescription className="text-gray-600">
                      FIPS 140-3 Level 4, Common Criteria EAL4+, SOC 2 Type II, ISO 27001, HIPAA, PCI DSS Level 1, FedRAMP High, FISMA, ITAR, EAR compliance. Pre-built audit reports and evidence packages.
                    </CardDescription>
                  </CardHeader>
                </Card>

                <Card className="bg-white border-gray-200 hover:shadow-lg transition-shadow">
                  <CardHeader>
                    <div className="w-12 h-12 bg-indigo-100 rounded-lg flex items-center justify-center mb-4">
                      <Users className="w-6 h-6 text-indigo-600" />
                    </div>
                    <CardTitle className="text-gray-900">Role-Based Access Control</CardTitle>
                    <CardDescription className="text-gray-600">
                      Granular permissions with principle of least privilege. Integration with Active Directory, LDAP, Okta, Auth0. Multi-factor authentication, hardware security keys, and biometric verification.
                    </CardDescription>
                  </CardHeader>
                </Card>

                <Card className="bg-white border-gray-200 hover:shadow-lg transition-shadow">
                  <CardHeader>
                    <div className="w-12 h-12 bg-yellow-100 rounded-lg flex items-center justify-center mb-4">
                      <Building className="w-6 h-6 text-yellow-600" />
                    </div>
                    <CardTitle className="text-gray-900">Audit & Reporting</CardTitle>
                    <CardDescription className="text-gray-600">
                      Comprehensive audit trails with tamper-proof logs. Real-time compliance dashboards, automated report generation, and executive summaries. Custom reporting for board presentations and regulatory submissions.
                    </CardDescription>
                  </CardHeader>
                </Card>
              </div>
            </div>
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
                <Link href="/trial-signup">
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
                <Link href="/trial-signup">
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
      <footer className="bg-gray-50 border-t border-gray-200 py-16">
        <div className="max-w-7xl mx-auto px-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
            <div>
              <div className="flex items-center space-x-3 mb-4">
                <img 
                  src="/averox-logo.png" 
                  alt="Averox Logo" 
                  className="w-32 h-32 object-contain"
                />
                <div>
                  <div className="font-bold text-gray-900 text-xs">CryptoShield KMS</div>
                </div>
              </div>
              <p className="text-gray-600 text-sm">
                Enterprise-grade encryption platform trusted by Fortune 500 companies worldwide.
              </p>
            </div>
            
            <div>
              <h4 className="font-semibold mb-4 text-gray-900">Product</h4>
              <ul className="space-y-2 text-sm text-gray-600">
                <li><a href="#" className="hover:text-blue-600 transition-colors">Features</a></li>
                <li><a href="#" className="hover:text-blue-600 transition-colors">Pricing</a></li>
                <li><a href="#" className="hover:text-blue-600 transition-colors">Security</a></li>
                <li><a href="#" className="hover:text-blue-600 transition-colors">Integrations</a></li>
              </ul>
            </div>
            
            <div>
              <h4 className="font-semibold mb-4 text-gray-900">Resources</h4>
              <ul className="space-y-2 text-sm text-gray-600">
                <li><a href="#" className="hover:text-blue-600 transition-colors">Documentation</a></li>
                <li><a href="#" className="hover:text-blue-600 transition-colors">API Reference</a></li>
                <li><a href="#" className="hover:text-blue-600 transition-colors">Support</a></li>
                <li><a href="#" className="hover:text-blue-600 transition-colors">Status</a></li>
              </ul>
            </div>
            
            <div>
              <h4 className="font-semibold mb-4 text-gray-900">Company</h4>
              <ul className="space-y-2 text-sm text-gray-600">
                <li><a href="#" className="hover:text-blue-600 transition-colors">About</a></li>
                <li><a href="#" className="hover:text-blue-600 transition-colors">Contact</a></li>
                <li><a href="#" className="hover:text-blue-600 transition-colors">Privacy</a></li>
                <li><a href="#" className="hover:text-blue-600 transition-colors">Terms</a></li>
              </ul>
            </div>
          </div>
          
          <div className="border-t border-gray-200 mt-12 pt-8 text-center text-sm text-gray-500">
            © 2024 Averox. All rights reserved.
          </div>
        </div>
      </footer>
    </div>
  );
}