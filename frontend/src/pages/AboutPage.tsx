import React from 'react';
import { BookOpen, ShieldAlert, Lock, AlertTriangle, Layers, Cpu, Compass, Globe, Server, CheckCircle2 } from 'lucide-react';

export const AboutPage: React.FC = () => {
  const futureModules = [
    { name: 'VirusTotal Threat API', status: 'Architectural Placeholder', desc: 'Cross-reference URL hashes against multi-antivirus engine telemetry.' },
    { name: 'Google Safe Browsing', status: 'Architectural Placeholder', desc: 'Query Google reputation database for flagged malware and deceptive sites.' },
    { name: 'WHOIS & Domain Age Lookup', status: 'Architectural Placeholder', desc: 'Evaluate domain registration age and registrar reputation metrics.' },
    { name: 'Passive DNS & IP Geolocation', status: 'Architectural Placeholder', desc: 'Resolve nameserver infrastructure and Autonomous System Numbers (ASN).' },
    { name: 'SSL/TLS Certificate Inspection', status: 'Architectural Placeholder', desc: 'Validate certificate authority validity, SAN matching, and issuance dates.' },
    { name: 'QR Code URL Extraction', status: 'Architectural Placeholder', desc: 'Decode QR code images into URL targets for automated static parsing.' },
  ];

  return (
    <div className="space-y-10 max-w-5xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-extrabold text-slate-100 flex items-center gap-3">
          <BookOpen className="w-8 h-8 text-cyan-400" />
          Educational Cybersecurity Guide & Documentation
        </h1>
        <p className="text-slate-400 text-sm mt-1">
          Understanding URL anatomy, phishing deception strategies, heuristic analysis, and the safety boundaries of static pattern evaluation.
        </p>
      </div>

      {/* Critical Concept: Why HTTPS != Safe */}
      <div className="glass-card rounded-2xl p-6 sm:p-8 border border-amber-500/40 bg-amber-950/15 space-y-4">
        <div className="flex items-center gap-3 text-amber-400">
          <AlertTriangle className="w-6 h-6 shrink-0" />
          <h2 className="text-xl font-bold">
            Critical Security Concept: Why HTTPS Alone Does NOT Mean "Safe"
          </h2>
        </div>

        <p className="text-slate-200 text-sm leading-relaxed">
          A common and dangerous misconception among everyday web users is equating the padlock icon or <code className="text-amber-300 font-mono">https://</code> protocol with a website being trustworthy and safe.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono pt-2">
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
            <span className="text-cyan-400 font-bold block mb-1">WHAT HTTPS ACTUALLY GUARANTEES</span>
            <p className="text-slate-300 leading-relaxed font-sans">
              HTTPS ensures that data in transit between your browser and the remote server is encrypted using TLS, preventing eavesdropping and tampering by intermediaries (e.g., open public Wi-Fi).
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
            <span className="text-rose-400 font-bold block mb-1">WHAT HTTPS DOES NOT GUARANTEE</span>
            <p className="text-slate-300 leading-relaxed font-sans">
              HTTPS does NOT verify the intent of the website operator. Today, automated free certificate authorities (e.g. Let's Encrypt) provide certificates to anyone in seconds—including phishing operations. A phishing kit with HTTPS securely encrypts the stolen passwords back to the attacker.
            </p>
          </div>
        </div>
      </div>

      {/* URL Anatomy Diagram */}
      <div className="glass-card rounded-2xl p-6 sm:p-8 border border-slate-800 space-y-5">
        <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
          <Globe className="w-5 h-5 text-cyan-400" />
          Anatomy of a Phishing URL
        </h3>
        <p className="text-xs text-slate-400">
          Phishing attacks rely on deceiving the human eye through structural confusion in URL components:
        </p>

        <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 overflow-x-auto">
          <div className="font-mono text-sm flex items-center space-x-1 whitespace-nowrap text-slate-300">
            <span className="text-cyan-400 bg-cyan-950/40 px-2 py-1 rounded">https://</span>
            <span className="text-amber-400 bg-amber-950/40 px-2 py-1 rounded">secure.login.chase.com.</span>
            <span className="text-rose-400 bg-rose-950/40 px-2 py-1 rounded font-bold">attacker-spoof.xyz</span>
            <span className="text-slate-400">:443</span>
            <span className="text-purple-400 bg-purple-950/40 px-2 py-1 rounded">/account/verify.php</span>
            <span className="text-emerald-400 bg-emerald-950/40 px-2 py-1 rounded">?token=steal</span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4 text-[11px] font-mono text-slate-400">
            <div>
              <span className="text-cyan-400 block font-bold">1. Protocol</span>
              <span>Encrypted transport channel</span>
            </div>
            <div>
              <span className="text-amber-400 block font-bold">2. Subdomain Mimicry</span>
              <span>Deceptive brand name prefix</span>
            </div>
            <div>
              <span className="text-rose-400 block font-bold">3. Actual Domain & TLD</span>
              <span>Attacker's true registered host</span>
            </div>
            <div>
              <span className="text-purple-400 block font-bold">4. Lure Path & Query</span>
              <span>Deceptive credential page</span>
            </div>
          </div>
        </div>
      </div>

      {/* Detection Architecture & SSRF Prevention */}
      <div className="glass-card rounded-2xl p-6 sm:p-8 border border-slate-800 space-y-4">
        <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
          <Server className="w-5 h-5 text-cyan-400" />
          Platform Security Design & SSRF Immunity
        </h3>
        <p className="text-slate-300 text-xs sm:text-sm leading-relaxed">
          A critical architectural decision of this platform is that the backend does <strong>NOT make server-side HTTP requests</strong> to user-submitted target URLs.
        </p>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2 text-xs text-slate-300">
          <p>
            In many naive URL checkers, the server fetches the target webpage to read its HTML. This creates a severe cybersecurity vulnerability known as <strong>Server-Side Request Forgery (SSRF)</strong>, allowing attackers to trick the scanner into probing internal cloud metadata services (e.g. <code className="text-rose-300 font-mono">http://169.254.169.254</code>), internal VPC networks, or localhost databases.
          </p>
          <p>
            By restricting analysis strictly to string-level pattern extraction, lexical heuristics, and machine learning feature matrices, this application remains completely immune to SSRF exploits while offering instantaneous threat evaluations.
          </p>
        </div>
      </div>

      {/* Future Extensibility Architecture */}
      <div className="glass-card rounded-2xl p-6 sm:p-8 border border-slate-800 space-y-5">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div>
            <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <Layers className="w-5 h-5 text-cyan-400" />
              Future Extensibility Architecture
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Modular integration contracts designed for future enterprise threat intelligence feeds.
            </p>
          </div>
          <span className="text-xs font-mono px-2.5 py-1 rounded bg-slate-800 text-cyan-300 border border-slate-700">
            Phase 2 Pipeline
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {futureModules.map((mod, idx) => (
            <div key={idx} className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
              <div className="flex items-center justify-between">
                <span className="text-sm font-bold text-slate-200">{mod.name}</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                  {mod.status}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-2 font-sans leading-relaxed">
                {mod.desc}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Mandatory Disclaimer */}
      <div className="p-5 rounded-2xl bg-amber-950/20 border border-amber-500/30 flex items-start gap-3">
        <ShieldAlert className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <h4 className="text-xs font-bold font-mono text-amber-300 uppercase tracking-wider">
            Educational Disclaimer Notice
          </h4>
          <p className="text-xs text-amber-200/90 leading-relaxed font-sans">
            Pattern-based detection cannot guarantee that a website is safe or malicious. A URL classified as Safe may still be compromised or malicious. Phishing classification should always be interpreted as "Potential Phishing" based on URL patterns. Always verify the destination and source independently before submitting sensitive credentials.
          </p>
        </div>
      </div>
    </div>
  );
};
