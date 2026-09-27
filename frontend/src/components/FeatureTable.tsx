import React, { useState } from 'react';
import { Table, Check, X, Search, ChevronDown, ChevronUp } from 'lucide-react';
import { URLFeatures } from '../types';

interface FeatureTableProps {
  features: URLFeatures;
}

export const FeatureTable: React.FC<FeatureTableProps> = ({ features }) => {
  const [showAll, setShowAll] = useState(false);
  const [filterQuery, setFilterQuery] = useState('');

  const featureItems = [
    { label: 'URL Length', value: `${features.url_length} chars`, isWarning: features.url_length > 75, category: 'Basic' },
    { label: 'Domain Length', value: `${features.domain_length} chars`, isWarning: features.domain_length > 30, category: 'Basic' },
    { label: 'Subdomains Count', value: features.subdomain_count, isWarning: features.subdomain_count >= 3, category: 'Structure' },
    { label: 'Special Characters Count', value: features.special_character_count, isWarning: features.special_character_count > 10, category: 'Basic' },
    { label: 'HTTPS Protocol', value: features.has_https ? 'Yes' : 'No', isWarning: !features.has_https, category: 'Security' },
    { label: 'IP Address as Hostname', value: features.has_ip_address ? 'Yes (Detected)' : 'No', isWarning: features.has_ip_address, category: 'Security' },
    { label: 'Brand Impersonation', value: features.has_brand_impersonation ? `Detected (${features.impersonated_brand})` : (features.is_authorized_brand ? 'Authorized Brand Domain' : 'None'), isWarning: !!features.has_brand_impersonation, category: 'Security' },
    { label: 'Hostname Shannon Entropy', value: features.entropy_hostname !== undefined ? `${features.entropy_hostname.toFixed(2)}` : 'N/A', isWarning: (features.entropy_hostname || 0) > 4.2, category: 'Entropy' },
    { label: 'Domain Shannon Entropy', value: features.entropy_domain !== undefined ? `${features.entropy_domain.toFixed(2)}` : 'N/A', isWarning: (features.entropy_domain || 0) > 4.0, category: 'Entropy' },
    { label: 'Suspicious Keywords', value: features.suspicious_keyword_count, isWarning: features.suspicious_keyword_count > 0, category: 'Security' },
    { label: 'Open Redirect Target', value: features.has_redirect_param ? 'Yes (Detected in Query)' : 'No', isWarning: !!features.has_redirect_param, category: 'Security' },
    { label: 'Executable Download Target', value: features.has_executable_ext ? 'Yes (Detected .exe/.scr/etc)' : 'No', isWarning: !!features.has_executable_ext, category: 'Security' },
    { label: 'Punycode / IDN (xn--)', value: features.has_punycode ? 'Yes (Detected)' : 'No', isWarning: features.has_punycode, category: 'Security' },
    { label: 'URL Shortener Service', value: features.has_url_shortener ? 'Yes (Detected)' : 'No', isWarning: features.has_url_shortener, category: 'Security' },
    { label: 'Percent-Encoded Obfuscation', value: features.has_percent_encoding ? `Yes (${features.percent_encoding_count})` : 'No', isWarning: features.has_percent_encoding, category: 'Security' },
    { label: '@ Symbol Present', value: features.has_at_symbol ? 'Yes (Detected)' : 'No', isWarning: features.has_at_symbol, category: 'Security' },
    { label: 'Double Slash in Path (//)', value: features.has_double_slash_path ? 'Yes (Detected)' : 'No', isWarning: features.has_double_slash_path, category: 'Structure' },
    { label: 'Hyphen-Heavy Domain', value: features.is_hyphen_heavy_domain ? `Yes (${features.domain_hyphen_count})` : `No (${features.domain_hyphen_count})`, isWarning: features.is_hyphen_heavy_domain, category: 'Structure' },
    { label: 'Custom / Non-Standard Port', value: features.has_suspicious_port ? `Port ${features.custom_port}` : 'Standard', isWarning: features.has_suspicious_port, category: 'Security' },
    { label: 'Query Parameters Count', value: features.query_param_count, isWarning: features.query_param_count > 4, category: 'Basic' },
    { label: 'Subdirectory Path Depth', value: features.path_depth, isWarning: features.path_depth >= 4, category: 'Structure' },
    { label: 'Dot Count', value: features.dot_count, isWarning: features.dot_count >= 4, category: 'Basic' },
    { label: 'Digit Count', value: features.digit_count, isWarning: features.digit_count >= 10, category: 'Basic' },
  ];

  const filteredItems = featureItems.filter((item) =>
    item.label.toLowerCase().includes(filterQuery.toLowerCase()) ||
    item.category.toLowerCase().includes(filterQuery.toLowerCase())
  );

  const displayedItems = showAll ? filteredItems : filteredItems.slice(0, 10);

  return (
    <div className="glass-card rounded-2xl p-6 border border-slate-800">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800/80 gap-3">
        <div>
          <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <Table className="w-5 h-5 text-cyan-400" />
            Extracted URL Feature Matrix
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Static mathematical and security attributes extracted during parsing.
          </p>
        </div>

        <div className="relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search features..."
            value={filterQuery}
            onChange={(e) => setFilterQuery(e.target.value)}
            className="pl-9 pr-3 py-1.5 bg-slate-900 text-xs rounded-lg border border-slate-700 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>
      </div>

      <div className="mt-4 overflow-x-auto">
        <table className="w-full text-left text-xs font-mono">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[11px]">
              <th className="pb-3 font-semibold">Security Feature</th>
              <th className="pb-3 font-semibold">Category</th>
              <th className="pb-3 font-semibold">Value</th>
              <th className="pb-3 font-semibold text-right">Risk Evaluation</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {displayedItems.map((item, idx) => (
              <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                <td className="py-2.5 font-medium text-slate-200">
                  {item.label}
                </td>
                <td className="py-2.5 text-slate-400">
                  <span className="px-2 py-0.5 rounded bg-slate-800/80 text-[10px]">
                    {item.category}
                  </span>
                </td>
                <td className="py-2.5 text-slate-300 font-bold">
                  {item.value}
                </td>
                <td className="py-2.5 text-right">
                  {item.isWarning ? (
                    <span className="inline-flex items-center gap-1 text-rose-400 bg-rose-500/10 border border-rose-500/20 px-2 py-0.5 rounded text-[10px]">
                      <X className="w-3 h-3" /> Flagged
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded text-[10px]">
                      <Check className="w-3 h-3" /> Normal
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {filteredItems.length > 10 && (
        <div className="mt-4 pt-3 border-t border-slate-800/60 text-center">
          <button
            onClick={() => setShowAll(!showAll)}
            className="inline-flex items-center gap-1.5 text-xs font-medium text-cyan-400 hover:text-cyan-300 transition-colors"
          >
            {showAll ? (
              <>
                Show Less <ChevronUp className="w-4 h-4" />
              </>
            ) : (
              <>
                Show All Features ({filteredItems.length}) <ChevronDown className="w-4 h-4" />
              </>
            )}
          </button>
        </div>
      )}
    </div>
  );
};
