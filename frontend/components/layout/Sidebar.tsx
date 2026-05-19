import { LayoutDashboard, Upload, Bug, Shield, Network, FileText } from 'lucide-react';
import { useState, useEffect } from 'react';

const navItems = [
  { name: 'Dashboard', icon: LayoutDashboard, href: '/' },
  { name: 'Analyze', icon: Upload, href: '/analyze' },
  { name: 'Cowrie', icon: Bug, href: '/cowrie' },
  { name: 'Wazuh', icon: Shield, href: '/wazuh' },
  { name: 'pfSense', icon: Network, href: '/pfsense' },
  { name: 'Reports', icon: FileText, href: '/reports' },
];

export default function Sidebar() {
  const [apiStatus, setApiStatus] = useState('Checking...');

  useEffect(() => {
    const checkApiStatus = async () => {
      try {
        const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/health`);
        setApiStatus(response.ok ? 'Online' : 'Offline');
      } catch {
        setApiStatus('Offline');
      }
    };
    checkApiStatus();
  }, []);

  return (
    <aside className="fixed top-0 left-0 h-full w-60 bg-[#111827] text-[#f9fafb] flex flex-col">
      <div className="flex items-center justify-center h-16 border-b border-[#374151]">
        <span className="text-xl font-bold">NS-CTI</span>
      </div>
      <nav className="flex-1 overflow-y-auto">
        <ul className="space-y-2 p-4">
          {navItems.map(({ name, icon: Icon, href }) => (
            <li key={name}>
              <Link href={href} className="flex items-center gap-3 p-2 rounded hover:bg-[#1f2937]">
                <Icon className="w-5 h-5" />
                <span>{name}</span>
              </Link>
            </li>
          ))}
        </ul>
      </nav>
      <div className="p-4 border-t border-[#374151]">
        <p className="text-sm">API Status: {apiStatus}</p>
      </div>
    </aside>
  );
}