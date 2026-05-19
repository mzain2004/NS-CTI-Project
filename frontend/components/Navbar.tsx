import Link from 'next/link';

export default function Navbar() {
  return (
    <nav className="border-b border-white/10 bg-[#0a0a0f]/50 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 bg-[#7c6af7] rounded-lg rotate-45 flex items-center justify-center">
            <span className="text-white font-bold -rotate-45">S</span>
          </div>
          <span className="font-bold text-xl tracking-tight">AutoShield</span>
        </div>
        <div className="flex gap-6 text-sm font-medium">
          <Link href="/" className="hover:text-[#00d4aa] transition-colors">Dashboard</Link>
          <Link href="/reports" className="hover:text-[#00d4aa] transition-colors">Threat Reports</Link>
          <Link href="/logs" className="hover:text-[#00d4aa] transition-colors">Active Defense</Link>
        </div>
      </div>
    </nav>
  );
}
