import type { Metadata } from 'next'
import { Space_Grotesk, JetBrains_Mono } from 'next/font/google'
import './globals.css'
import Sidebar from '@/components/layout/Sidebar'
import TopBar from '@/components/layout/TopBar'

const display = Space_Grotesk({ subsets: ['latin'], variable: '--font-display' })
const mono = JetBrains_Mono({ subsets: ['latin'], variable: '--font-mono' })

export const metadata: Metadata = {
  title: 'AutoShield',
  description: 'Malware Analysis & Threat Intelligence Platform',
}

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className={`${display.variable} ${mono.variable} antialiased`}>
        <div className="app-shell flex">
          <Sidebar />
          <div className="app-main ml-60 w-[calc(100%-240px)] min-h-screen overflow-x-hidden">
            <TopBar />
            <main className="page-container">{children}</main>
          </div>
        </div>
      </body>
    </html>
  )
}
