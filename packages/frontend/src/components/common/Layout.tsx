import { ReactNode, useEffect, useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useSelector, useDispatch } from 'react-redux'
import {
  LayoutDashboard,
  Bell,
  Shield,
  ArrowRightLeft,
  Menu,
  X,
  LogOut,
  Database,
  BarChart3,
  Search,
  Settings,
  Webhook,
  Moon,
  Sun,
  Users,
  FileText,
  FileBarChart,
  AlertTriangle,
  Sparkles,
  LayoutGrid,
  Target,
  Clock,
  ChevronDown,
  Crosshair,
  Activity,
  Wrench,
  Bot,
  Plug,
  GitBranch,
  KeyRound,
  Mail,
  MessageSquare,
  Ticket,
  AlertCircle,
} from 'lucide-react'
import { RootState } from '../../store'
import { toggleSidebar } from '../../store/uiSlice'
import { logout } from '../../store/authSlice'
import { cn } from '../../lib/utils'
import RevOpsLogo from './RevOpsLogo'
import AlertNotifications from '../alerts/AlertNotifications'
import NotificationCenter from '../notifications/NotificationCenter'
import MobileNav from '../mobile/MobileNav'
import AIChatWidget from '../ai/AIChatWidget'

interface LayoutProps {
  children: ReactNode
}

interface NavItem {
  path: string
  label: string
  icon: React.ElementType
}

interface NavSection {
  id: string
  label: string
  icon: React.ElementType
  items: NavItem[]
}

// Grouped navigation structure
const navSections: NavSection[] = [
  {
    id: 'operations',
    label: 'Security Ops',
    icon: AlertTriangle,
    items: [
      { path: '/alerts', label: 'Alerts', icon: Bell },
      { path: '/alerts/clusters', label: 'Alert Clusters', icon: LayoutGrid },
      { path: '/incidents', label: 'Incidents', icon: AlertTriangle },
      { path: '/oncall', label: 'On-Call', icon: Users },
      { path: '/escalation-policies', label: 'Escalation', icon: Bell },
    ],
  },
  {
    id: 'automation',
    label: 'Automation',
    icon: GitBranch,
    items: [
      { path: '/connectors', label: 'Connectors', icon: Plug },
      { path: '/pipelines', label: 'Pipelines', icon: GitBranch },
      { path: '/workflows', label: 'Workflows', icon: GitBranch },
    ],
  },
  {
    id: 'investigation',
    label: 'Investigation',
    icon: Crosshair,
    items: [
      { path: '/queries', label: 'Query Explorer', icon: Database },
      { path: '/ioc-search', label: 'IOC Search', icon: Search },
      { path: '/threat-intel', label: 'Threat Intel', icon: Shield },
      { path: '/threat-hunting', label: 'Threat Hunting', icon: Crosshair },
    ],
  },
  {
    id: 'integrations',
    label: 'Integrations',
    icon: Plug,
    items: [
      { path: '/integrations', label: 'All Integrations', icon: Plug },
    ],
  },
  {
    id: 'tools',
    label: 'Tools',
    icon: ArrowRightLeft,
    items: [
      { path: '/migration', label: 'Migration Hub', icon: ArrowRightLeft },
    ],
  },
  {
    id: 'analytics',
    label: 'Analytics',
    icon: Activity,
    items: [
      { path: '/analytics', label: 'Overview', icon: BarChart3 },
      { path: '/executive-summary', label: 'Executive Summary', icon: BarChart3 },
      { path: '/compliance', label: 'Compliance', icon: Shield },
      { path: '/mitre', label: 'MITRE ATT&CK', icon: Target },
      { path: '/rule-health', label: 'Rule Health', icon: Activity },
      { path: '/sla', label: 'SLA Tracking', icon: Clock },
      { path: '/dashboards', label: 'Dashboards', icon: LayoutGrid },
      { path: '/reports', label: 'Reports', icon: FileBarChart },
      { path: '/report-builder', label: 'Report Builder', icon: FileBarChart },
    ],
  },
  {
    id: 'admin',
    label: 'Administration',
    icon: Wrench,
    items: [
      { path: '/webhooks', label: 'Webhooks', icon: Webhook },
      { path: '/enrichment', label: 'Enrichment', icon: Sparkles },
      { path: '/asset-criticality', label: 'Asset Criticality', icon: Shield },
      { path: '/roles', label: 'Roles', icon: Users },
      { path: '/audit', label: 'Audit Logs', icon: FileText },
      { path: '/settings', label: 'Settings', icon: Settings },
      { path: '/settings/ai', label: 'AI Settings', icon: Bot },
      { path: '/settings/sso', label: 'SSO Settings', icon: KeyRound },
      { path: '/playbook-generator', label: 'Playbook AI', icon: Sparkles },
    ],
  },
]

function NavSectionComponent({
  section,
  isExpanded,
  onToggle,
  pathname,
}: {
  section: NavSection
  isExpanded: boolean
  onToggle: () => void
  pathname: string
}) {
  const hasActiveItem = section.items.some(
    (item) => pathname === item.path || (item.path !== '/' && pathname.startsWith(item.path))
  )

  return (
    <div className="mb-1">
      <button
        onClick={onToggle}
        className={cn(
          'flex items-center justify-between w-full px-3 py-2 text-sm font-medium rounded-md transition-colors',
          hasActiveItem
            ? 'text-foreground bg-accent/50'
            : 'text-muted-foreground hover:text-foreground hover:bg-accent/50'
        )}
      >
        <div className="flex items-center gap-2">
          <section.icon size={16} />
          <span>{section.label}</span>
        </div>
        <ChevronDown
          size={14}
          className={cn('transition-transform', isExpanded ? 'rotate-180' : '')}
        />
      </button>

      {isExpanded && (
        <div className="mt-1 ml-3 pl-3 border-l border-border space-y-1">
          {section.items.map((item) => {
            const isActive =
              pathname === item.path || (item.path !== '/' && pathname.startsWith(item.path))
            return (
              <Link
                key={item.path}
                to={item.path}
                className={cn(
                  'flex items-center gap-2 rounded-md px-2 py-1.5 text-sm transition-colors',
                  isActive
                    ? 'bg-primary text-primary-foreground font-medium'
                    : 'text-muted-foreground hover:text-foreground hover:bg-accent'
                )}
              >
                <item.icon size={14} />
                {item.label}
              </Link>
            )
          })}
        </div>
      )}
    </div>
  )
}

export default function Layout({ children }: LayoutProps) {
  const location = useLocation()
  const navigate = useNavigate()
  const dispatch = useDispatch()
  const sidebarOpen = useSelector((state: RootState) => state.ui.sidebarOpen)
  const { userEmail, userName, refreshToken } = useSelector((state: RootState) => state.auth)

  // Theme state (stored in localStorage)
  const [theme, setTheme] = useState(() => localStorage.getItem('theme') || 'dark')

  // Track expanded sections - auto-expand section with active item
  const [expandedSections, setExpandedSections] = useState<Set<string>>(() => {
    const initial = new Set<string>()
    navSections.forEach((section) => {
      if (
        section.items.some(
          (item) =>
            location.pathname === item.path ||
            (item.path !== '/' && location.pathname.startsWith(item.path))
        )
      ) {
        initial.add(section.id)
      }
    })
    // Default expand operations if nothing else is active
    if (initial.size === 0) {
      initial.add('operations')
    }
    return initial
  })

  const toggleSection = (sectionId: string) => {
    setExpandedSections((prev) => {
      const next = new Set(prev)
      if (next.has(sectionId)) {
        next.delete(sectionId)
      } else {
        next.add(sectionId)
      }
      return next
    })
  }

  const toggleTheme = () => {
    const newTheme = theme === 'dark' ? 'light' : 'dark'
    setTheme(newTheme)
    localStorage.setItem('theme', newTheme)
  }

  // Apply theme on mount and when theme changes
  useEffect(() => {
    if (theme === 'dark') {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
  }, [theme])

  // Auto-expand section when navigating
  useEffect(() => {
    navSections.forEach((section) => {
      if (
        section.items.some(
          (item) =>
            location.pathname === item.path ||
            (item.path !== '/' && location.pathname.startsWith(item.path))
        )
      ) {
        setExpandedSections((prev) => new Set(prev).add(section.id))
      }
    })
  }, [location.pathname])

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Ignore if typing in an input
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) {
        return
      }

      // g + key navigation
      if (e.key === 'g') {
        const handleNav = (nextKey: KeyboardEvent) => {
          if (nextKey.key === 'a') navigate('/alerts')
          else if (nextKey.key === 'r') navigate('/rules')
          else if (nextKey.key === 'q') navigate('/queries')
          else if (nextKey.key === 's') navigate('/settings')
          else if (nextKey.key === 'd') navigate('/')
          else if (nextKey.key === 'i') navigate('/ioc-search')
          else if (nextKey.key === 'm') navigate('/migration')
          window.removeEventListener('keydown', handleNav)
        }
        window.addEventListener('keydown', handleNav, { once: true })
        setTimeout(() => window.removeEventListener('keydown', handleNav), 1000)
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [navigate])

  const handleLogout = async () => {
    // Try to logout on backend if we have a refresh token
    if (refreshToken) {
      try {
        await fetch(`${import.meta.env.VITE_API_BASE_URL || ''}/api/v1/auth/logout`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: refreshToken }),
        })
      } catch (err) {
        console.warn('Backend logout failed:', err)
      }
    }
    dispatch(logout())
    navigate('/login')
  }

  const isDashboardActive = location.pathname === '/'

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 w-full border-b border-border bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="flex h-14 items-center justify-between px-4">
          <div className="flex items-center">
            <button
              onClick={() => dispatch(toggleSidebar())}
              className="mr-4 p-2 hover:bg-accent rounded-md transition-colors"
            >
              {sidebarOpen ? <X size={20} /> : <Menu size={20} />}
            </button>
            <div className="flex items-center gap-2">
              <RevOpsLogo size={32} />
              <span className="font-semibold text-lg">RevOps</span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {(userName || userEmail) && (
              <div className="hidden sm:flex items-center gap-2 text-sm text-muted-foreground">
                <span>{userName || userEmail}</span>
              </div>
            )}
            <AlertNotifications />
            <NotificationCenter />
            <button
              onClick={toggleTheme}
              className="p-2 hover:bg-accent rounded-md transition-colors"
              title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            >
              {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
            </button>
            <button
              onClick={handleLogout}
              className="flex items-center gap-2 px-3 py-1.5 text-sm text-muted-foreground hover:text-foreground hover:bg-accent rounded-md transition-colors"
            >
              <LogOut size={16} />
              <span className="hidden sm:inline">Logout</span>
            </button>
          </div>
        </div>
      </header>

      <div className="flex">
        {/* Sidebar - Hidden on mobile, shown on md+ */}
        <aside
          className={cn(
            'hidden md:flex md:flex-col fixed left-0 top-14 z-40 h-[calc(100vh-3.5rem)] w-56 border-r border-border bg-background transition-transform duration-300',
            sidebarOpen ? 'translate-x-0' : '-translate-x-full'
          )}
        >
          {/* Scrollable nav area */}
          <nav className="flex-1 flex flex-col p-3 overflow-y-auto">
            {/* Top-level items */}
            <Link
              to="/"
              className={cn(
                'flex items-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition-colors',
                isDashboardActive
                  ? 'bg-primary text-primary-foreground'
                  : 'text-muted-foreground hover:text-foreground hover:bg-accent'
              )}
            >
              <LayoutDashboard size={16} />
              Dashboard
            </Link>

            <div className="h-px bg-border mb-2" />

            {/* Collapsible sections */}
            {navSections.map((section) => (
              <NavSectionComponent
                key={section.id}
                section={section}
                isExpanded={expandedSections.has(section.id)}
                onToggle={() => toggleSection(section.id)}
                pathname={location.pathname}
              />
            ))}
          </nav>

          {/* Keyboard shortcuts hint - fixed at bottom */}
          <div className="flex-shrink-0 p-3 border-t border-border bg-background">
            <p className="text-xs text-muted-foreground">
              <kbd className="px-1 bg-muted rounded text-[10px]">g</kbd>+
              <kbd className="px-1 bg-muted rounded text-[10px]">c</kbd>/
              <kbd className="px-1 bg-muted rounded text-[10px]">a</kbd>/
              <kbd className="px-1 bg-muted rounded text-[10px]">r</kbd>{' '}
              quick nav
            </p>
          </div>
        </aside>

        {/* Main content */}
        <main
          className={cn(
            'flex-1 transition-all duration-300',
            sidebarOpen ? 'md:ml-56' : 'ml-0'
          )}
        >
          <div className="container mx-auto p-4 md:p-6 pb-20 md:pb-6">{children}</div>
        </main>
      </div>

      {/* Mobile Navigation */}
      <MobileNav />

      {/* AI Chat Widget */}
      <AIChatWidget />
    </div>
  )
}
