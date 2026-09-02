import React, { useState, useEffect, useMemo } from 'react';
import { Header } from './components/common/Header';
import { HeroCarouselCard } from './components/dashboard/HeroCarouselCard';
import { ConcentricProgressRing } from './components/dashboard/ConcentricProgressRing';
import { VendorProjectGrid } from './components/dashboard/VendorProjectGrid';
import { StatCardsGrid } from './components/dashboard/StatCardsGrid';
import { VisualAnalytics } from './components/dashboard/VisualAnalytics';
import { FilterBar } from './components/dashboard/FilterBar';
import { EventFeed } from './components/dashboard/EventFeed';
import { SecurityChatbot } from './components/chat/SecurityChatbot';
import { ArchitectureView } from './components/docs/ArchitectureView';
import { DrilldownModal } from './components/drilldown/DrilldownModal';
import { InstantIngestModal } from './components/ingest/InstantIngestModal';
import { NotificationDrawer, NotificationItem } from './components/notifications/NotificationDrawer';
import { SettingsModal } from './components/settings/SettingsModal';
import { BottomDock, ActiveTabType } from './components/common/BottomDock';
import { AutoMappingStudio } from './components/assistant/AutoMappingStudio';
import { OCSFEvent, OCSFClassName } from './types/ocsf';
import { FilterState, SummaryStats } from './types/events';
import { apiService, BackendStatus } from './services/apiService';
import { SAMPLE_RAW_LOGS } from './data/sampleRawLogs';

export const App: React.FC = () => {
  // Navigation: 'dashboard' | 'analytics' | 'assistant' | 'ingest' | 'chat' | 'docs'
  const [activeTab, setActiveTab] = useState<ActiveTabType>('dashboard');

  // Events & Backend State
  const [events, setEvents] = useState<OCSFEvent[]>([]);
  const [backendStatus, setBackendStatus] = useState<BackendStatus>({
    connected: false,
    url: 'http://localhost:8000 (Mock Mode)',
    lastChecked: new Date().toISOString()
  });
  const [mockMode, setMockMode] = useState<boolean>(true);

  // Modals & Drawers
  const [selectedEvent, setSelectedEvent] = useState<OCSFEvent | null>(null);
  const [isIngestModalOpen, setIsIngestModalOpen] = useState<boolean>(false);
  const [isNotificationsOpen, setIsNotificationsOpen] = useState<boolean>(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState<boolean>(false);
  const [isLiveStreaming, setIsLiveStreaming] = useState<boolean>(false);

  // Notifications List
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);

  // Filters
  const [filters, setFilters] = useState<FilterState>({
    searchQuery: '',
    selectedClass: 'ALL',
    selectedVendor: 'ALL',
    selectedAction: 'ALL',
    selectedSeverity: 'ALL',
    timeRange: 'ALL',
    ipFilter: '',
    portFilter: ''
  });

  // Load initial events & notifications
  useEffect(() => {
    const init = async () => {
      const status = await apiService.checkHealth();
      setBackendStatus(status);
      const initialEvents = await apiService.getEvents();
      setEvents(initialEvents);

      // Seed initial security notifications linked to mock events
      if (initialEvents.length > 0) {
        setNotifications([
          {
            id: 'notif-1',
            title: 'Critical Threat Finding: SQL Injection',
            desc: 'Suricata EVE IDS triggered on DMZ web server (45.33.32.156 -> 10.0.4.80:80)',
            timeAgo: '2m ago',
            type: 'critical',
            read: false,
            eventRef: initialEvents.find(e => e.class_name === 'Detection Finding') || initialEvents[0]
          },
          {
            id: 'notif-2',
            title: 'Perimeter Rule Block: SSH Reconnaissance',
            desc: 'Palo Alto edge-fw-01 blocked external connection on port 22 (203.0.113.45)',
            timeAgo: '8m ago',
            type: 'deny',
            read: false,
            eventRef: initialEvents[0]
          },
          {
            id: 'notif-3',
            title: 'SMB Exploit Vector Blocked',
            desc: 'Fortinet FortiOS default-deny-inbound blocked inbound port 445',
            timeAgo: '18m ago',
            type: 'deny',
            read: true,
            eventRef: initialEvents[2] || initialEvents[0]
          },
          {
            id: 'notif-4',
            title: 'YAML Mapping Engine Online',
            desc: '4 declarative vendor parsers active with 100% lossless OCSF schema compliance',
            timeAgo: '1h ago',
            type: 'system',
            read: true
          }
        ]);
      }
    };
    init();
  }, []);

  // Periodic health check
  useEffect(() => {
    const timer = setInterval(async () => {
      const status = await apiService.checkHealth();
      setBackendStatus(status);
    }, 15000);
    return () => clearInterval(timer);
  }, []);

  // Live stream generator
  useEffect(() => {
    if (!isLiveStreaming) return;

    const streamInterval = setInterval(async () => {
      const randomSample = SAMPLE_RAW_LOGS[Math.floor(Math.random() * SAMPLE_RAW_LOGS.length)];
      try {
        const newEvent = await apiService.ingestRaw(randomSample.raw);
        setEvents(prev => [newEvent, ...prev]);

        // If it's a critical alert, push a notification
        if (newEvent.class_name === 'Detection Finding') {
          setNotifications(prev => [
            {
              id: `notif-${Date.now()}`,
              title: `New Finding: ${newEvent.finding_info?.title || 'Security Alert'}`,
              desc: `Source ${newEvent.src_endpoint?.ip} targeting ${newEvent.dst_endpoint?.ip}`,
              timeAgo: 'Just now',
              type: 'critical',
              read: false,
              eventRef: newEvent
            },
            ...prev
          ]);
        }
      } catch (err) {
        console.error('Stream simulation error:', err);
      }
    }, 3200);

    return () => clearInterval(streamInterval);
  }, [isLiveStreaming]);

  // Compute available vendors
  const availableVendors = useMemo(() => {
    const vendorSet = new Set<string>();
    events.forEach(e => {
      const v = e.device?.vendor_name || e.source_vendor;
      if (v) vendorSet.add(v);
    });
    return Array.from(vendorSet);
  }, [events]);

  // Apply filters
  const filteredEvents = useMemo(() => {
    return events.filter(event => {
      if (filters.searchQuery.trim()) {
        const query = filters.searchQuery.toLowerCase();
        const str = `${event.raw_data} ${event.event_uid} ${event.class_name} ${event.device?.vendor_name} ${event.device?.name} ${event.src_endpoint?.ip} ${event.dst_endpoint?.ip} ${event.firewall_rule?.name || ''} ${event.finding_info?.title || ''}`.toLowerCase();
        if (!str.includes(query)) return false;
      }

      if (filters.selectedClass !== 'ALL' && event.class_name !== filters.selectedClass) {
        return false;
      }

      if (filters.selectedVendor !== 'ALL') {
        const v = event.device?.vendor_name || event.source_vendor;
        if (v !== filters.selectedVendor) return false;
      }

      if (filters.selectedAction !== 'ALL') {
        if (filters.selectedAction === 'Deny' && event.activity_name?.toLowerCase() !== 'deny' && event.activity_name?.toLowerCase() !== 'drop') return false;
        if (filters.selectedAction === 'Allow' && event.activity_name?.toLowerCase() !== 'allow' && event.activity_name?.toLowerCase() !== 'accept') return false;
        if (filters.selectedAction === 'Create' && event.activity_name?.toLowerCase() !== 'create') return false;
      }

      if (filters.selectedSeverity !== 'ALL' && event.severity !== filters.selectedSeverity) {
        return false;
      }

      return true;
    });
  }, [events, filters]);

  // Summary statistics
  const summaryStats: SummaryStats = useMemo(() => {
    let denyCount = 0;
    let allowCount = 0;
    let activeFindings = 0;
    const vendorCounts: Record<string, number> = {};
    const classCounts: Record<string, number> = {};

    events.forEach(e => {
      if (e.activity_name?.toLowerCase() === 'deny' || e.activity_name?.toLowerCase() === 'drop') {
        denyCount++;
      } else if (e.activity_name?.toLowerCase() === 'allow' || e.activity_name?.toLowerCase() === 'accept') {
        allowCount++;
      }

      if (e.class_name === 'Detection Finding') {
        activeFindings++;
      }

      const v = e.device?.vendor_name || e.source_vendor || 'Other';
      vendorCounts[v] = (vendorCounts[v] || 0) + 1;
      classCounts[e.class_name] = (classCounts[e.class_name] || 0) + 1;
    });

    return {
      totalEvents: events.length,
      activeSources: Object.keys(vendorCounts).length,
      denyCount,
      allowCount,
      activeFindings,
      losslessPreservationRate: 100,
      vendorCounts,
      classCounts,
      eventsPerSecond: isLiveStreaming ? 14 : 0
    };
  }, [events, isLiveStreaming]);

  // Handlers
  const handleFilterChange = (newFilters: Partial<FilterState>) => {
    setFilters(prev => ({ ...prev, ...newFilters }));
  };

  const handleResetFilters = () => {
    setFilters({
      searchQuery: '',
      selectedClass: 'ALL',
      selectedVendor: 'ALL',
      selectedAction: 'ALL',
      selectedSeverity: 'ALL',
      timeRange: 'ALL',
      ipFilter: '',
      portFilter: ''
    });
  };

  const handleToggleMockMode = () => {
    const nextMode = !mockMode;
    setMockMode(nextMode);
    apiService.setMockMode(nextMode);
    apiService.checkHealth().then(setBackendStatus);
  };

  const handleResetEvents = () => {
    const fresh = apiService.resetLocalEvents();
    setEvents(fresh);
  };

  const handleEventIngested = (newEvent: OCSFEvent) => {
    setEvents(prev => [newEvent, ...prev]);
  };

  const handleMarkAllRead = () => {
    setNotifications(prev => prev.map(n => ({ ...n, read: true })));
  };

  const handleClearNotifications = () => {
    setNotifications([]);
  };

  const handleExportNDJSON = () => {
    const ndjson = filteredEvents.map(e => JSON.stringify(e)).join('\n');
    const blob = new Blob([ndjson], { type: 'application/x-ndjson' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `logfusion-ocsf-export-${Date.now()}.ndjson`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const unreadCount = notifications.filter(n => !n.read).length;

  return (
    <div className="min-h-screen bg-[#0c0e17] text-slate-100 flex flex-col font-sans pb-28">
      
      {/* Top Header & Greeting Bar */}
      <Header
        backendStatus={backendStatus}
        mockMode={mockMode}
        onToggleMockMode={handleToggleMockMode}
        onResetEvents={handleResetEvents}
        totalEventsCount={events.length}
        unreadNotificationsCount={unreadCount}
        onOpenNotifications={() => setIsNotificationsOpen(true)}
        onOpenSettings={() => setIsSettingsOpen(true)}
      />

      {/* Main App Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 space-y-6">
        
        {/* VIEW 1: OVERVIEW & FEED (Mockup Screen 1) */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6 animate-fade-in">
            {/* Hero Incident Carousel Card */}
            <HeroCarouselCard
              topEvent={events[0]}
              onInspect={(e) => setSelectedEvent(e)}
            />

            {/* KPI Stat Cards */}
            <StatCardsGrid
              stats={summaryStats}
              onFilterClick={(type, val) => {
                if (type === 'action') handleFilterChange({ selectedAction: val });
                if (type === 'class') handleFilterChange({ selectedClass: val as OCSFClassName });
                if (type === 'vendor') handleFilterChange({ selectedVendor: val });
                if (type === 'reset') handleResetFilters();
              }}
            />

            {/* Smooth Wave Area Chart with Interactive Weeks/Days/Months Dropdown */}
            <VisualAnalytics events={events} />

            {/* Filter and Search Bar */}
            <FilterBar
              filters={filters}
              onFilterChange={handleFilterChange}
              onResetFilters={handleResetFilters}
              isLiveStreaming={isLiveStreaming}
              onToggleStreaming={() => setIsLiveStreaming(!isLiveStreaming)}
              onExportNDJSON={handleExportNDJSON}
              availableVendors={availableVendors}
            />

            {/* Unified Event Feed */}
            <EventFeed
              events={filteredEvents}
              onSelectEvent={(e) => setSelectedEvent(e)}
              selectedEventId={selectedEvent?.event_uid}
              onOpenIngestLab={() => setIsIngestModalOpen(true)}
            />
          </div>
        )}

        {/* VIEW 2: STATISTICS & CONCENTRIC RINGS (Mockup Screen 2) */}
        {activeTab === 'analytics' && (
          <div className="space-y-6 animate-fade-in">
            <ConcentricProgressRing stats={summaryStats} />
            <VendorProjectGrid
              stats={summaryStats}
              selectedVendor={filters.selectedVendor}
              onSelectVendor={(v) => handleFilterChange({ selectedVendor: v })}
            />
            <VisualAnalytics events={events} />
          </div>
        )}

        {/* VIEW 3: AUTO-MAPPING ASSISTANT STUDIO */}
        {activeTab === 'assistant' && (
          <div className="animate-fade-in">
            <AutoMappingStudio
              onEventIngested={handleEventIngested}
              onOpenDrilldown={(e) => setSelectedEvent(e)}
            />
          </div>
        )}

        {/* VIEW 4: JOI AI CHATBOT */}
        {activeTab === 'chat' && (
          <div className="animate-fade-in">
            <SecurityChatbot
              events={events}
              onOpenDrilldown={(e) => setSelectedEvent(e)}
            />
          </div>
        )}

        {/* VIEW 4: OCSF DOCS & YAML MAPPING CONFIGS */}
        {activeTab === 'docs' && (
          <div className="animate-fade-in">
            <ArchitectureView />
          </div>
        )}

      </main>

      {/* Floating Bottom Navigation Dock */}
      <BottomDock
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenIngestModal={() => setIsIngestModalOpen(true)}
      />

      {/* Instant Ingest & Normalization Modal (Triggered by + Button) */}
      <InstantIngestModal
        isOpen={isIngestModalOpen}
        onClose={() => setIsIngestModalOpen(false)}
        onEventIngested={handleEventIngested}
        onOpenDrilldown={(e) => setSelectedEvent(e)}
      />

      {/* Notifications Drawer (Triggered by Bell Button) */}
      <NotificationDrawer
        isOpen={isNotificationsOpen}
        onClose={() => setIsNotificationsOpen(false)}
        notifications={notifications}
        onMarkAllRead={handleMarkAllRead}
        onClearAll={handleClearNotifications}
        onSelectEvent={(e) => setSelectedEvent(e)}
      />

      {/* Settings Modal (Triggered by Gear Button / Avatar) */}
      <SettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        mockMode={mockMode}
        onToggleMockMode={handleToggleMockMode}
        backendStatus={backendStatus}
        onResetEvents={handleResetEvents}
      />

      {/* Forensic Drill-Down Modal (Side-by-Side Raw vs OCSF JSON) */}
      {selectedEvent && (
        <DrilldownModal
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
        />
      )}

    </div>
  );
};
