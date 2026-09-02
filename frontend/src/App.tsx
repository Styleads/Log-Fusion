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
import { SettingsModal } from './components/settings/SettingsModal';
import { BottomDock, ActiveTabType } from './components/common/BottomDock';
import { AutoMappingStudio } from './components/assistant/AutoMappingStudio';
import { OCSFEvent, OCSFClassName } from './types/ocsf';
import { FilterState, SummaryStats } from './types/events';
import { apiService, BackendStatus } from './services/apiService';

export const App: React.FC = () => {
  // Navigation: 'dashboard' | 'analytics' | 'assistant' | 'chat' | 'docs'
  const [activeTab, setActiveTab] = useState<ActiveTabType>('dashboard');

  // Events & Backend State
  const [events, setEvents] = useState<OCSFEvent[]>([]);
  const [backendStatus, setBackendStatus] = useState<BackendStatus>({
    connected: false,
    url: 'http://localhost:8000 (Mock Mode)',
    lastChecked: new Date().toISOString()
  });
  const [mockMode, setMockMode] = useState<boolean>(false);
  const [realDataOnly, setRealDataOnly] = useState<boolean>(false);

  // Modals
  const [selectedEvent, setSelectedEvent] = useState<OCSFEvent | null>(null);
  const [isIngestModalOpen, setIsIngestModalOpen] = useState<boolean>(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState<boolean>(false);
  const [isLiveStreaming, setIsLiveStreaming] = useState<boolean>(false);

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

  // Load initial events from OpenSearch or fallback mock
  useEffect(() => {
    const init = async () => {
      const status = await apiService.checkHealth();
      setBackendStatus(status);
      const initialEvents = await apiService.getEvents();
      setEvents(initialEvents);
    };
    init();

    // Poll backend health status every 15s
    const interval = setInterval(async () => {
      const status = await apiService.checkHealth();
      setBackendStatus(status);
    }, 15000);

    return () => clearInterval(interval);
  }, []);

  // Live streaming simulator effect
  useEffect(() => {
    if (!isLiveStreaming) return;
    const timer = setInterval(() => {
      const randSrcPort = Math.floor(Math.random() * 55000) + 1024;
      const isAllowed = Math.random() > 0.4;
      const liveEv: OCSFEvent = {
        class_name: 'Network Activity',
        class_uid: 4001,
        activity_name: isAllowed ? 'Allow' : 'Deny',
        activity_id: isAllowed ? 1 : 6,
        time: new Date().toISOString(),
        event_uid: `live-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
        raw_data: `2026-08-27 ${new Date().toLocaleTimeString()} ${isAllowed ? 'ALLOW' : 'DROP'} TCP 192.168.1.10${Math.floor(Math.random() * 9)} 10.0.4.15 ${randSrcPort} 443`,
        raw_format: 'space_delimited',
        source_vendor: 'Microsoft',
        source_product: 'Windows Firewall',
        src_endpoint: {
          ip: `192.168.1.10${Math.floor(Math.random() * 9)}`,
          port: randSrcPort,
          zone: 'trust'
        },
        dst_endpoint: {
          ip: '10.0.4.15',
          port: 443,
          zone: 'untrust'
        },
        connection_info: {
          protocol_name: 'TCP',
          direction: 'outbound'
        },
        device: {
          name: 'win-fw-core',
          vendor_name: 'Microsoft',
          type: 'Host Firewall'
        }
      };
      setEvents(prev => [liveEv, ...prev.slice(0, 199)]);
    }, 4500);

    return () => clearInterval(timer);
  }, [isLiveStreaming]);

  // Distinct vendors in dataset
  const availableVendors = useMemo(() => {
    const set = new Set<string>();
    events.forEach(e => {
      const v = e.device?.vendor_name || e.source_vendor;
      if (v) set.add(v);
    });
    return Array.from(set);
  }, [events]);

  // Filtered dataset
  const filteredEvents = useMemo(() => {
    const list = events.filter(event => {
      if (filters.searchQuery) {
        const q = filters.searchQuery.toLowerCase();
        const strVal = JSON.stringify(event).toLowerCase();
        if (!strVal.includes(q)) return false;
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

      // Date Range Filtering
      if (filters.startDate) {
        try {
          const evTime = new Date(event.time).getTime();
          const startTime = new Date(filters.startDate).setHours(0, 0, 0, 0);
          if (evTime < startTime) return false;
        } catch {
          // ignore parsing error
        }
      }

      if (filters.endDate) {
        try {
          const evTime = new Date(event.time).getTime();
          const endTime = new Date(filters.endDate).setHours(23, 59, 59, 999);
          if (evTime > endTime) return false;
        } catch {
          // ignore parsing error
        }
      }

      return true;
    });

    // Sort by Date (Descending by default, Ascending if selected)
    return list.sort((a, b) => {
      const timeA = new Date(a.time).getTime() || 0;
      const timeB = new Date(b.time).getTime() || 0;
      return filters.sortOrder === 'asc' ? timeA - timeB : timeB - timeA;
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
      eventsPerSecond: events.length > 0 ? Number((events.length / 60).toFixed(1)) : 0
    };
  }, [events]);

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

  const handleToggleRealDataOnly = async () => {
    const next = !realDataOnly;
    setRealDataOnly(next);
    apiService.setRealDataOnly(next);
    const updated = await apiService.getEvents();
    setEvents(updated);
  };

  const handleSeedMockData = () => {
    setRealDataOnly(false);
    apiService.setRealDataOnly(false);
    const seeded = apiService.seedMockEvents();
    setEvents(seeded);
  };

  const handleResetEvents = async () => {
    const fresh = await apiService.resetEvents();
    setEvents(fresh);
  };

  const handleEventIngested = (newEvent: OCSFEvent | OCSFEvent[]) => {
    if (Array.isArray(newEvent)) {
      setEvents(prev => [...newEvent, ...prev]);
    } else {
      setEvents(prev => [newEvent, ...prev]);
    }
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

  return (
    <div className="min-h-screen bg-[#0c0e17] text-slate-100 flex flex-col font-sans pb-28">
      
      {/* Top Header & Greeting Bar */}
      <Header
        backendStatus={backendStatus}
        mockMode={mockMode}
        onToggleMockMode={handleToggleMockMode}
        onResetEvents={handleResetEvents}
        totalEventsCount={events.length}
        onOpenSettings={() => setIsSettingsOpen(true)}
      />

      {/* Main App Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 space-y-6">
        
        {/* VIEW 1: OVERVIEW & FEED */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6 animate-fade-in">
            {/* Hero Incident Carousel Card */}
            <HeroCarouselCard
              events={events}
              topEvent={events[0]}
              onInspect={(e) => setSelectedEvent(e)}
              onOpenIngest={() => setIsIngestModalOpen(true)}
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

        {/* VIEW 2: STATISTICS & CONCENTRIC RINGS */}
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

        {/* VIEW 5: OCSF DOCS & YAML MAPPING CONFIGS */}
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

      {/* Instant Ingest & Normalization Modal */}
      <InstantIngestModal
        isOpen={isIngestModalOpen}
        onClose={() => setIsIngestModalOpen(false)}
        onEventIngested={handleEventIngested}
        onOpenDrilldown={(e) => setSelectedEvent(e)}
      />

      {/* Settings Modal */}
      <SettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        mockMode={mockMode}
        onToggleMockMode={handleToggleMockMode}
        backendStatus={backendStatus}
        onResetEvents={handleResetEvents}
        realDataOnly={realDataOnly}
        onToggleRealDataOnly={handleToggleRealDataOnly}
        onSeedMockData={handleSeedMockData}
      />

      {/* Forensic Drill-Down Modal */}
      {selectedEvent && (
        <DrilldownModal
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
        />
      )}

    </div>
  );
};
