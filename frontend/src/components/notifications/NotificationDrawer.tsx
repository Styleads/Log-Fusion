import React, { useRef, useEffect } from 'react';
import { X, Bell, ShieldAlert, Check, Ban, CheckCircle2, FileCode, ArrowRight, Trash2 } from 'lucide-react';
import { OCSFEvent } from '../../types/ocsf';

export interface NotificationItem {
  id: string;
  title: string;
  desc: string;
  timeAgo: string;
  type: 'critical' | 'alert' | 'deny' | 'system';
  read: boolean;
  eventRef?: OCSFEvent;
}

interface NotificationDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  notifications: NotificationItem[];
  onMarkAllRead: () => void;
  onClearAll: () => void;
  onSelectEvent: (event: OCSFEvent) => void;
}

export const NotificationDrawer: React.FC<NotificationDrawerProps> = ({
  isOpen,
  onClose,
  notifications,
  onMarkAllRead,
  onClearAll,
  onSelectEvent
}) => {
  const drawerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (drawerRef.current && !drawerRef.current.contains(e.target as Node)) {
        onClose();
      }
    };
    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const unreadCount = notifications.filter(n => !n.read).length;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/50 backdrop-blur-sm animate-fade-in">
      <div
        ref={drawerRef}
        className="w-full max-w-md h-full bg-[#0e111d] border-l border-slate-700/80 shadow-2xl flex flex-col justify-between animate-slide-up"
      >
        {/* Top Header */}
        <div className="p-5 border-b border-slate-800/80 bg-[#131627] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-2xl bg-pink-500/15 text-pink-400 border border-pink-500/30">
              <Bell className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold text-white font-mono">
                  SOC Notifications
                </h3>
                {unreadCount > 0 && (
                  <span className="px-2 py-0.5 rounded-full bg-pink-500 text-[10px] font-bold text-white shadow-[0_0_8px_#ec4899]">
                    {unreadCount} new
                  </span>
                )}
              </div>
              <p className="text-[11px] text-slate-400">
                Live perimeter security alerts & system events
              </p>
            </div>
          </div>

          <div className="flex items-center gap-1">
            <button
              onClick={onClose}
              className="p-2 rounded-2xl text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Action Controls */}
        <div className="px-5 py-2.5 bg-slate-950/60 border-b border-slate-800/60 flex items-center justify-between text-xs">
          <button
            onClick={onMarkAllRead}
            disabled={unreadCount === 0}
            className="flex items-center gap-1.5 text-cyan-400 hover:text-cyan-300 disabled:text-slate-600 font-semibold transition-colors disabled:cursor-not-allowed"
          >
            <Check className="w-3.5 h-3.5" />
            <span>Mark all as read</span>
          </button>

          <button
            onClick={onClearAll}
            disabled={notifications.length === 0}
            className="flex items-center gap-1.5 text-slate-400 hover:text-rose-400 disabled:text-slate-700 transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear list</span>
          </button>
        </div>

        {/* Notifications List */}
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          {notifications.length === 0 ? (
            <div className="p-12 text-center text-slate-500 text-xs">
              <CheckCircle2 className="w-10 h-10 mx-auto text-emerald-400/60 mb-2" />
              <p className="font-semibold text-slate-300">All alerts clear</p>
              <p className="text-slate-500 mt-1">No pending security notifications</p>
            </div>
          ) : (
            notifications.map((notif) => {
              return (
                <div
                  key={notif.id}
                  onClick={() => {
                    if (notif.eventRef) {
                      onSelectEvent(notif.eventRef);
                      onClose();
                    }
                  }}
                  className={`p-4 rounded-3xl border transition-all cursor-pointer ${
                    !notif.read
                      ? 'bg-[#181b2e] border-pink-500/30 shadow-md shadow-pink-950/20'
                      : 'bg-[#131627] hover:bg-[#181c30] border-white/5'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2 mb-1.5">
                    <div className="flex items-center gap-2">
                      <span
                        className={`w-2 h-2 rounded-full ${
                          notif.type === 'critical'
                            ? 'bg-red-500 shadow-[0_0_8px_#ef4444]'
                            : notif.type === 'deny'
                            ? 'bg-pink-500 shadow-[0_0_8px_#ec4899]'
                            : notif.type === 'alert'
                            ? 'bg-purple-500 shadow-[0_0_8px_#a855f7]'
                            : 'bg-cyan-400'
                        }`}
                      />
                      <h4 className="text-xs font-bold text-slate-100 font-mono">
                        {notif.title}
                      </h4>
                    </div>
                    <span className="text-[10px] font-mono text-slate-500">
                      {notif.timeAgo}
                    </span>
                  </div>

                  <p className="text-xs text-slate-300/90 pl-4 leading-relaxed">
                    {notif.desc}
                  </p>

                  {notif.eventRef && (
                    <div className="mt-2.5 pt-2 border-t border-slate-800/80 pl-4 flex items-center justify-between text-[11px] font-mono text-cyan-400">
                      <span>Inspect OCSF Traceability</span>
                      <ArrowRight className="w-3 h-3" />
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800/80 bg-[#131627] text-center text-xs text-slate-500 font-mono">
          LogFusion Real-time Event Broadcaster
        </div>

      </div>
    </div>
  );
};
