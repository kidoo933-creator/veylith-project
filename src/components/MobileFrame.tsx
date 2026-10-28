import React from 'react';
import { Wifi, Battery, Signal } from 'lucide-react';

interface MobileFrameProps {
  children: React.ReactNode;
  activeScreenTitle?: string;
  isDark: boolean;
}

export const MobileFrame: React.FC<MobileFrameProps> = ({ children, isDark }) => {
  const currentTime = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });

  return (
    <div className="flex justify-center items-center py-4 px-2 w-full">
      {/* Android Device Shell */}
      <div className="relative w-full max-w-[420px] h-[850px] bg-slate-950 rounded-[48px] p-3 shadow-2xl border-4 border-slate-700/80 ring-1 ring-slate-800 flex flex-col overflow-hidden">
        {/* Device Notch & Camera Punch-hole */}
        <div className="absolute top-4 left-1/2 -translate-x-1/2 w-4 h-4 bg-slate-900 rounded-full border border-slate-700 z-50 flex items-center justify-center">
          <div className="w-1.5 h-1.5 bg-blue-950 rounded-full" />
        </div>

        {/* Screen Bezel Area */}
        <div className="relative w-full h-full bg-[#F5F7FA] dark:bg-[#0B132B] rounded-[38px] overflow-hidden flex flex-col">
          {/* Android Status Bar */}
          <div className="h-9 px-6 pt-1 flex items-center justify-between text-xs font-semibold text-slate-800 dark:text-slate-200 select-none z-40 bg-transparent">
            <span>{currentTime}</span>
            <div className="flex items-center gap-1.5 opacity-80">
              <Signal className="w-3.5 h-3.5" />
              <Wifi className="w-3.5 h-3.5" />
              <Battery className="w-4 h-4" />
            </div>
          </div>

          {/* Android App Content Area */}
          <div className="flex-1 overflow-y-auto overflow-x-hidden relative flex flex-col">
            {children}
          </div>

          {/* Android Gesture Bar */}
          <div className="h-5 flex items-center justify-center bg-transparent z-40">
            <div className="w-32 h-1 bg-slate-400 dark:bg-slate-600 rounded-full" />
          </div>
        </div>
      </div>
    </div>
  );
};
